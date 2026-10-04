"""
Kalamon MCP server: expose the healthcare denial pipeline as MCP tools and resources.

Uses Anthropic's open-source Python MCP SDK (MCPServer / @mcp.tool / @mcp.resource).
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Iterator, Literal

import psycopg2
from dotenv import load_dotenv
from loguru import logger
from mcp.server import MCPServer
from psycopg2.extras import RealDictCursor
from pydantic import Field

_HEALTHPIPELINE_ROOT = Path(__file__).resolve().parent.parent

AppealMethod = Literal["agent_generated", "manual", "hybrid"]
AppealOutcome = Literal["approved", "denied", "pending", "escalated"]

mcp = MCPServer(
    name="kalamon",
    instructions=(
        "Kalamon healthcare data pipeline. Primary live workflow is prior-auth "
        "completeness (DTR-shaped pre-submit packets). Denial contexts remain available "
        "as a secondary workflow. Load workflow rules, retrieve completeness packets or "
        "denial contexts, list pending cases, and record appeal outcomes for denials."
    ),
)


def _connect_db() -> psycopg2.extensions.connection:
    load_dotenv(_HEALTHPIPELINE_ROOT / ".env")
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ.get("PGDATABASE", "healthpipeline"),
        user=os.environ.get("PGUSER", os.environ.get("USER", "postgres")),
        password=os.environ.get("PGPASSWORD", ""),
    )


@contextmanager
def _db() -> Iterator[psycopg2.extensions.connection]:
    conn = _connect_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _json_ready(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(key): _json_ready(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_ready(item) for item in obj]
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    return obj


def _dumps(payload: Any) -> str:
    return json.dumps(_json_ready(payload), indent=2)


def _error(message: str) -> str:
    return _dumps({"error": message})


def _as_dict(row: Any) -> dict[str, Any]:
    return dict(row) if row is not None else {}


@mcp.tool(
    description=(
        "Retrieve a complete, validated denial context record for a specific claim. "
        "Returns assembled denial reason, clinical evidence, payer requirements, "
        "appeal deadline, and data quality flags."
    )
)
def get_denial_context(
    claim_id: Annotated[str, Field(description="The claim ID to retrieve")],
) -> str:
    try:
        with _db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM denial_contexts
                WHERE claim_id = %s
                """,
                (claim_id,),
            )
            row = cur.fetchone()
        logger.info("get_denial_context claim_id={} rows={}", claim_id, 1 if row else 0)
        if row is None:
            return _error(f"No denial context found for claim_id={claim_id!r}")
        return _dumps(_as_dict(row))
    except psycopg2.Error as exc:
        logger.exception("get_denial_context failed claim_id={}", claim_id)
        return _error(f"Database error retrieving denial context: {exc}")


@mcp.tool(
    description=(
        "Retrieve a prior-auth completeness packet for an order. Returns whether auth "
        "is required, LCD/NCD citation if known, evidence found vs missing, data quality "
        "flags, and the assembled packet. This is a pre-submit completeness record — not "
        "a PAS submission and not a UM approve/deny decision."
    )
)
def get_completeness_packet(
    order_id: Annotated[str, Field(description="The order_id or claim_id of the completeness packet")],
) -> str:
    try:
        with _db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM prior_auth_contexts
                WHERE claim_id = %s OR order_id = %s
                LIMIT 1
                """,
                (order_id, order_id),
            )
            row = cur.fetchone()
        logger.info("get_completeness_packet order_id={} rows={}", order_id, 1 if row else 0)
        if row is None:
            return _error(f"No completeness packet found for order_id={order_id!r}")
        return _dumps(_as_dict(row))
    except psycopg2.Error as exc:
        logger.exception("get_completeness_packet failed order_id={}", order_id)
        return _error(f"Database error retrieving completeness packet: {exc}")


@mcp.tool(
    description=(
        "List prior-auth completeness packets that still have missing evidence or required "
        "fields. Sorted by planned service date. Use this before submitting a prior auth."
    )
)
def list_pending_auth_packets(
    limit: Annotated[int, Field(description="Max records to return")] = 20,
    payer_name: Annotated[str | None, Field(description="Filter by payer name")] = None,
    status: Annotated[
        str | None,
        Field(description="Filter by validation_status: clean, flagged"),
    ] = None,
) -> str:
    limit = max(1, min(int(limit), 500))
    clauses = ["dc.assembled_at IS NOT NULL", "dc.validation_status IN ('clean', 'flagged')"]
    params: list[Any] = []
    if payer_name:
        clauses.append("dc.payer_name = %s")
        params.append(payer_name)
    if status:
        clauses.append("dc.validation_status = %s")
        params.append(status)
    where_sql = " AND ".join(clauses)
    params.append(limit)
    try:
        with _db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    dc.*,
                    CASE
                        WHEN dc.payer_appeal_deadline IS NULL THEN NULL
                        ELSE (dc.payer_appeal_deadline - CURRENT_DATE)
                    END AS days_until_deadline
                FROM prior_auth_contexts dc
                WHERE {where_sql}
                ORDER BY dc.payer_appeal_deadline ASC NULLS LAST, dc.assembled_at DESC
                LIMIT %s
                """,
                params,
            )
            rows = [_as_dict(row) for row in cur.fetchall()]
        logger.info("list_pending_auth_packets rows={}", len(rows))
        return _dumps(rows)
    except psycopg2.Error as exc:
        logger.exception("list_pending_auth_packets failed")
        return _error(f"Database error listing completeness packets: {exc}")


@mcp.tool(
    description=(
        "List all unworked prior auth denials sorted by appeal deadline urgency. "
        "Returns cases needing agent action, prioritized by days remaining before "
        "payer deadline."
    )
)
def list_pending_denials(
    limit: Annotated[int, Field(description="Max records to return")] = 20,
    payer_name: Annotated[
        str | None, Field(description="Filter by specific payer name")
    ] = None,
    status: Annotated[
        str | None,
        Field(description="Filter by validation_status: clean, flagged"),
    ] = None,
) -> str:
    limit = max(1, min(int(limit), 500))
    clauses = [
        """NOT EXISTS (
            SELECT 1 FROM denial_outcomes o WHERE o.claim_id = dc.claim_id
        )"""
    ]
    params: list[Any] = []
    if payer_name:
        clauses.append("dc.payer_name = %s")
        params.append(payer_name)
    if status:
        clauses.append("dc.validation_status = %s")
        params.append(status)
    where_sql = " AND ".join(clauses)
    params.append(limit)

    try:
        with _db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    dc.*,
                    CASE
                        WHEN dc.payer_appeal_deadline IS NULL THEN NULL
                        ELSE (dc.payer_appeal_deadline - CURRENT_DATE)
                    END AS days_until_deadline
                FROM denial_contexts dc
                WHERE {where_sql}
                ORDER BY dc.payer_appeal_deadline ASC NULLS LAST, dc.assembled_at DESC
                LIMIT %s
                """,
                params,
            )
            rows = [_as_dict(row) for row in cur.fetchall()]
        logger.info(
            "list_pending_denials limit={} payer_name={} status={} rows={}",
            limit,
            payer_name,
            status,
            len(rows),
        )
        return _dumps(rows)
    except psycopg2.Error as exc:
        logger.exception(
            "list_pending_denials failed limit={} payer_name={} status={}",
            limit,
            payer_name,
            status,
        )
        return _error(f"Database error listing pending denials: {exc}")


@mcp.tool(
    description=(
        "Record the result of an agent action on a denial — whether an appeal was "
        "filed, the outcome, and time taken. Used to track ROI and build the case study."
    )
)
def record_outcome(
    claim_id: Annotated[str, Field(description="The claim ID this outcome belongs to")],
    appeal_filed: Annotated[bool, Field(description="Whether an appeal was filed")],
    appeal_method: Annotated[
        AppealMethod,
        Field(description="How the appeal was produced: agent_generated, manual, hybrid"),
    ],
    appeal_outcome: Annotated[
        AppealOutcome,
        Field(description="Appeal result: approved, denied, pending, escalated"),
    ],
    staff_minutes_saved: Annotated[
        float | None, Field(description="Staff minutes saved by the agent action")
    ] = None,
    amount_recovered: Annotated[
        float | None, Field(description="Dollar amount recovered from the appeal")
    ] = None,
    agent_used: Annotated[
        str | None, Field(description="Name of the agent that handled this denial")
    ] = None,
) -> str:
    filed_at = datetime.now(timezone.utc) if appeal_filed else None
    try:
        with _db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT 1 FROM denial_contexts WHERE claim_id = %s",
                (claim_id,),
            )
            if cur.fetchone() is None:
                logger.info("record_outcome claim_id={} rows=0 (claim not found)", claim_id)
                return _error(
                    f"Cannot record outcome: no denial context for claim_id={claim_id!r}"
                )
            cur.execute(
                """
                INSERT INTO denial_outcomes (
                    claim_id,
                    appeal_filed_at,
                    appeal_method,
                    appeal_outcome,
                    staff_minutes_saved,
                    amount_recovered,
                    agent_used
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING
                    id,
                    claim_id,
                    appeal_filed_at,
                    appeal_method,
                    appeal_outcome,
                    staff_minutes_saved,
                    amount_recovered,
                    agent_used,
                    created_at
                """,
                (
                    claim_id,
                    filed_at,
                    appeal_method,
                    appeal_outcome,
                    staff_minutes_saved,
                    amount_recovered,
                    agent_used,
                ),
            )
            row = _as_dict(cur.fetchone())
        row["appeal_filed"] = appeal_filed
        logger.info(
            "record_outcome claim_id={} appeal_filed={} method={} outcome={} rows=1",
            claim_id,
            appeal_filed,
            appeal_method,
            appeal_outcome,
        )
        return _dumps(
            {
                "status": "ok",
                "message": "Appeal outcome recorded",
                "outcome": row,
            }
        )
    except psycopg2.Error as exc:
        logger.exception("record_outcome failed claim_id={}", claim_id)
        return _error(f"Database error recording outcome: {exc}")


@mcp.tool(
    description=(
        "Retrieve the active workflow rules and payer configuration for a specific "
        "workflow. This is the operational context — payer appeal windows, required "
        "fields, escalation thresholds — that agents should load before acting on denials."
    )
)
def get_workflow_rules(
    workflow: Annotated[
        str,
        Field(description="Workflow name to retrieve rules for"),
    ] = "prior_auth_denial",
    client_id: Annotated[
        str | None,
        Field(description="Client-specific rules. Omit for default rules."),
    ] = None,
) -> str:
    try:
        with _db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, client_id, workflow, rule_type, rule_config, active, created_at
                FROM workflow_rules
                WHERE workflow = %s
                  AND active = true
                  AND (client_id = %s OR client_id IS NULL)
                ORDER BY rule_type, id
                """,
                (workflow, client_id),
            )
            rows = [_as_dict(row) for row in cur.fetchall()]
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            grouped.setdefault(row["rule_type"], []).append(row)
        logger.info(
            "get_workflow_rules workflow={} client_id={} rows={}",
            workflow,
            client_id,
            len(rows),
        )
        return _dumps(
            {
                "workflow": workflow,
                "client_id": client_id,
                "rules": grouped,
            }
        )
    except psycopg2.Error as exc:
        logger.exception(
            "get_workflow_rules failed workflow={} client_id={}",
            workflow,
            client_id,
        )
        return _error(f"Database error retrieving workflow rules: {exc}")


@mcp.tool(
    description=(
        "Check the health of the data pipeline — last successful extraction run, "
        "records processed, data quality metrics, and any quarantined records needing review."
    )
)
def get_pipeline_health() -> str:
    try:
        with _db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT ON (resource_type)
                    resource_type,
                    extractor_name,
                    completed_at,
                    status,
                    records_read,
                    records_inserted,
                    error_message
                FROM (
                    SELECT
                        CASE
                            WHEN position(':' IN extractor_name) > 0
                                THEN split_part(extractor_name, ':', 2)
                            ELSE 'ExplanationOfBenefit'
                        END AS resource_type,
                        extractor_name,
                        completed_at,
                        status,
                        records_read,
                        records_inserted,
                        error_message
                    FROM extraction_log
                ) runs
                ORDER BY resource_type, completed_at DESC NULLS LAST
                """
            )
            latest_runs = [_as_dict(row) for row in cur.fetchall()]

            cur.execute(
                """
                SELECT MAX(completed_at) AS last_run_at
                FROM extraction_log
                """
            )
            last_run_at = cur.fetchone()["last_run_at"]

            cur.execute(
                """
                SELECT status
                FROM extraction_log
                ORDER BY completed_at DESC NULLS LAST, id DESC
                LIMIT 1
                """
            )
            latest_status_row = cur.fetchone()
            latest_status = latest_status_row["status"] if latest_status_row else None

            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE validation_status = 'clean') AS records_clean,
                    COUNT(*) FILTER (WHERE validation_status = 'flagged') AS records_flagged
                FROM clean_denial_records
                """
            )
            clean_counts = _as_dict(cur.fetchone())

            cur.execute("SELECT COUNT(*) AS records_quarantined FROM quarantine_records")
            quarantined = int(cur.fetchone()["records_quarantined"] or 0)

        records_extracted = sum(int(run.get("records_read") or 0) for run in latest_runs)
        records_clean = int(clean_counts.get("records_clean") or 0)
        records_flagged = int(clean_counts.get("records_flagged") or 0)

        if latest_status is None or latest_status != "success":
            pipeline_status = "down"
        elif quarantined > 0:
            pipeline_status = "degraded"
        else:
            pipeline_status = "healthy"

        summary = {
            "last_run_at": last_run_at,
            "records_extracted": records_extracted,
            "records_clean": records_clean,
            "records_flagged": records_flagged,
            "records_quarantined": quarantined,
            "pipeline_status": pipeline_status,
            "latest_runs": latest_runs,
        }
        logger.info(
            "get_pipeline_health status={} extracted={} clean={} flagged={} quarantined={} rows={}",
            pipeline_status,
            records_extracted,
            records_clean,
            records_flagged,
            quarantined,
            len(latest_runs),
        )
        return _dumps(summary)
    except psycopg2.Error as exc:
        logger.exception("get_pipeline_health failed")
        return _error(f"Database error checking pipeline health: {exc}")


def _format_workflow_rules(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Prior Auth Denial Workflow Rules",
        "",
        "Operational instructions for agents handling prior authorization denials.",
        "Load these rules before acting on a denial context.",
        "",
        f"Active rules: {len(rows)}",
        "",
    ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["rule_type"], []).append(row)

    headings = {
        "required_field": "Required fields (quarantine if missing)",
        "payer_override": "Payer appeal windows",
        "escalation": "Escalation rules",
        "code_alias": "Denial code aliases",
    }
    for rule_type, rules in grouped.items():
        title = headings.get(rule_type, rule_type.replace("_", " ").title())
        lines.append(f"## {title}")
        lines.append(f"rule_type: {rule_type}")
        lines.append("")
        for rule in rules:
            config = rule.get("rule_config") or {}
            if not isinstance(config, dict):
                config = {"value": config}
            scope = rule.get("client_id") or "default"
            parts = [f"{key}={value}" for key, value in config.items()]
            lines.append(f"- [{scope}] " + ", ".join(parts))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


@mcp.resource(
    "kalamon://workflow/prior-auth-denial",
    name="Prior Auth Denial Workflow Rules",
    description=(
        "Complete operational context for the prior authorization denial workflow — "
        "payer appeal windows, required documentation, X12 denial code categories, "
        "and escalation rules."
    ),
    mime_type="text/plain",
)
def prior_auth_denial_workflow() -> str:
    try:
        with _db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT client_id, workflow, rule_type, rule_config, active
                FROM workflow_rules
                WHERE workflow = 'prior_auth_denial'
                  AND active = true
                ORDER BY rule_type, id
                """
            )
            rows = [_as_dict(row) for row in cur.fetchall()]
        logger.info("resource prior-auth-denial rows={}", len(rows))
        if not rows:
            return "No active workflow_rules found for workflow='prior_auth_denial'.\n"
        return _format_workflow_rules(rows)
    except psycopg2.Error as exc:
        logger.exception("resource prior-auth-denial failed")
        return f"Database error loading workflow rules: {exc}"


DENIAL_CONTEXT_SCHEMA_DOC = """# DenialContext Schema

Field definitions and data quality flag meanings for denial context records
served by this pipeline. Agents should treat this as the contract for
`get_denial_context` and `list_pending_denials`.

## Record fields

- claim_id: Unique claim identifier. Required. Primary lookup key.
- patient_id: Patient identifier from the source FHIR resource.
- service_date: Date of service on the denied claim.
- denial_reason_code: Source denial / CARC code as received from the payer.
- denial_category: Canonical category after X12 mapping (e.g. authorization_required, not_covered).
- canonical_denial_description: Human-readable description of the mapped denial code.
- payer_name: Payer responsible for the claim.
- payer_appeal_deadline: Last date an appeal can be filed, derived from payer appeal windows.
- appeal_requirements: JSON object of documentation / fields required for a successful appeal.
- diagnosis_codes: ICD diagnosis codes associated with the claim.
- procedure_codes: Procedure / service codes associated with the claim.
- clinical_notes_summary: Short clinical evidence summary assembled from related documents.
- total_claim_amount: Billed amount on the claim.
- prior_submission_history: JSON history of related submissions and extraction runs.
- data_quality_flags: Array of quality markers. See flag meanings below.
- validation_status: Pipeline validation result: `clean` or `flagged`. Rejected records are quarantined and are not served here.
- assembled_at: Timestamp when this denial context was assembled.
- days_until_deadline: (list_pending_denials only) Whole days remaining until payer_appeal_deadline. Negative means the deadline has passed. Null if no deadline is set.

## validation_status

- clean: Required and optional fields are present. Safe to act on.
- flagged: Required fields are present, but one or more optional fields are missing or an escalation rule matched. Act with the gaps in mind; do not invent missing clinical facts.
- rejected: Required fields are missing. These records go to quarantine_records and are not returned as denial contexts.

## data_quality_flags

Flags are strings of the form `kind:field` (or `kind:detail`).

- missing_required:<field>
  A required field is empty. The assembler quarantines the record. Agents should not see these on denial_contexts. If one appears, stop and ask a human to review.
- missing_optional:<field>
  An optional field is empty (for example denial_reason_code, payer_name, diagnosis_codes). The record is still usable. Do not fabricate the missing value; note the gap in any appeal letter and prefer fields that are present.
- escalation:<detail>
  A workflow escalation rule matched (for example denial_category=authorization_required). Treat as higher priority; check appeal_requirements and remaining days until the payer deadline.

## How agents should interpret missing flags

1. missing_required — do not generate an appeal; the record is incomplete for safe action.
2. missing_optional — generate an appeal only from present evidence; explicitly call out what is unknown.
3. No flags and validation_status=clean — proceed using workflow rules and appeal_requirements.
"""


@mcp.resource(
    "kalamon://schema/denial-context",
    name="DenialContext Schema",
    description=(
        "Field definitions and data quality flag meanings for denial context records "
        "served by this pipeline."
    ),
    mime_type="text/plain",
)
def denial_context_schema() -> str:
    logger.info("resource denial-context-schema rows=0")
    return DENIAL_CONTEXT_SCHEMA_DOC


if __name__ == "__main__":
    mcp.run()


# To test: run `python api/run_mcp.py` — server should start
#   without errors
# To verify tools: use MCP inspector at
#   https://inspector.tools.anthropic.com
# To connect Claude: add to claude_desktop_config.json:
# {
#   "mcpServers": {
#     "kalamon": {
#       "command": "python",
#       "args": ["/full/path/to/healthpipeline/api/run_mcp.py"]
#     }
#   }
# }
