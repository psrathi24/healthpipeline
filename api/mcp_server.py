"""
Kalamon MCP server: expose the prior-auth completeness pipeline as MCP tools.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Iterator

import psycopg2
from dotenv import load_dotenv
from loguru import logger
from mcp.server import MCPServer
from psycopg2.extras import RealDictCursor
from pydantic import Field

_HEALTHPIPELINE_ROOT = Path(__file__).resolve().parent.parent

mcp = MCPServer(
    name="kalamon",
    instructions=(
        "Kalamon healthcare data pipeline. The live workflow is prior-auth "
        "completeness: DTR-shaped pre-submit packets assembled from orders, "
        "coverage, notes, and payer criteria. Load workflow rules, retrieve "
        "completeness packets, and list packets still missing evidence. This is "
        "not PAS submit, not UM approve/deny, and not appeal-letter drafting."
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
        "Retrieve the active workflow rules and payer configuration for a specific "
        "workflow. This is the operational context — required fields and payer criteria "
        "that agents should load before assembling or serving a completeness packet."
    )
)
def get_workflow_rules(
    workflow: Annotated[
        str,
        Field(description="Workflow name to retrieve rules for"),
    ] = "prior_auth_completeness",
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
                FROM prior_auth_contexts
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
        "# Prior Auth Completeness Workflow Rules",
        "",
        "Operational instructions for agents assembling pre-submit completeness packets.",
        "Load these rules before serving a packet. This is not PAS submit and not UM.",
        "",
        f"Active rules: {len(rows)}",
        "",
    ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["rule_type"], []).append(row)

    headings = {
        "required_field": "Required fields (quarantine if missing)",
        "payer_override": "Payer criteria windows",
        "escalation": "Escalation rules",
        "code_alias": "Code aliases",
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
    "kalamon://workflow/prior-auth-completeness",
    name="Prior Auth Completeness Workflow Rules",
    description=(
        "Operational context for the DTR-shaped prior-auth completeness workflow — "
        "required documentation, local LCD/NCD criteria, and data-quality rules."
    ),
    mime_type="text/plain",
)
def prior_auth_completeness_workflow() -> str:
    try:
        with _db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT client_id, workflow, rule_type, rule_config, active
                FROM workflow_rules
                WHERE workflow = 'prior_auth_completeness'
                  AND active = true
                ORDER BY rule_type, id
                """
            )
            rows = [_as_dict(row) for row in cur.fetchall()]
        logger.info("resource prior-auth-completeness rows={}", len(rows))
        if not rows:
            return "No active workflow_rules found for workflow='prior_auth_completeness'.\n"
        return _format_workflow_rules(rows)
    except psycopg2.Error as exc:
        logger.exception("resource prior-auth-completeness failed")
        return f"Database error loading workflow rules: {exc}"


COMPLETENESS_PACKET_SCHEMA_DOC = """# CompletenessPacket Schema

Field definitions and data quality flag meanings for prior-auth completeness
packets. Agents should treat this as the contract for `get_completeness_packet`
and `list_pending_auth_packets`. This is a pre-submit completeness record —
not a PAS submission and not a UM approve/deny decision.

## Record fields

- claim_id / order_id: Unique order identifier. Required. Primary lookup key.
- patient_id: Patient identifier from the source FHIR or order extract.
- service_date: Planned service date on the order.
- payer_name: Payer responsible for the order.
- payer_appeal_deadline: Planned-service due date used for packet urgency.
- diagnosis_codes: ICD diagnosis codes associated with the order.
- procedure_codes: Procedure / service codes associated with the order.
- clinical_notes_summary: Short clinical evidence summary assembled from related documents.
- data_quality_flags: Array of quality markers. See flag meanings below.
- validation_status: Pipeline validation result: `clean` or `flagged`.
- assembled_at: Timestamp when this completeness packet was assembled.

## data_quality_flags

- missing_required:<field> — a required field is empty; the assembler quarantines the record.
- missing_optional:<field> — an optional field is empty. Do not fabricate the missing value.
- missing_evidence:<criterion> — a payer-criteria keyword was not found in notes.
"""


@mcp.resource(
    "kalamon://schema/completeness-packet",
    name="CompletenessPacket Schema",
    description=(
        "Field definitions and data quality flag meanings for prior-auth completeness packets."
    ),
    mime_type="text/plain",
)
def completeness_packet_schema() -> str:
    logger.info("resource completeness-packet-schema rows=0")
    return COMPLETENESS_PACKET_SCHEMA_DOC


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
