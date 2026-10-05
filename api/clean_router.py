"""
Provider portal Clean API — validation, quarantine, payer mappings, rules.

Verification checklist (manual):
□ Summary stats match actual table counts
□ Record browser shows patient initials only
□ Inspect drawer Tab 1 shows DenialContext fields with source tags
□ Tab 2 JSON viewer renders without crashing on large FHIR bundles
□ Tab 3 transformation log shows real steps
□ Quarantine approve moves record to denial_contexts as flagged
□ Quarantine dismiss keeps record in quarantine with reviewed_at
□ Confirming a payer mapping sets validated_by_provider = true
□ Workflow rules show lock vs pencil for system vs provider rules
□ YAML export downloads valid YAML
□ All actions appear in portal_audit_log
□ RoleGuard hides Workflow Rules from billing
□ 401 redirects to /login; 403 stays on page
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field

from .auth_router import get_current_user, log_audit_event
from .auth_security import utcnow
from .serve_router import (
    FORBIDDEN,
    WORKFLOW_DEFAULT,
    _forbidden,
    _jsonable,
    _patient_initials,
    require_admin,
)
from .workflows import WORKFLOW_COMPLETENESS, case_table, is_completeness

clean_router = APIRouter(tags=["clean"])

DENIAL_CONTEXT_FIELDS = [
    "claim_id",
    "patient_id",
    "service_date",
    "payer_name",
    "procedure_codes",
    "diagnosis_codes",
    "denial_reason_code",
    "denial_category",
    "canonical_denial_description",
    "clinical_notes_summary",
    "total_claim_amount",
    "payer_appeal_deadline",
    "appeal_requirements",
]

REQUIRED_FIELDS = {"claim_id", "patient_id", "service_date"}

FLAG_REASONS = {
    "missing_required:claim_id": "No claim identifier found in source data",
    "missing_required:patient_id": "No patient identifier — cannot link to EHR",
    "missing_required:service_date": "Service date missing — cannot calculate deadline",
    "invalid_format:member_id": "Member ID format does not match payer pattern",
    "invalid_code:diagnosis": "Diagnosis code not found in ICD-10 code set",
    "invalid_code:procedure": "Procedure code not found in CPT code set",
    "duplicate_resource": "Duplicate record already exists in pipeline",
}

RULE_TYPES = ("required_field", "payer_override", "escalation", "code_alias")


class OverrideBody(BaseModel):
    override_reason: str = Field(min_length=20, max_length=2000)


class DismissBody(BaseModel):
    dismiss_reason: str = Field(min_length=1, max_length=2000)


class MappingValidateBody(BaseModel):
    action: Literal["confirm", "reject"]
    corrected_canonical_name: str | None = None


class MappingAddBody(BaseModel):
    raw_name: str = Field(min_length=1, max_length=120)
    canonical_name: str = Field(min_length=1, max_length=160)
    canonical_payer_id: str | None = None


class RulePatchBody(BaseModel):
    rule_config: dict[str, Any]
    active: bool = True


def _db(request: Request):
    return request.app.state.db


def _cursor(request: Request):
    return _db(request).cursor(cursor_factory=RealDictCursor)


def require_staff(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if user.get("role") not in {"admin", "billing"}:
        raise _forbidden()
    return user


def _ensure_date_range(date_from: date | None, date_to: date | None) -> tuple[date, date]:
    end = date_to or date.today()
    start = date_from or (end - timedelta(days=7))
    return start, end


def _preview(record: Any) -> dict[str, Any]:
    if isinstance(record, str):
        try:
            record = json.loads(record)
        except json.JSONDecodeError:
            return {}
    if not isinstance(record, dict):
        return {}
    out: dict[str, Any] = {}
    for key in list(record.keys())[:3]:
        value = record[key]
        if isinstance(value, (dict, list)):
            out[key] = "[complex]"
        else:
            out[key] = value
    return out


def _rejection_reason(flags: list[str] | None, fallback: str | None = None) -> str:
    flags = list(flags or [])
    if flags:
        return FLAG_REASONS.get(flags[0], flags[0].replace("_", " ").replace(":", " — "))
    return fallback or "Record failed required-field validation"


def _raw_path(obj: Any, *path: str) -> Any:
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _first_error_code(raw: dict[str, Any] | None) -> str | None:
    if not raw:
        return None
    for err in raw.get("error") or []:
        for coding in err.get("coding") or []:
            if coding.get("code"):
                return str(coding["code"])
    return None


def _source_for_claim(cur, claim_id: str | None, raw_resource_id: str | None = None) -> tuple[str, str | None]:
    resource_id = raw_resource_id
    if not resource_id and claim_id:
        cur.execute(
            """
            SELECT raw_resource_id
            FROM clean_denial_records
            WHERE claim_id = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (claim_id,),
        )
        hit = cur.fetchone()
        resource_id = hit["raw_resource_id"] if hit else None
    if not resource_id and claim_id:
        resource_id = claim_id
    if not resource_id:
        return "manual", None
    cur.execute(
        "SELECT source FROM raw_fhir_responses WHERE resource_id = %s LIMIT 1",
        (resource_id,),
    )
    row = cur.fetchone()
    source = (row["source"] if row else None) or "manual"
    return source, resource_id


def _load_raw_payload(cur, resource_id: str | None) -> dict[str, Any] | None:
    if not resource_id:
        return None
    cur.execute(
        "SELECT payload FROM raw_fhir_responses WHERE resource_id = %s LIMIT 1",
        (resource_id,),
    )
    row = cur.fetchone()
    if not row:
        return None
    payload = row["payload"]
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return None
    return payload if isinstance(payload, dict) else None


def _normalize_steps(raw: dict[str, Any] | None, record: dict[str, Any], source: str) -> list[dict[str, Any]]:
    raw = raw or {}
    billable = _raw_path(raw, "billablePeriod", "start") or raw.get("created")
    insurer = _raw_path(raw, "insurer", "display") or _raw_path(raw, "insurer", "reference")
    error_code = _first_error_code(raw)
    dx_raw = None
    diagnoses = raw.get("diagnosis") or []
    if diagnoses:
        dx_raw = _raw_path(diagnoses[0], "diagnosisCodeableConcept", "coding")
        if isinstance(dx_raw, list) and dx_raw:
            dx_raw = dx_raw[0].get("code")
    px_raw = None
    items = raw.get("item") or []
    if items:
        px_raw = _raw_path(items[0], "productOrService", "coding")
        if isinstance(px_raw, list) and px_raw:
            px_raw = px_raw[0].get("code")

    def step(
        field: str,
        raw_value: Any,
        normalized: Any,
        transformation: str,
        json_path: str | None,
        outcome: str,
    ) -> dict[str, Any]:
        return {
            "field": field,
            "raw_value": raw_value if raw_value not in ("", []) else None,
            "normalized_value": normalized if normalized not in ("", []) else None,
            "transformation": transformation,
            "source": json_path,
            "connector": source,
            "outcome": outcome,
        }

    svc = record.get("service_date")
    svc_iso = svc.isoformat() if isinstance(svc, date) else svc
    payer = record.get("payer_name")
    denial = record.get("denial_reason_code")
    category = record.get("denial_category")
    dx = record.get("diagnosis_codes") or []
    px = record.get("procedure_codes") or []

    steps = [
        step(
            "service_date",
            billable,
            svc_iso,
            "CCYYMMDD → ISO 8601" if billable and "-" not in str(billable) else "FHIR date → ISO 8601",
            "billablePeriod.start",
            "applied" if svc_iso else "missing",
        ),
        step(
            "payer_name",
            insurer,
            payer,
            "payer_name_mapping lookup" if insurer and payer and str(insurer) != str(payer) else "insurer.display passthrough",
            "insurer.display",
            "applied" if payer else "missing",
        ),
        step(
            "denial_reason_code",
            error_code,
            denial,
            "extracted from EOB error[] / adjudication" if denial else "not found in EOB error[] or adjudication",
            "error[].coding.code",
            "applied" if denial else "missing",
        ),
        step(
            "denial_category",
            error_code or denial,
            category,
            "code_mappings lookup" if category else "no canonical category mapped",
            "error[].coding.code",
            "applied" if category else "missing",
        ),
        step(
            "diagnosis_codes",
            dx_raw,
            ", ".join(dx) if dx else None,
            "FHIR diagnosis[].coding → array",
            "diagnosis[].diagnosisCodeableConcept.coding.code",
            "applied" if dx else "missing",
        ),
        step(
            "procedure_codes",
            px_raw,
            ", ".join(px) if px else None,
            "FHIR item[].productOrService → array",
            "item[].productOrService.coding.code",
            "applied" if px else "missing",
        ),
        step(
            "claim_id",
            _raw_path(raw, "claim", "reference") or raw.get("id"),
            record.get("claim_id"),
            "claim.reference / identifier → claim_id",
            "claim.reference",
            "applied" if record.get("claim_id") else "failed",
        ),
        step(
            "patient_id",
            _raw_path(raw, "patient", "reference"),
            record.get("patient_id"),
            "patient.reference → id",
            "patient.reference",
            "applied" if record.get("patient_id") else "failed",
        ),
    ]
    return steps


def _field_views(record: dict[str, Any], steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_field = {step["field"]: step for step in steps}
    flags = set(record.get("data_quality_flags") or [])
    views = []
    for field in DENIAL_CONTEXT_FIELDS:
        value = record.get(field)
        if isinstance(value, list):
            display = ", ".join(str(item) for item in value) if value else None
        elif isinstance(value, (dict, list)):
            display = json.dumps(value)
        elif isinstance(value, (date, datetime)):
            display = value.isoformat()
        else:
            display = str(value) if value is not None and value != "" else None
        required = field in REQUIRED_FIELDS
        missing_req = f"missing_required:{field}" in flags
        missing_opt = f"missing_optional:{field}" in flags
        if display and not missing_req and not missing_opt:
            status_name = "present"
        elif missing_req or (required and not display):
            status_name = "missing_required"
        elif missing_opt or not display:
            status_name = "missing_optional"
        else:
            status_name = "flagged"
        step = by_field.get(field, {})
        views.append(
            {
                "field": field,
                "value": display,
                "status": status_name,
                "source": step.get("source"),
                "connector": step.get("connector"),
                "transformation": step.get("transformation"),
            }
        )
    return views


def _validate_rule_config(rule_type: str, config: dict[str, Any]) -> dict[str, Any]:
    if rule_type == "required_field":
        field = str(config.get("field") or "").strip()
        action = str(config.get("action") or "quarantine")
        if not field or action not in {"quarantine", "flag", "skip"}:
            raise HTTPException(status_code=400, detail="Invalid required_field rule")
        return {"field": field, "action": action}
    if rule_type == "payer_override":
        payer = str(config.get("payer") or "").strip()
        days = config.get("appeal_window_days")
        if not payer or days is None:
            raise HTTPException(status_code=400, detail="Invalid payer_override rule")
        return {
            "payer": payer,
            "appeal_window_days": int(days),
            "notes": config.get("notes"),
        }
    if rule_type == "escalation":
        category = str(config.get("denial_category") or "").strip()
        priority = str(config.get("priority") or "medium")
        if not category or priority not in {"high", "medium", "low"}:
            raise HTTPException(status_code=400, detail="Invalid escalation rule")
        return {
            "denial_category": category,
            "priority": priority,
            "notify": bool(config.get("notify")),
        }
    if rule_type == "code_alias":
        source_code = str(config.get("source_code") or "").strip()
        canonical = str(config.get("canonical") or config.get("maps_to") or "").strip()
        source_system = str(config.get("source_system") or "X12")
        if not source_code or not canonical:
            raise HTTPException(status_code=400, detail="Invalid code_alias rule")
        return {
            "source_code": source_code,
            "source_system": source_system,
            "canonical": canonical,
        }
    raise HTTPException(status_code=400, detail="Unknown rule type")


@clean_router.get("/summary")
def get_summary(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    workflow: str = Query(WORKFLOW_DEFAULT),
    date_from: date | None = None,
    date_to: date | None = None,
) -> dict[str, Any]:
    start, end = _ensure_date_range(date_from, date_to)
    table = case_table(workflow)
    source_join = (
        "LEFT JOIN raw_fhir_responses r ON r.resource_id = dc.raw_resource_id"
        if is_completeness(workflow)
        else """
            LEFT JOIN LATERAL (
                SELECT raw_resource_id
                FROM clean_denial_records c
                WHERE c.claim_id = dc.claim_id
                ORDER BY c.id DESC
                LIMIT 1
            ) c ON TRUE
            LEFT JOIN raw_fhir_responses r ON r.resource_id = c.raw_resource_id
        """
    )
    with _cursor(request) as cur:
        cur.execute(
            f"""
            SELECT
                COUNT(*) AS total_processed,
                COUNT(*) FILTER (WHERE validation_status = 'clean') AS clean,
                COUNT(*) FILTER (WHERE validation_status = 'flagged') AS flagged
            FROM {table}
            WHERE assembled_at::date BETWEEN %s AND %s
            """,
            (start, end),
        )
        counts = cur.fetchone() or {}
        cur.execute(
            """
            SELECT COUNT(*) AS quarantined
            FROM quarantine_records
            WHERE COALESCE(created_at, NOW())::date BETWEEN %s AND %s
              AND COALESCE(review_action, '') <> 'dismissed'
              AND COALESCE(workflow, %s) = %s
            """,
            (start, end, WORKFLOW_DEFAULT, workflow),
        )
        quarantined = int((cur.fetchone() or {}).get("quarantined") or 0)
        cur.execute(
            f"""
            SELECT flag, COUNT(*) AS count
            FROM {table} dc
            CROSS JOIN LATERAL unnest(COALESCE(dc.data_quality_flags, ARRAY[]::text[])) AS flag
            WHERE dc.assembled_at::date BETWEEN %s AND %s
            GROUP BY flag
            ORDER BY COUNT(*) DESC
            LIMIT 8
            """,
            (start, end),
        )
        flags = cur.fetchall()
        cur.execute(
            f"""
            SELECT COALESCE(r.source, 'unknown') AS source, COUNT(*) AS records
            FROM {table} dc
            {source_join}
            WHERE dc.assembled_at::date BETWEEN %s AND %s
            GROUP BY 1
            ORDER BY COUNT(*) DESC
            """,
            (start, end),
        )
        sources = cur.fetchall()
        cur.execute(f"SELECT MAX(assembled_at) AS last_run FROM {table}")
        last_run = (cur.fetchone() or {}).get("last_run")
        cur.execute(
            """
            SELECT COUNT(*) AS n
            FROM quarantine_records
            WHERE review_action IS NULL
              AND COALESCE(workflow, %s) = %s
            """,
            (WORKFLOW_DEFAULT, workflow),
        )
        unreviewed = int((cur.fetchone() or {}).get("n") or 0)
        flow = {
            "ingested": 0,
            "criteria_applied": 0,
            "evidence_matched": 0,
            "completed": 0,
        }
        if is_completeness(workflow):
            cur.execute(
                """
                SELECT
                    COUNT(*) AS ingested,
                    COUNT(*) FILTER (
                        WHERE COALESCE(auth_required, 'unknown') IN ('yes', 'no')
                           OR COALESCE(lcd_ncd_citation, '') <> ''
                    ) AS criteria_applied,
                    COUNT(*) FILTER (
                        WHERE COALESCE(jsonb_array_length(COALESCE(evidence_found, '[]'::jsonb)), 0)
                            + COALESCE(jsonb_array_length(COALESCE(evidence_missing, '[]'::jsonb)), 0) > 0
                    ) AS evidence_matched,
                    COUNT(*) FILTER (
                        WHERE validation_status = 'clean'
                          AND COALESCE(jsonb_array_length(COALESCE(evidence_missing, '[]'::jsonb)), 0) = 0
                    ) AS completed
                FROM prior_auth_contexts
                WHERE assembled_at::date BETWEEN %s AND %s
                """,
                (start, end),
            )
            flow_row = cur.fetchone() or {}
            flow = {
                "ingested": int(flow_row.get("ingested") or 0),
                "criteria_applied": int(flow_row.get("criteria_applied") or 0),
                "evidence_matched": int(flow_row.get("evidence_matched") or 0),
                "completed": int(flow_row.get("completed") or 0),
            }
    total = int(counts.get("total_processed") or 0) + quarantined
    clean = int(counts.get("clean") or 0)
    flagged = int(counts.get("flagged") or 0)
    denom = total or 1
    most_common = [
        {
            "flag": row["flag"],
            "count": int(row["count"]),
            "pct": round(int(row["count"]) / max(flagged + clean, 1) * 100, 1),
        }
        for row in flags
    ]
    return _jsonable(
        {
            "workflow": workflow,
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
            "total_processed": total,
            "clean": clean,
            "flagged": flagged,
            "quarantined": quarantined,
            "clean_pct": round(clean / denom * 100, 1),
            "flagged_pct": round(flagged / denom * 100, 1),
            "quarantine_pct": round(quarantined / denom * 100, 1),
            "most_common_flags": most_common,
            "sources_contributing": [
                {"source": row["source"], "records": int(row["records"])} for row in sources
            ],
            "last_transformation_run": last_run.isoformat() if last_run else None,
            "unreviewed_quarantine": unreviewed,
            "flow": flow,
        }
    )


@clean_router.get("/records")
def list_records(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    workflow: str = Query(WORKFLOW_DEFAULT),
    status_filter: str | None = Query("all", alias="status"),
    source: str | None = None,
    payer_name: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    search: str | None = None,
    sort: str = "assembled_at_desc",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    table = case_table(workflow)
    include_clean = status_filter in {None, "all", "clean", "flagged"}
    include_flagged = status_filter in {None, "all", "clean", "flagged"}
    include_quarantine = status_filter in {None, "all", "quarantined"}
    if status_filter == "clean":
        include_flagged = False
        include_quarantine = False
    if status_filter == "flagged":
        include_clean = False
        include_quarantine = False
    if status_filter == "quarantined":
        include_clean = False
        include_flagged = False

    items: list[dict[str, Any]] = []
    payers: list[str] = []
    sources: list[str] = []
    with _cursor(request) as cur:
        cur.execute(
            f"""
            SELECT DISTINCT payer_name FROM {table}
            WHERE payer_name IS NOT NULL AND btrim(payer_name) <> ''
            ORDER BY payer_name
            """
        )
        payers = [row["payer_name"] for row in cur.fetchall()]
        cur.execute(
            """
            SELECT DISTINCT source FROM raw_fhir_responses
            WHERE source IS NOT NULL
            ORDER BY source
            """
        )
        sources = [row["source"] for row in cur.fetchall()]

        if include_clean or include_flagged:
            clauses = ["dc.assembled_at IS NOT NULL"]
            params: list[Any] = []
            statuses = []
            if include_clean:
                statuses.append("clean")
            if include_flagged:
                statuses.append("flagged")
            clauses.append("dc.validation_status = ANY(%s)")
            params.append(statuses)
            if payer_name:
                clauses.append("dc.payer_name = %s")
                params.append(payer_name)
            if date_from:
                clauses.append("dc.assembled_at::date >= %s")
                params.append(date_from)
            if date_to:
                clauses.append("dc.assembled_at::date <= %s")
                params.append(date_to)
            if search:
                clauses.append("dc.claim_id ILIKE %s")
                params.append(f"%{search.strip()}%")
            if source:
                if is_completeness(workflow):
                    clauses.append("COALESCE(r.source, 'manual') = %s")
                    params.append(source)
                else:
                    clauses.append("COALESCE(r.source, 'manual') = %s")
                    params.append(source)
            order = "dc.assembled_at DESC NULLS LAST"
            if sort == "assembled_at_asc":
                order = "dc.assembled_at ASC NULLS LAST"
            source_join = (
                "LEFT JOIN raw_fhir_responses r ON r.resource_id = dc.raw_resource_id"
                if is_completeness(workflow)
                else """
                LEFT JOIN LATERAL (
                    SELECT raw_resource_id
                    FROM clean_denial_records x
                    WHERE x.claim_id = dc.claim_id
                    ORDER BY x.id DESC
                    LIMIT 1
                ) c ON TRUE
                LEFT JOIN raw_fhir_responses r ON r.resource_id = c.raw_resource_id
                """
            )
            cur.execute(
                f"""
                SELECT
                    dc.claim_id, dc.patient_id, dc.payer_name, dc.service_date,
                    dc.validation_status, dc.data_quality_flags, dc.assembled_at,
                    r.source, {'dc.raw_resource_id' if is_completeness(workflow) else 'c.raw_resource_id'}
                FROM {table} dc
                {source_join}
                WHERE {' AND '.join(clauses)}
                ORDER BY {order}
                """,
                params,
            )
            for row in cur.fetchall():
                flags = list(row.get("data_quality_flags") or [])
                items.append(
                    {
                        "claim_id": row["claim_id"],
                        "patient_initials": _patient_initials(row.get("patient_id")),
                        "payer_name": row.get("payer_name") or "Unknown payer",
                        "service_date": row["service_date"].isoformat() if row.get("service_date") else None,
                        "source": row.get("source") or "manual",
                        "validation_status": row["validation_status"],
                        "data_quality_flags": flags,
                        "flag_count": len(flags),
                        "assembled_at": row["assembled_at"].isoformat() if row.get("assembled_at") else None,
                        "raw_resource_id": row.get("raw_resource_id"),
                    }
                )

        if include_quarantine:
            q_clauses = ["COALESCE(qr.workflow, %s) = %s"]
            q_params: list[Any] = [WORKFLOW_DEFAULT, workflow]
            if date_from:
                q_clauses.append("COALESCE(qr.created_at, NOW())::date >= %s")
                q_params.append(date_from)
            if date_to:
                q_clauses.append("COALESCE(qr.created_at, NOW())::date <= %s")
                q_params.append(date_to)
            if search:
                q_clauses.append("(COALESCE(qr.claim_id, qr.record->>'claim_id') ILIKE %s)")
                q_params.append(f"%{search.strip()}%")
            if source:
                q_clauses.append("COALESCE(r.source, 'manual') = %s")
                q_params.append(source)
            cur.execute(
                f"""
                SELECT qr.id, qr.raw_resource_id, qr.record, qr.data_quality_flags,
                       qr.created_at, qr.claim_id, r.source
                FROM quarantine_records qr
                LEFT JOIN raw_fhir_responses r ON r.resource_id = qr.raw_resource_id
                WHERE {' AND '.join(q_clauses)}
                ORDER BY qr.created_at DESC
                """,
                q_params,
            )
            for row in cur.fetchall():
                record = row.get("record") or {}
                if isinstance(record, str):
                    try:
                        record = json.loads(record)
                    except json.JSONDecodeError:
                        record = {}
                claim_id = row.get("claim_id") or record.get("claim_id") or row["raw_resource_id"]
                if payer_name and record.get("payer_name") != payer_name:
                    continue
                flags = list(row.get("data_quality_flags") or [])
                items.append(
                    {
                        "claim_id": claim_id,
                        "patient_initials": _patient_initials(record.get("patient_id")),
                        "payer_name": record.get("payer_name") or "Unknown payer",
                        "service_date": record.get("service_date"),
                        "source": row.get("source") or "manual",
                        "validation_status": "quarantined",
                        "data_quality_flags": flags,
                        "flag_count": len(flags),
                        "assembled_at": row["created_at"].isoformat() if row.get("created_at") else None,
                        "raw_resource_id": row.get("raw_resource_id"),
                        "quarantine_id": row["id"],
                    }
                )

    items.sort(key=lambda row: row.get("assembled_at") or "", reverse=sort != "assembled_at_asc")
    total = len(items)
    return {
        "items": items[offset : offset + limit],
        "total": total,
        "limit": limit,
        "offset": offset,
        "payers": payers,
        "sources": sources,
    }


@clean_router.get("/record/{claim_id}")
def get_record(
    claim_id: str,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        cur.execute("SELECT * FROM prior_auth_contexts WHERE claim_id = %s OR order_id = %s LIMIT 1", (claim_id, claim_id))
        row = cur.fetchone()
        if not row:
            cur.execute("SELECT * FROM denial_contexts WHERE claim_id = %s LIMIT 1", (claim_id,))
            row = cur.fetchone()
        quarantine = None
        if not row:
            cur.execute(
                """
                SELECT * FROM quarantine_records
                WHERE claim_id = %s OR record->>'claim_id' = %s OR raw_resource_id = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (claim_id, claim_id, claim_id),
            )
            quarantine = cur.fetchone()
            if not quarantine:
                raise HTTPException(status_code=404, detail="Record not found")
            payload = quarantine.get("record") or {}
            if isinstance(payload, str):
                payload = json.loads(payload)
            row = {
                **payload,
                "claim_id": payload.get("claim_id") or claim_id,
                "validation_status": "quarantined",
                "data_quality_flags": list(quarantine.get("data_quality_flags") or []),
                "assembled_at": quarantine.get("created_at"),
            }
        source, resource_id = _source_for_claim(
            cur,
            row.get("claim_id"),
            (quarantine or {}).get("raw_resource_id") if quarantine else None,
        )
        if not resource_id and quarantine:
            resource_id = quarantine.get("raw_resource_id")
        raw = _load_raw_payload(cur, resource_id)
        steps = _normalize_steps(raw, dict(row), source)
        fields = _field_views(dict(row), steps)
    log_audit_event(
        request,
        action="viewed_clean_record",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="denial_context",
        resource_id=claim_id,
    )
    safe_raw = raw
    if isinstance(safe_raw, dict) and "contained" in safe_raw:
        # Keep contained but frontend collapses; strip obviously named PHI keys if any.
        safe_raw = dict(safe_raw)
    return _jsonable(
        {
            **dict(row),
            "patient_initials": _patient_initials(row.get("patient_id")),
            "source": source,
            "raw_resource_id": resource_id,
            "raw_payload": safe_raw,
            "normalization_steps": steps,
            "fields": fields,
        }
    )


@clean_router.get("/quarantine")
def list_quarantine(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    workflow: str = Query(WORKFLOW_DEFAULT),
    review: str = "unreviewed",
    date_from: date | None = None,
    date_to: date | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    clauses = ["COALESCE(qr.workflow, %s) = %s"]
    params: list[Any] = [WORKFLOW_DEFAULT, workflow]
    if review == "unreviewed":
        clauses.append("qr.review_action IS NULL")
    elif review == "approved":
        clauses.append("qr.review_action = 'approved'")
    elif review == "dismissed":
        clauses.append("qr.review_action = 'dismissed'")
    if date_from:
        clauses.append("qr.created_at::date >= %s")
        params.append(date_from)
    if date_to:
        clauses.append("qr.created_at::date <= %s")
        params.append(date_to)
    with _cursor(request) as cur:
        cur.execute(
            f"SELECT COUNT(*) AS n FROM quarantine_records qr WHERE {' AND '.join(clauses)}",
            params,
        )
        total = int(cur.fetchone()["n"] or 0)
        cur.execute(
            """
            SELECT COUNT(*) AS n FROM quarantine_records WHERE review_action IS NULL
            """
        )
        unreviewed = int(cur.fetchone()["n"] or 0)
        cur.execute(
            f"""
            SELECT qr.id, qr.raw_resource_id, qr.record, qr.data_quality_flags,
                   qr.created_at, qr.claim_id, qr.reviewed_by, qr.reviewed_at,
                   qr.review_action, qr.override_reason, r.source,
                   u.full_name AS reviewed_by_name
            FROM quarantine_records qr
            LEFT JOIN raw_fhir_responses r ON r.resource_id = qr.raw_resource_id
            LEFT JOIN portal_users u ON u.id = qr.reviewed_by
            WHERE {' AND '.join(clauses)}
            ORDER BY qr.created_at DESC
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        )
        rows = cur.fetchall()
    items = []
    for row in rows:
        record = row.get("record") or {}
        if isinstance(record, str):
            try:
                record = json.loads(record)
            except json.JSONDecodeError:
                record = {}
        flags = list(row.get("data_quality_flags") or [])
        claim_id = row.get("claim_id") or record.get("claim_id")
        items.append(
            {
                "id": row["id"],
                "raw_resource_id": row["raw_resource_id"],
                "claim_id": claim_id,
                "patient_initials": _patient_initials(record.get("patient_id")),
                "payer_name": record.get("payer_name"),
                "rejection_reason": _rejection_reason(flags),
                "data_quality_flags": flags,
                "raw_data_preview": _preview(record),
                "quarantined_at": row["created_at"].isoformat() if row.get("created_at") else None,
                "reviewed_by": row.get("reviewed_by_name"),
                "reviewed_at": row["reviewed_at"].isoformat() if row.get("reviewed_at") else None,
                "review_action": row.get("review_action"),
                "source": row.get("source") or "manual",
            }
        )
    return {"items": items, "total": total, "unreviewed": unreviewed, "limit": limit, "offset": offset}


@clean_router.post("/quarantine/{record_id}/approve")
def approve_quarantine(
    record_id: int,
    body: OverrideBody,
    request: Request,
    user: dict[str, Any] = Depends(require_staff),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM quarantine_records WHERE id = %s", (record_id,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Quarantine record not found")
        record = row.get("record") or {}
        if isinstance(record, str):
            record = json.loads(record)
        claim_id = row.get("claim_id") or record.get("claim_id") or f"q-{record_id}"
        flags = list(row.get("data_quality_flags") or [])
        flags.append(f"manual_override: {body.override_reason.strip()}")
        service_date = record.get("service_date") or None
        workflow = row.get("workflow") or record.get("workflow") or WORKFLOW_DEFAULT
        if is_completeness(workflow):
            cur.execute(
                """
                INSERT INTO prior_auth_contexts (
                    order_id, claim_id, patient_id, member_id, service_date, payer_name,
                    diagnosis_codes, procedure_codes, clinical_notes_summary,
                    data_quality_flags, validation_status, assembled_at, auth_required
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'flagged', NOW(), %s)
                ON CONFLICT (claim_id) DO UPDATE SET
                    data_quality_flags = EXCLUDED.data_quality_flags,
                    validation_status = 'flagged'
                RETURNING id, claim_id
                """,
                (
                    record.get("order_id") or claim_id,
                    claim_id,
                    record.get("patient_id"),
                    record.get("member_id"),
                    service_date,
                    record.get("payer_name"),
                    record.get("diagnosis_codes") or [],
                    record.get("procedure_codes") or [],
                    record.get("clinical_notes_summary"),
                    flags,
                    record.get("auth_required") or "unknown",
                ),
            )
        else:
            cur.execute(
                """
                INSERT INTO denial_contexts (
                    claim_id, patient_id, service_date, denial_reason_code, denial_category,
                    canonical_denial_description, payer_name, diagnosis_codes, procedure_codes,
                    total_claim_amount, data_quality_flags, validation_status, assembled_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'flagged', NOW())
                ON CONFLICT (claim_id) DO UPDATE SET
                    data_quality_flags = EXCLUDED.data_quality_flags,
                    validation_status = 'flagged',
                    needs_reprocessing = FALSE
                RETURNING id, claim_id
                """,
                (
                    claim_id,
                    record.get("patient_id"),
                    service_date,
                    record.get("denial_reason_code"),
                    record.get("denial_category"),
                    record.get("canonical_denial_description"),
                    record.get("payer_name"),
                    record.get("diagnosis_codes") or [],
                    record.get("procedure_codes") or [],
                    record.get("total_claim_amount"),
                    flags,
                ),
            )
        inserted = cur.fetchone()
        cur.execute(
            """
            UPDATE quarantine_records
            SET reviewed_by = %s, reviewed_at = NOW(), review_action = 'approved',
                override_reason = %s, claim_id = %s
            WHERE id = %s
            """,
            (str(user["id"]), body.override_reason.strip(), claim_id, record_id),
        )
    conn.commit()
    log_audit_event(
        request,
        action="quarantine_record_approved",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="quarantine_record",
        resource_id=str(record_id),
        details={
            "quarantine_id": record_id,
            "override_reason": body.override_reason,
            "claim_id": claim_id,
        },
    )
    return {
        "success": True,
        "claim_id": inserted["claim_id"],
        "denial_context_id": inserted["id"],
    }


@clean_router.post("/quarantine/{record_id}/dismiss")
def dismiss_quarantine(
    record_id: int,
    body: DismissBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            UPDATE quarantine_records
            SET reviewed_by = %s, reviewed_at = NOW(), review_action = 'dismissed',
                override_reason = %s
            WHERE id = %s
            RETURNING id
            """,
            (str(user["id"]), body.dismiss_reason.strip(), record_id),
        )
        row = cur.fetchone()
    if not row:
        conn.rollback()
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    conn.commit()
    log_audit_event(
        request,
        action="quarantine_record_dismissed",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="quarantine_record",
        resource_id=str(record_id),
        details={"dismiss_reason": body.dismiss_reason},
    )
    return {"ok": True}


@clean_router.get("/payer-mappings")
def list_payer_mappings(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    client_id = user.get("client_id")
    with _cursor(request) as cur:
        cur.execute(
            """
            SELECT m.*, u.full_name AS validated_by_name
            FROM payer_name_mappings m
            LEFT JOIN portal_users u ON u.id = m.validated_by
            WHERE m.active = TRUE
              AND (m.client_id IS NULL OR m.client_id = %s)
            ORDER BY m.validated_by_provider ASC, m.confidence_score ASC, m.raw_name
            """,
            (client_id,),
        )
        rows = [_jsonable(dict(row)) for row in cur.fetchall()]
    pending = sum(1 for row in rows if not row.get("validated_by_provider"))
    return {"items": rows, "pending_validation": pending}


@clean_router.post("/payer-mappings/{mapping_id}/validate")
def validate_mapping(
    mapping_id: UUID,
    body: MappingValidateBody,
    request: Request,
    user: dict[str, Any] = Depends(require_staff),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM payer_name_mappings WHERE id = %s", (str(mapping_id),))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Mapping not found")
        old_name = row["canonical_name"]
        new_name = old_name
        if body.action == "reject":
            if not body.corrected_canonical_name or not body.corrected_canonical_name.strip():
                conn.rollback()
                raise HTTPException(status_code=400, detail="corrected_canonical_name is required")
            new_name = body.corrected_canonical_name.strip()
            cur.execute(
                """
                UPDATE denial_contexts
                SET needs_reprocessing = TRUE
                WHERE payer_name = %s
                """,
                (old_name,),
            )
        cur.execute(
            """
            UPDATE payer_name_mappings
            SET canonical_name = %s,
                validated_by_provider = TRUE,
                validated_at = NOW(),
                validated_by = %s
            WHERE id = %s
            """,
            (new_name, str(user["id"]), str(mapping_id)),
        )
    conn.commit()
    log_audit_event(
        request,
        action="confirmed_payer_mapping" if body.action == "confirm" else "corrected_payer_mapping",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="payer_mapping",
        resource_id=str(mapping_id),
        details={
            "raw_name": row["raw_name"],
            "canonical_name": new_name,
            "old_canonical": old_name,
        },
    )
    return {"ok": True}


@clean_router.post("/payer-mappings/add")
def add_mapping(
    body: MappingAddBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO payer_name_mappings (
                client_id, raw_name, canonical_name, canonical_payer_id,
                source, validated_by_provider, validated_at, validated_by, confidence_score
            )
            VALUES (%s, %s, %s, %s, 'manual', TRUE, NOW(), %s, 1.0)
            RETURNING *
            """,
            (
                user.get("client_id"),
                body.raw_name.strip(),
                body.canonical_name.strip(),
                body.canonical_payer_id,
                str(user["id"]),
            ),
        )
        row = cur.fetchone()
    conn.commit()
    log_audit_event(
        request,
        action="added_payer_mapping",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="payer_mapping",
        resource_id=str(row["id"]),
        details={"raw_name": body.raw_name, "canonical_name": body.canonical_name},
    )
    return _jsonable(dict(row))


@clean_router.get("/workflow-rules")
def list_workflow_rules(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    workflow: str = Query(WORKFLOW_DEFAULT),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        cur.execute(
            """
            SELECT id, workflow, rule_type, rule_config, active,
                   COALESCE(editable_by_provider, FALSE) AS editable_by_provider,
                   created_at
            FROM workflow_rules
            WHERE workflow = %s AND active = TRUE
            ORDER BY rule_type, id
            """,
            (workflow,),
        )
        rows = [_jsonable(dict(row)) for row in cur.fetchall()]
    grouped = {key: [] for key in ("required_fields", "payer_overrides", "escalation_rules", "code_aliases")}
    mapping = {
        "required_field": "required_fields",
        "payer_override": "payer_overrides",
        "escalation": "escalation_rules",
        "code_alias": "code_aliases",
    }
    for row in rows:
        grouped[mapping.get(row["rule_type"], "required_fields")].append(row)
    return {"workflow": workflow, **grouped}


@clean_router.patch("/workflow-rules/{rule_id}")
def patch_workflow_rule(
    rule_id: int,
    body: RulePatchBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM workflow_rules WHERE id = %s", (rule_id,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Rule not found")
        if not row.get("editable_by_provider"):
            conn.rollback()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=FORBIDDEN)
        config = _validate_rule_config(row["rule_type"], body.rule_config)
        before = row.get("rule_config")
        cur.execute(
            """
            UPDATE workflow_rules
            SET rule_config = %s, active = %s
            WHERE id = %s
            RETURNING *
            """,
            (json.dumps(config), body.active, rule_id),
        )
        updated = cur.fetchone()
    conn.commit()
    log_audit_event(
        request,
        action="updated_workflow_rule",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="workflow_rule",
        resource_id=str(rule_id),
        details={"before": before, "after": config, "active": body.active},
    )
    return _jsonable(dict(updated))
