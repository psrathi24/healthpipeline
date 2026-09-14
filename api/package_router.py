"""
Provider portal Package API — assembled case review, checklists, agent preview.

Verification checklist (manual):
□ Queue readiness tabs filter correctly
□ AgentReadinessScore: 0 flags=100, 1 optional=-10, 1 required=-40
□ Package detail loads as a full page
□ EvidenceField left border matches field status
□ Missing fields show inline suggestion text
□ Checklist groups Required / Recommended / Verify Manually
□ Manual checklist confirmation persists after refresh
□ Agent preview JSON matches MCP get_denial_context
□ Copy MCP call copies valid tool syntax
□ Mark Ready records override_note and override_by
□ Flag for Review sets needs_review = true
□ System templates show lock icon; custom templates edit/delete
□ Template auto-applies when payer + procedure match
□ All actions appear in portal_audit_log
□ RoleGuard hides Templates from billing
□ Queue list shows initials only; detail shows full patient label
"""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from psycopg2 import IntegrityError
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field

from .auth_router import get_current_user, log_audit_event
from .serve_router import (
    FORBIDDEN,
    WORKFLOW_DEFAULT,
    _forbidden,
    _jsonable,
    _patient_full_name,
    _patient_initials,
    require_admin,
)

package_router = APIRouter(tags=["package"])

CPT_LABELS = {
    "72148": "MRI lumbar spine without contrast",
    "72141": "MRI cervical spine without contrast",
    "70553": "MRI brain without and with contrast",
    "73721": "MRI any joint of lower extremity without contrast",
}

FIELD_HINTS = {
    "claim_id": "Not found in EOB. Check 837 claim.reference or the payer portal for this claim.",
    "patient_id": "Not found in the Patient reference. Link this resource to the EHR Patient record.",
    "member_id": "Not found in Coverage.subscriberId. Check the 271 eligibility response.",
    "service_date": "Not found in billablePeriod.start. Check the encounter appointment date.",
    "denial_reason_code": "Not found in EOB error[] or adjudication. Check ERA 835 CAS segment.",
    "diagnosis_codes": "Not found in diagnosis[].coding. Check encounter documentation for ICD-10.",
    "procedure_codes": "Not found in item[].productOrService. Check charge capture / CPT.",
    "payer_name": "Not found in insurer.display. Confirm coverage or add a payer mapping.",
    "clinical_notes_summary": "No clinical notes found. Pull the visit note from the EHR.",
    "provider_npi": "Ordering provider NPI was not in the source resource. Confirm in the EHR.",
    "payer_appeal_deadline": "Deadline could not be calculated. Confirm the payer appeal window.",
    "appeal_requirements": "No payer-specific appeal requirements stored for this case.",
}

FIELD_SOURCES = {
    "claim_id": ("ERA 835", "claim.reference"),
    "patient_id": ("Epic EHR", "Patient.reference"),
    "member_id": ("Payer API", "Coverage.subscriberId"),
    "service_date": ("ERA 835", "CCYYMMDD → ISO 8601"),
    "denial_reason_code": ("ERA 835", "error[].coding.code"),
    "diagnosis_codes": ("Epic EHR", "diagnosis[].coding.code"),
    "procedure_codes": ("ERA 835", "item[].productOrService"),
    "payer_name": ("Payer API", "insurer.display → payer_name_mapping"),
    "clinical_notes_summary": ("Epic EHR", "DocumentReference.text"),
    "provider_npi": ("Epic EHR", "provider.identifier"),
    "ordering_provider_npi": ("Epic EHR", "provider.identifier"),
    "payer_appeal_deadline": ("Payer API", "appeal window from payer rules"),
    "appeal_requirements": ("Payer API", "workflow_rules.appeal_requirements"),
    "total_claim_amount": ("ERA 835", "total.amount"),
    "denial_category": ("ERA 835", "code_mappings canonical category"),
    "canonical_denial_description": ("ERA 835", "code_mappings description"),
}

FIELD_LABELS = {
    "claim_id": "Claim ID",
    "patient_id": "Patient ID",
    "member_id": "Member ID",
    "service_date": "Service date",
    "procedure_codes": "Procedure code(s)",
    "diagnosis_codes": "Diagnosis code(s)",
    "total_claim_amount": "Total claim amount",
    "denial_reason_code": "Denial reason code",
    "denial_category": "Canonical denial category",
    "canonical_denial_description": "Canonical description",
    "payer_name": "Payer name",
    "payer_appeal_deadline": "Payer appeal deadline",
    "appeal_requirements": "Appeal requirements",
    "clinical_notes_summary": "Clinical notes summary",
    "provider_npi": "Ordering provider NPI",
    "ordering_provider_npi": "Ordering provider NPI",
}

SCORE_SQL = """
GREATEST(0, LEAST(100,
  100
  - 40 * (
    SELECT COUNT(*) FROM unnest(COALESCE(dc.data_quality_flags, ARRAY[]::text[])) AS f
    WHERE starts_with(f, 'missing_required')
  )
  - 10 * (
    SELECT COUNT(*) FROM unnest(COALESCE(dc.data_quality_flags, ARRAY[]::text[])) AS f
    WHERE starts_with(f, 'missing_optional')
  )
))
"""

BAND_SQL = f"""
CASE
  WHEN COALESCE(dc.manual_ready_override, FALSE) THEN 'ready'
  WHEN ({SCORE_SQL}) >= 80 THEN 'ready'
  WHEN ({SCORE_SQL}) >= 50 THEN 'incomplete'
  ELSE 'review_needed'
END
"""


class TemplateItemIn(BaseModel):
    label: str = Field(min_length=1, max_length=160)
    description: str | None = None
    field_source: str | None = None
    required: bool = True
    sort_order: int = 0


class TemplateCreateBody(BaseModel):
    workflow: str = WORKFLOW_DEFAULT
    payer_name: str | None = None
    procedure_code: str | None = None
    procedure_description: str | None = None
    checklist_items: list[TemplateItemIn] = Field(default_factory=list)


class TemplatePatchBody(BaseModel):
    payer_name: str | None = None
    procedure_code: str | None = None
    procedure_description: str | None = None
    active: bool | None = None
    checklist_items: list[TemplateItemIn] | None = None


class FlagBody(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)
    notify_admin: bool = False


class ReadyBody(BaseModel):
    override_note: str = Field(min_length=10, max_length=2000)


class ManualCheckBody(BaseModel):
    item_id: UUID
    confirmed: bool = True


def _db(request: Request):
    return request.app.state.db


def _cursor(request: Request):
    return _db(request).cursor(cursor_factory=RealDictCursor)


def require_staff(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if user.get("role") not in {"admin", "billing"}:
        raise _forbidden()
    return user


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    if isinstance(value, (list, tuple, dict)) and len(value) == 0:
        return False
    return True


def _readiness(
    flags: list[str] | None, override: bool = False
) -> tuple[int, str, list[dict[str, Any]]]:
    score = 100
    deductions: list[dict[str, Any]] = []
    for flag in flags or []:
        flag = str(flag)
        if flag.startswith("missing_required"):
            score -= 40
            deductions.append({"flag": flag, "points": -40})
        elif flag.startswith("missing_optional"):
            score -= 10
            deductions.append({"flag": flag, "points": -10})
    score = max(0, min(100, score))
    if override:
        band = "ready"
    elif score >= 80:
        band = "ready"
    elif score >= 50:
        band = "incomplete"
    else:
        band = "review_needed"
    return score, band, deductions


def _field_value(record: dict[str, Any], field_source: str | None) -> Any:
    if not field_source:
        return None
    if field_source == "member_id":
        return record.get("patient_id")
    if field_source == "provider_npi":
        return record.get("ordering_provider_npi")
    return record.get(field_source)


def _item_status(record: dict[str, Any], flags: list[str], item: dict[str, Any], confirmed: bool) -> str:
    field = item.get("field_source")
    if not field:
        return "met" if confirmed else "manual_check"
    value = _field_value(record, field)
    flag_set = set(flags or [])
    present = _present(value)
    if present and (
        f"missing_required:{field}" in flag_set or f"missing_optional:{field}" in flag_set
    ):
        return "partial"
    if present:
        return "met"
    return "missing"


def _procedure(record: dict[str, Any]) -> tuple[str | None, str | None]:
    codes = record.get("procedure_codes") or []
    code = codes[0] if codes else None
    if not code:
        return None, None
    return str(code), CPT_LABELS.get(str(code))


def _context(record: dict[str, Any], has_requirements: bool) -> dict[str, bool]:
    return {
        "has_clinical_notes": _present(record.get("clinical_notes_summary")),
        "has_diagnosis_codes": _present(record.get("diagnosis_codes")),
        "has_procedure_codes": _present(record.get("procedure_codes")),
        "has_denial_reason": _present(record.get("denial_reason_code")),
        "has_payer_requirements": has_requirements,
    }


def _display(value: Any) -> str | None:
    if not _present(value):
        return None
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value)
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)


def _pending_clause() -> str:
    return """
        dc.assembled_at IS NOT NULL
        AND dc.validation_status IN ('clean', 'flagged')
        AND NOT EXISTS (SELECT 1 FROM denial_outcomes o WHERE o.claim_id = dc.claim_id)
    """


def _load_items(cur, template_id: str) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT id, label, description, field_source, required, sort_order
        FROM package_checklist_items
        WHERE template_id = %s
        ORDER BY sort_order, created_at
        """,
        (template_id,),
    )
    return [_jsonable(dict(row)) for row in cur.fetchall()]


def _pick_template(cur, workflow: str, payer_name: str | None, procedure_code: str | None, client_id: str | None):
    cur.execute(
        """
        SELECT *
        FROM package_requirement_templates
        WHERE active = TRUE
          AND workflow = %s
          AND (client_id IS NULL OR client_id = %s)
        ORDER BY
          CASE WHEN payer_name IS NOT NULL AND procedure_code IS NOT NULL THEN 0
               WHEN payer_name IS NOT NULL THEN 1
               ELSE 2 END,
          CASE WHEN client_id IS NOT NULL THEN 0 ELSE 1 END
        """,
        (workflow, client_id),
    )
    rows = cur.fetchall()
    payer = (payer_name or "").strip() or None
    cpt = (procedure_code or "").strip() or None
    exact = next(
        (
            row
            for row in rows
            if row.get("payer_name") == payer and row.get("procedure_code") == cpt
        ),
        None,
    )
    if exact:
        return exact
    payer_only = next(
        (
            row
            for row in rows
            if row.get("payer_name") == payer and row.get("procedure_code") is None
        ),
        None,
    )
    if payer_only:
        return payer_only
    return next((row for row in rows if row.get("payer_name") is None and row.get("procedure_code") is None), None)


def _replace_items(cur, template_id: str, items: list[TemplateItemIn]) -> None:
    cur.execute("DELETE FROM package_checklist_items WHERE template_id = %s", (template_id,))
    for index, item in enumerate(items):
        cur.execute(
            """
            INSERT INTO package_checklist_items
              (template_id, label, description, field_source, required, sort_order)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                template_id,
                item.label.strip(),
                item.description,
                item.field_source,
                item.required,
                item.sort_order if item.sort_order else index,
            ),
        )


def _recommended_behavior(score: int, band: str, blocking: list[str], advisory: list[str]) -> str:
    if band == "review_needed" or blocking:
        listed = ", ".join(blocking) if blocking else "required fields"
        return f"Do not proceed. The following required fields are absent: {listed}. Resolve before routing to agent."
    if advisory:
        gaps = "; ".join(advisory)
        return (
            "Proceed with submission. Note in the submission letter: "
            f"{gaps}."
        )
    if score >= 80:
        return "All required fields confirmed. Agent can proceed with prior auth submission."
    return "Proceed with submission. Note remaining data quality gaps in the letter."


@package_router.get("/queue")
def get_queue(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    workflow: str = Query(WORKFLOW_DEFAULT),
    readiness: str = "all",
    payer_name: str | None = None,
    sort: str = "deadline_asc",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    del workflow
    order = {
        "deadline_asc": "dc.payer_appeal_deadline ASC NULLS LAST, dc.assembled_at DESC",
        "deadline_desc": "dc.payer_appeal_deadline DESC NULLS LAST",
        "readiness": "score ASC, dc.payer_appeal_deadline ASC NULLS LAST",
        "date": "dc.assembled_at DESC",
        "assembled_at": "dc.assembled_at DESC",
    }.get(sort, "dc.payer_appeal_deadline ASC NULLS LAST, dc.assembled_at DESC")
    clauses = [_pending_clause()]
    params: list[Any] = []
    if payer_name:
        clauses.append("dc.payer_name = %s")
        params.append(payer_name)
    if readiness in {"ready", "incomplete", "review_needed"}:
        clauses.append(f"({BAND_SQL}) = %s")
        params.append(readiness)
    where_sql = " AND ".join(clauses)
    with _cursor(request) as cur:
        cur.execute(
            f"SELECT COUNT(*) AS n FROM denial_contexts dc WHERE {where_sql}",
            params,
        )
        total = int(cur.fetchone()["n"] or 0)
        count_where = _pending_clause()
        count_params: list[Any] = []
        if payer_name:
            count_where += " AND dc.payer_name = %s"
            count_params.append(payer_name)
        cur.execute(
            f"""
            SELECT
              COUNT(*) AS all_count,
              COUNT(*) FILTER (WHERE ({BAND_SQL}) = 'ready') AS ready,
              COUNT(*) FILTER (WHERE ({BAND_SQL}) = 'incomplete') AS incomplete,
              COUNT(*) FILTER (WHERE ({BAND_SQL}) = 'review_needed') AS review_needed
            FROM denial_contexts dc
            WHERE {count_where}
            """,
            count_params,
        )
        counts = cur.fetchone() or {}
        cur.execute(
            f"""
            SELECT
                dc.claim_id, dc.patient_id, dc.payer_name, dc.procedure_codes,
                dc.denial_category, dc.service_date, dc.payer_appeal_deadline,
                CASE WHEN dc.payer_appeal_deadline IS NULL THEN NULL
                     ELSE (dc.payer_appeal_deadline - CURRENT_DATE) END AS days_until_deadline,
                dc.validation_status, dc.data_quality_flags, dc.assembled_at,
                dc.clinical_notes_summary, dc.diagnosis_codes, dc.denial_reason_code,
                dc.appeal_requirements, dc.manual_ready_override, dc.needs_review,
                ({SCORE_SQL}) AS score,
                ({BAND_SQL}) AS readiness_band
            FROM denial_contexts dc
            WHERE {where_sql}
            ORDER BY {order}
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        )
        rows = cur.fetchall()
        cur.execute(
            """
            SELECT DISTINCT payer_name FROM denial_contexts
            WHERE payer_name IS NOT NULL AND btrim(payer_name) <> ''
            ORDER BY payer_name
            """
        )
        payers = [row["payer_name"] for row in cur.fetchall()]
        cur.execute(
            """
            SELECT DISTINCT payer FROM (
                SELECT rule_config->>'payer' AS payer
                FROM workflow_rules
                WHERE rule_type = 'payer_override' AND active = TRUE
            ) x WHERE payer IS NOT NULL
            """
        )
        requirement_payers = {row["payer"] for row in cur.fetchall()}
    items = []
    for row in rows:
        flags = list(row.get("data_quality_flags") or [])
        score, band, deductions = _readiness(flags, bool(row.get("manual_ready_override")))
        code, description = _procedure(row)
        has_req = bool(row.get("appeal_requirements")) or (row.get("payer_name") in requirement_payers)
        items.append(
            {
                "claim_id": row["claim_id"],
                "patient_initials": _patient_initials(row.get("patient_id")),
                "payer_name": row.get("payer_name") or "Unknown payer",
                "procedure_code": code,
                "procedure_description": description,
                "denial_category": row.get("denial_category"),
                "service_date": row["service_date"].isoformat() if row.get("service_date") else None,
                "payer_appeal_deadline": row["payer_appeal_deadline"].isoformat()
                if row.get("payer_appeal_deadline")
                else None,
                "days_until_deadline": int(row["days_until_deadline"])
                if row.get("days_until_deadline") is not None
                else None,
                "validation_status": row["validation_status"],
                "data_quality_flags": flags,
                "flag_count": len(flags),
                "agent_readiness_score": score,
                "readiness_band": row.get("readiness_band") or band,
                "readiness_deductions": deductions,
                "assembled_at": row["assembled_at"].isoformat() if row.get("assembled_at") else None,
                "needs_review": bool(row.get("needs_review")),
                "manual_ready_override": bool(row.get("manual_ready_override")),
                "workflow_specific_context": _context(dict(row), has_req),
            }
        )
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "payers": payers,
        "counts": {
            "all": int(counts.get("all_count") or 0),
            "ready": int(counts.get("ready") or 0),
            "incomplete": int(counts.get("incomplete") or 0),
            "review_needed": int(counts.get("review_needed") or 0),
        },
    }


@package_router.get("/case/{claim_id}")
def get_package_case(
    claim_id: str,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        cur.execute("SELECT * FROM denial_contexts WHERE claim_id = %s LIMIT 1", (claim_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Package not found")
        record = dict(row)
        flags = list(record.get("data_quality_flags") or [])
        score, band, deductions = _readiness(flags, bool(record.get("manual_ready_override")))
        code, description = _procedure(record)
        template = _pick_template(
            cur,
            WORKFLOW_DEFAULT,
            record.get("payer_name"),
            code,
            user.get("client_id"),
        )
        items = _load_items(cur, str(template["id"])) if template else []
        cur.execute(
            """
            SELECT item_id, confirmed_at, u.full_name AS confirmed_by_name
            FROM package_manual_checks c
            LEFT JOIN portal_users u ON u.id = c.confirmed_by
            WHERE c.claim_id = %s
            """,
            (claim_id,),
        )
        confirmed = {str(row["item_id"]): dict(row) for row in cur.fetchall()}
        cur.execute(
            """
            SELECT id, rule_type, rule_config, created_at
            FROM workflow_rules
            WHERE active = TRUE AND rule_type = 'payer_override'
              AND (rule_config->>'payer') = %s
            """,
            (record.get("payer_name"),),
        )
        payer_requirements = [_jsonable(dict(row)) for row in cur.fetchall()]
        cur.execute(
            """
            SELECT appeal_filed_at, appeal_method, appeal_outcome, created_at, agent_used
            FROM denial_outcomes WHERE claim_id = %s ORDER BY created_at
            """,
            (claim_id,),
        )
        outcomes = [_jsonable(dict(row)) for row in cur.fetchall()]
        cur.execute(
            """
            SELECT extractor_name, started_at, completed_at, status, records_inserted
            FROM extraction_log
            WHERE status = 'success'
            ORDER BY completed_at DESC NULLS LAST
            LIMIT 3
            """
        )
        extractions = [_jsonable(dict(row)) for row in cur.fetchall()]
        cur.execute(
            """
            SELECT action, created_at, user_email, details
            FROM portal_audit_log
            WHERE resource_id = %s
            ORDER BY created_at
            LIMIT 40
            """,
            (claim_id,),
        )
        audits = [_jsonable(dict(row)) for row in cur.fetchall()]

    checklist = []
    for item in items:
        hit = confirmed.get(str(item["id"]))
        status_name = _item_status(record, flags, item, bool(hit))
        checklist.append(
            {
                **item,
                "status": status_name,
                "value": _display(_field_value(record, item.get("field_source"))),
                "hint": FIELD_HINTS.get(item.get("field_source") or ""),
                "confirmed_at": hit["confirmed_at"].isoformat() if hit and hit.get("confirmed_at") else None,
                "confirmed_by": hit.get("confirmed_by_name") if hit else None,
            }
        )

    evidence_fields = [
        "claim_id",
        "patient_id",
        "member_id",
        "service_date",
        "procedure_codes",
        "diagnosis_codes",
        "total_claim_amount",
        "denial_reason_code",
        "denial_category",
        "canonical_denial_description",
        "payer_name",
        "payer_appeal_deadline",
        "clinical_notes_summary",
        "provider_npi",
        "appeal_requirements",
        "ordering_provider_npi",
    ]
    evidence = []
    for field in evidence_fields:
        source, transform = FIELD_SOURCES.get(field, (None, None))
        value = _field_value(record, field if field != "ordering_provider_npi" else "provider_npi")
        if field == "ordering_provider_npi":
            value = record.get("ordering_provider_npi")
        flag_set = set(flags)
        mapped = "member_id" if field == "member_id" else field
        if field in {"provider_npi", "ordering_provider_npi"}:
            mapped = "provider_npi"
        present = _present(value)
        if not FIELD_SOURCES.get(field) and field not in record and field not in {"member_id", "provider_npi"}:
            status_name = "missing"
        elif mapped and (
            f"missing_required:{mapped}" in flag_set or f"missing_optional:{mapped}" in flag_set
        ) and present:
            status_name = "partial"
        elif present:
            status_name = "met"
        else:
            status_name = "missing"
        evidence.append(
            {
                "field": field,
                "label": FIELD_LABELS.get(field, field.replace("_", " ")),
                "value": _display(value),
                "status": status_name,
                "source": source,
                "transformation": transform,
                "hint": FIELD_HINTS.get(mapped or field),
            }
        )

    timeline = []
    for ext in reversed(extractions):
        when = ext.get("completed_at") or ext.get("started_at")
        timeline.append(
            {
                "at": when,
                "label": f"Raw EOB received from {ext.get('extractor_name')}",
                "actor": ext.get("extractor_name"),
                "future": False,
            }
        )
    if record.get("assembled_at"):
        timeline.append(
            {
                "at": record["assembled_at"].isoformat()
                if isinstance(record["assembled_at"], datetime)
                else record["assembled_at"],
                "label": "Transformed, validated, and package assembled",
                "actor": "Kalamon engine",
                "future": False,
            }
        )
    for flag in flags[:4]:
        timeline.append(
            {
                "at": record.get("assembled_at").isoformat()
                if isinstance(record.get("assembled_at"), datetime)
                else record.get("assembled_at"),
                "label": f"Flagged: {flag}",
                "actor": "validator",
                "future": False,
            }
        )
    for event in audits:
        timeline.append(
            {
                "at": event.get("created_at"),
                "label": event.get("action"),
                "actor": event.get("user_email"),
                "future": False,
            }
        )
    for outcome in outcomes:
        timeline.append(
            {
                "at": outcome.get("created_at"),
                "label": f"Outcome recorded: {outcome.get('appeal_outcome')}",
                "actor": outcome.get("agent_used") or "staff",
                "future": False,
            }
        )
    if not outcomes:
        timeline.append({"at": None, "label": "Awaiting agent action", "actor": None, "future": True})

    blocking = [flag for flag in flags if str(flag).startswith("missing_required")]
    advisory = [flag for flag in flags if str(flag).startswith("missing_optional")]
    log_audit_event(
        request,
        action="package_viewed",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="denial_context",
        resource_id=claim_id,
    )
    specific = bool(template and (template.get("payer_name") or template.get("procedure_code")))
    return _jsonable(
        {
            **record,
            "patient_initials": _patient_initials(record.get("patient_id")),
            "patient_full_name": _patient_full_name(record.get("patient_id")),
            "procedure_code": code,
            "procedure_description": description,
            "agent_readiness_score": score,
            "readiness_band": band,
            "readiness_deductions": deductions,
            "payer_requirements": payer_requirements,
            "requirement_checklist": checklist,
            "template": _jsonable(dict(template)) if template else None,
            "using_default_template": not specific,
            "evidence": evidence,
            "package_timeline": timeline,
            "prior_submission_history": record.get("prior_submission_history") or outcomes,
            "workflow_specific_context": _context(record, bool(payer_requirements or record.get("appeal_requirements"))),
            "blocking_gaps": blocking,
            "advisory_gaps": advisory,
            "recommended_agent_behavior": _recommended_behavior(score, band, blocking, advisory),
        }
    )


@package_router.get("/agent-preview/{claim_id}")
def get_agent_preview(
    claim_id: str,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        cur.execute("SELECT * FROM denial_contexts WHERE claim_id = %s LIMIT 1", (claim_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Package not found")
    record = dict(row)
    flags = list(record.get("data_quality_flags") or [])
    score, band, _deductions = _readiness(flags, bool(record.get("manual_ready_override")))
    blocking = [flag for flag in flags if str(flag).startswith("missing_required")]
    advisory = [flag for flag in flags if str(flag).startswith("missing_optional")]
    payload = _jsonable(dict(record))
    instructions = {
        "claim_id": "Use as the primary reference ID",
        "denial_category": "Determines appeal strategy",
        "data_quality_flags": "Review before proceeding",
        "payer_appeal_deadline": "Hard deadline for filing",
        "appeal_requirements": "Use as submission checklist",
        "diagnosis_codes": "Cite as medical necessity support",
        "procedure_codes": "The denied service to authorize",
        "clinical_notes_summary": "Source language for the letter",
        "payer_name": "Select the correct payer channel",
    }
    log_audit_event(
        request,
        action="agent_payload_preview_viewed",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="denial_context",
        resource_id=claim_id,
    )
    return {
        "claim_id": claim_id,
        "mcp_call": f'get_denial_context(claim_id="{claim_id}")',
        "payload": payload,
        "agent_instructions": instructions,
        "readiness_assessment": {
            "score": score,
            "band": band,
            "can_proceed": not blocking or bool(record.get("manual_ready_override")),
            "blocking_gaps": blocking,
            "advisory_gaps": advisory,
            "recommended_agent_behavior": _recommended_behavior(score, band, blocking, advisory),
        },
    }


@package_router.get("/requirement-templates")
def list_templates(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    workflow: str = Query(WORKFLOW_DEFAULT),
    payer_name: str | None = None,
    procedure_code: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    clauses = ["t.active = TRUE", "t.workflow = %s"]
    params: list[Any] = [workflow]
    if payer_name:
        clauses.append("(t.payer_name IS NULL OR t.payer_name = %s)")
        params.append(payer_name)
    if procedure_code:
        clauses.append("(t.procedure_code IS NULL OR t.procedure_code = %s)")
        params.append(procedure_code)
    if source in {"system", "provider_custom"}:
        clauses.append("t.source = %s")
        params.append(source)
    with _cursor(request) as cur:
        cur.execute(
            f"""
            SELECT t.*, u.full_name AS created_by_name
            FROM package_requirement_templates t
            LEFT JOIN portal_users u ON u.id = t.created_by
            WHERE {' AND '.join(clauses)}
            ORDER BY t.source DESC, t.payer_name NULLS LAST, t.procedure_code NULLS LAST
            """,
            params,
        )
        rows = cur.fetchall()
        items = []
        for row in rows:
            checklist = _load_items(cur, str(row["id"]))
            items.append(
                {
                    **_jsonable(dict(row)),
                    "template_id": str(row["id"]),
                    "checklist_items": checklist,
                    "item_count": len(checklist),
                    "required_count": sum(1 for item in checklist if item.get("required")),
                    "recommended_count": sum(1 for item in checklist if not item.get("required") and item.get("field_source")),
                    "manual_count": sum(1 for item in checklist if not item.get("field_source")),
                }
            )
    return {"items": items}


@package_router.post("/requirement-templates")
def create_template(
    body: TemplateCreateBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    conn = _db(request)
    payer = body.payer_name or None
    cpt = body.procedure_code or None
    description = body.procedure_description or CPT_LABELS.get(cpt or "")
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT *
            FROM package_requirement_templates
            WHERE workflow = %s
              AND COALESCE(client_id, '') = COALESCE(%s, '')
              AND COALESCE(payer_name, '') = COALESCE(%s, '')
              AND COALESCE(procedure_code, '') = COALESCE(%s, '')
            """,
            (body.workflow, user.get("client_id"), payer, cpt),
        )
        existing = cur.fetchone()
        created = existing is None
        if existing and existing.get("source") == "system":
            conn.rollback()
            raise HTTPException(
                status_code=409,
                detail="Cannot overwrite a system template. Duplicate it as custom with a payer or CPT scope.",
            )
        try:
            if existing:
                cur.execute(
                    """
                    UPDATE package_requirement_templates
                    SET procedure_description = COALESCE(%s, procedure_description),
                        updated_at = NOW()
                    WHERE id = %s
                    RETURNING *
                    """,
                    (description, str(existing["id"])),
                )
                row = cur.fetchone()
            else:
                cur.execute(
                    """
                    INSERT INTO package_requirement_templates
                      (client_id, workflow, payer_name, procedure_code, procedure_description,
                       source, created_by)
                    VALUES (%s, %s, %s, %s, %s, 'provider_custom', %s)
                    RETURNING *
                    """,
                    (
                        user.get("client_id"),
                        body.workflow,
                        payer,
                        cpt,
                        description,
                        str(user["id"]),
                    ),
                )
                row = cur.fetchone()
        except IntegrityError as exc:
            conn.rollback()
            raise HTTPException(
                status_code=409,
                detail="A template already exists for this scope.",
            ) from exc
        _replace_items(cur, str(row["id"]), body.checklist_items)
        items = _load_items(cur, str(row["id"]))
    conn.commit()
    log_audit_event(
        request,
        action="requirement_template_created" if created else "requirement_template_updated",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="package_template",
        resource_id=str(row["id"]),
        details={"payer": body.payer_name, "procedure_code": body.procedure_code},
    )
    return _jsonable({**dict(row), "template_id": str(row["id"]), "checklist_items": items})


@package_router.patch("/requirement-templates/{template_id}")
def patch_template(
    template_id: UUID,
    body: TemplatePatchBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM package_requirement_templates WHERE id = %s", (str(template_id),))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Template not found")
        if row.get("source") == "system":
            conn.rollback()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=FORBIDDEN)
        before = _jsonable(dict(row))
        cur.execute(
            """
            UPDATE package_requirement_templates
            SET payer_name = COALESCE(%s, payer_name),
                procedure_code = COALESCE(%s, procedure_code),
                procedure_description = COALESCE(%s, procedure_description),
                active = COALESCE(%s, active),
                updated_at = NOW()
            WHERE id = %s
            RETURNING *
            """,
            (
                body.payer_name,
                body.procedure_code,
                body.procedure_description,
                body.active,
                str(template_id),
            ),
        )
        updated = cur.fetchone()
        if body.checklist_items is not None:
            _replace_items(cur, str(template_id), body.checklist_items)
        items = _load_items(cur, str(template_id))
    conn.commit()
    log_audit_event(
        request,
        action="requirement_template_updated",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="package_template",
        resource_id=str(template_id),
        details={"before": before, "after": _jsonable(dict(updated))},
    )
    return _jsonable({**dict(updated), "template_id": str(updated["id"]), "checklist_items": items})


@package_router.delete("/requirement-templates/{template_id}")
def delete_template(
    template_id: UUID,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT source FROM package_requirement_templates WHERE id = %s", (str(template_id),))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Template not found")
        if row.get("source") == "system":
            conn.rollback()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=FORBIDDEN)
        cur.execute("DELETE FROM package_requirement_templates WHERE id = %s", (str(template_id),))
    conn.commit()
    log_audit_event(
        request,
        action="requirement_template_deleted",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="package_template",
        resource_id=str(template_id),
    )
    return {"ok": True}


@package_router.post("/requirement-templates/{template_id}/items")
def add_item(
    template_id: UUID,
    body: TemplateItemIn,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT source FROM package_requirement_templates WHERE id = %s", (str(template_id),))
        row = cur.fetchone()
        if not row or row.get("source") == "system":
            conn.rollback()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=FORBIDDEN)
        cur.execute(
            """
            INSERT INTO package_checklist_items
              (template_id, label, description, field_source, required, sort_order)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                str(template_id),
                body.label,
                body.description,
                body.field_source,
                body.required,
                body.sort_order,
            ),
        )
        item = cur.fetchone()
    conn.commit()
    return _jsonable(dict(item))


@package_router.delete("/requirement-templates/{template_id}/items/{item_id}")
def remove_item(
    template_id: UUID,
    item_id: UUID,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT source FROM package_requirement_templates WHERE id = %s", (str(template_id),))
        row = cur.fetchone()
        if not row or row.get("source") == "system":
            conn.rollback()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=FORBIDDEN)
        cur.execute(
            "DELETE FROM package_checklist_items WHERE id = %s AND template_id = %s",
            (str(item_id), str(template_id)),
        )
    conn.commit()
    return {"ok": True}


@package_router.post("/case/{claim_id}/checklist")
def confirm_manual_item(
    claim_id: str,
    body: ManualCheckBody,
    request: Request,
    user: dict[str, Any] = Depends(require_staff),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        if body.confirmed:
            cur.execute(
                """
                INSERT INTO package_manual_checks (claim_id, item_id, confirmed_by, confirmed_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (claim_id, item_id) DO UPDATE
                  SET confirmed_by = EXCLUDED.confirmed_by, confirmed_at = NOW()
                """,
                (claim_id, str(body.item_id), str(user["id"])),
            )
        else:
            cur.execute(
                "DELETE FROM package_manual_checks WHERE claim_id = %s AND item_id = %s",
                (claim_id, str(body.item_id)),
            )
    conn.commit()
    log_audit_event(
        request,
        action="manual_checklist_item_confirmed",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="denial_context",
        resource_id=claim_id,
        details={"item_id": str(body.item_id), "confirmed": body.confirmed},
    )
    return {"ok": True}


@package_router.post("/case/{claim_id}/flag-for-review")
def flag_for_review(
    claim_id: str,
    body: FlagBody,
    request: Request,
    user: dict[str, Any] = Depends(require_staff),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            UPDATE denial_contexts
            SET needs_review = TRUE, review_reason = %s
            WHERE claim_id = %s
            RETURNING claim_id
            """,
            (body.reason.strip(), claim_id),
        )
        row = cur.fetchone()
    if not row:
        conn.rollback()
        raise HTTPException(status_code=404, detail="Package not found")
    conn.commit()
    log_audit_event(
        request,
        action="package_flagged_for_review",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="denial_context",
        resource_id=claim_id,
        details={"reason": body.reason, "notify_admin": body.notify_admin},
    )
    return {"ok": True}


@package_router.post("/case/{claim_id}/mark-ready")
def mark_ready(
    claim_id: str,
    body: ReadyBody,
    request: Request,
    user: dict[str, Any] = Depends(require_staff),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            UPDATE denial_contexts
            SET manual_ready_override = TRUE,
                override_note = %s,
                override_by = %s,
                override_at = NOW()
            WHERE claim_id = %s
            RETURNING claim_id
            """,
            (body.override_note.strip(), str(user["id"]), claim_id),
        )
        row = cur.fetchone()
    if not row:
        conn.rollback()
        raise HTTPException(status_code=404, detail="Package not found")
    conn.commit()
    log_audit_event(
        request,
        action="package_marked_ready",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="denial_context",
        resource_id=claim_id,
        details={"override_note": body.override_note},
    )
    return {"ok": True}
