"""
Provider portal Serve API — worklist, pipeline health, outcomes, vendors.

Verification checklist (manual):
□ Worklist loads and shows real data from denial_contexts table
□ Patient initials show in list, full name only in case drawer (PHI minimization)
□ Deadline countdown colors correct for all states
□ Case drawer slides in without page navigation
□ Data quality flags show plain English, not codes
□ Source tags show correct origin per field
□ Outcome form saves to denial_outcomes table
□ Pipeline health reflects real extraction_log data
□ Manual run button disabled for billing role
□ Vendor management hidden for billing role
□ API key shown once, cannot be retrieved again
□ MCP connection instructions copy correctly
□ Query log shows no PHI in input params column
□ Session timeout modal appears after 20min
□ All actions logged to portal_audit_log
□ 401 response redirects to /login
□ 403 response shows inline error, no redirect
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sys
import threading
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field

from .auth_router import get_current_user, log_audit_event
from .auth_security import hash_token, utcnow
from .workflows import WORKFLOW_COMPLETENESS, WORKFLOW_DEFAULT, case_table, is_completeness

serve_router = APIRouter(tags=["serve"])
audit_router = APIRouter(tags=["audit"])

_ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = {
    "code": "forbidden",
    "message": "You don't have permission to view this.",
}

SORT_SQL = {
    "deadline_asc": "dc.payer_appeal_deadline ASC NULLS LAST, dc.assembled_at DESC",
    "deadline_desc": "dc.payer_appeal_deadline DESC NULLS LAST, dc.assembled_at DESC",
    "payer": "dc.payer_name ASC NULLS LAST, dc.payer_appeal_deadline ASC NULLS LAST",
    "assembled_at": "dc.assembled_at DESC NULLS LAST",
}
APPEAL_METHODS = {
    "agent": "agent_generated",
    "agent_generated": "agent_generated",
    "manual": "manual",
    "hybrid": "hybrid",
}


class OutcomeBody(BaseModel):
    appeal_filed: bool
    appeal_method: str
    appeal_outcome: Literal["approved", "denied", "pending", "escalated"]
    staff_minutes_saved: float | None = None
    amount_recovered: float | None = None
    agent_used: str | None = None


class VendorBody(BaseModel):
    vendor_name: str = Field(min_length=1, max_length=120)
    vendor_type: str | None = "other"
    workflows: list[str] = Field(default_factory=lambda: [WORKFLOW_DEFAULT])


class AuditBody(BaseModel):
    action: str = Field(min_length=1, max_length=80)
    resource_type: str | None = None
    resource_id: str | None = None
    details: dict[str, Any] | None = None
    success: bool = True
    error_message: str | None = None


class ManualRunBody(BaseModel):
    workflow: str = WORKFLOW_DEFAULT
    source: str | None = "all"


def _db(request: Request):
    return request.app.state.db


def _cursor(request: Request):
    return _db(request).cursor(cursor_factory=RealDictCursor)


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


def _forbidden() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=FORBIDDEN)


def require_admin(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if user.get("role") != "admin":
        raise _forbidden()
    return user


def _patient_initials(patient_id: str | None) -> str:
    if not patient_id:
        return "—"
    digest = hashlib.sha256(patient_id.encode("utf-8")).hexdigest()
    first = chr(ord("A") + int(digest[0:2], 16) % 26)
    last = chr(ord("A") + int(digest[2:4], 16) % 26)
    return f"{first}.{last}."


def _patient_full_name(patient_id: str | None) -> str:
    initials = _patient_initials(patient_id)
    if initials == "—":
        return "Unknown patient"
    return f"Patient {initials} (ID {patient_id})"


def _source_from_history(history: Any) -> str:
    if isinstance(history, str):
        try:
            history = json.loads(history)
        except json.JSONDecodeError:
            history = {}
    if not isinstance(history, dict):
        return "Manual"
    runs = history.get("extraction_runs") or []
    names = " ".join(str(run.get("extractor_name") or "") for run in runs).lower()
    if "epic" in names:
        return "Epic"
    if "bluebutton" in names:
        return "Payer API"
    if "hapi" in names:
        return "Epic"
    return "Manual"


def _display_source(kind: str, history: Any) -> str:
    if kind == "denial":
        return "ERA 835"
    if kind == "payer":
        return "Payer API"
    if kind == "manual":
        return "Manual"
    mapped = _source_from_history(history)
    if mapped == "Payer API" and kind == "clinical":
        return "Epic EHR"
    if kind == "clinical":
        return "Epic EHR" if mapped == "Epic" else mapped
    return mapped


def _relative_hours(ts: datetime | None) -> int | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return int((utcnow() - ts).total_seconds() // 3600)


@serve_router.get("/worklist")
def get_worklist(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    workflow: str = Query(WORKFLOW_DEFAULT),
    payer_name: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    sort: str = "deadline_asc",
    q: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    del user
    table = case_table(workflow)
    order_sql = SORT_SQL.get(sort, SORT_SQL["deadline_asc"])
    clauses = [
        "dc.assembled_at IS NOT NULL",
        "dc.validation_status IN ('clean', 'flagged')",
    ]
    if not is_completeness(workflow):
        clauses.append(
            """NOT EXISTS (
            SELECT 1 FROM denial_outcomes o WHERE o.claim_id = dc.claim_id
        )"""
        )
    params: list[Any] = []
    if payer_name:
        clauses.append("dc.payer_name = %s")
        params.append(payer_name)
    if status_filter in {"clean", "flagged"}:
        clauses.append("dc.validation_status = %s")
        params.append(status_filter)
    if q:
        clauses.append("dc.claim_id ILIKE %s")
        params.append(f"%{q.strip()}%")
    where_sql = " AND ".join(clauses)
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"SELECT COUNT(*) AS total FROM {table} dc WHERE {where_sql}",
            params,
        )
        total = int(cur.fetchone()["total"] or 0)
        cur.execute(
            f"""
            SELECT
                dc.claim_id,
                dc.patient_id,
                dc.payer_name,
                dc.procedure_codes,
                dc.service_date,
                dc.denial_category,
                dc.payer_appeal_deadline,
                CASE
                    WHEN dc.payer_appeal_deadline IS NULL THEN NULL
                    ELSE (dc.payer_appeal_deadline - CURRENT_DATE)
                END AS days_until_deadline,
                dc.validation_status,
                dc.data_quality_flags,
                dc.assembled_at
            FROM {table} dc
            WHERE {where_sql}
            ORDER BY {order_sql}
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        )
        rows = cur.fetchall()
        cur.execute(
            f"""
            SELECT DISTINCT payer_name
            FROM {table}
            WHERE payer_name IS NOT NULL AND btrim(payer_name) <> ''
            ORDER BY payer_name
            """
        )
        payers = [row["payer_name"] for row in cur.fetchall()]
    items = []
    for row in rows:
        procedures = row.get("procedure_codes") or []
        items.append(
            {
                "claim_id": row["claim_id"],
                "patient_initials": _patient_initials(row.get("patient_id")),
                "payer_name": row.get("payer_name") or "Unknown payer",
                "procedure_code": procedures[0] if procedures else None,
                "service_date": row["service_date"].isoformat() if row.get("service_date") else None,
                "denial_category": row.get("denial_category"),
                "denial_reason_code": None,
                "payer_appeal_deadline": row["payer_appeal_deadline"].isoformat()
                if row.get("payer_appeal_deadline")
                else None,
                "days_until_deadline": int(row["days_until_deadline"])
                if row.get("days_until_deadline") is not None
                else None,
                "validation_status": row["validation_status"],
                "data_quality_flags": list(row.get("data_quality_flags") or []),
                "assembled_at": row["assembled_at"].isoformat() if row.get("assembled_at") else None,
                "outcome_status": None,
            }
        )
    return {"items": items, "total": total, "limit": limit, "offset": offset, "payers": payers}


@serve_router.get("/case/{claim_id}")
def get_case(
    claim_id: str,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        cur.execute("SELECT * FROM prior_auth_contexts WHERE claim_id = %s OR order_id = %s LIMIT 1", (claim_id, claim_id))
        row = cur.fetchone()
        workflow_used = WORKFLOW_COMPLETENESS
        if not row:
            cur.execute("SELECT * FROM denial_contexts WHERE claim_id = %s LIMIT 1", (claim_id,))
            row = cur.fetchone()
            workflow_used = WORKFLOW_DEFAULT
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        cur.execute(
            """
            SELECT id, claim_id, appeal_filed_at, appeal_method, appeal_outcome,
                   time_to_resolution_hours, staff_minutes_saved, amount_recovered,
                   agent_used, created_at
            FROM denial_outcomes
            WHERE claim_id = %s
            ORDER BY created_at DESC
            """,
            (claim_id,),
        )
        outcomes = [_jsonable(dict(item)) for item in cur.fetchall()]
        cur.execute(
            """
            SELECT rule_type, rule_config
            FROM workflow_rules
            WHERE workflow = %s AND active = TRUE
            ORDER BY rule_type, id
            """,
            (workflow_used,),
        )
        rules = [_jsonable(dict(item)) for item in cur.fetchall()]
    log_audit_event(
        request,
        action="viewed_case_detail",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="denial_context",
        resource_id=claim_id,
    )
    history = row.get("prior_submission_history")
    flags = list(row.get("data_quality_flags") or [])
    diagnosis = list(row.get("diagnosis_codes") or [])
    procedures = list(row.get("procedure_codes") or [])
    evidence = [
        {
            "field": "Member ID",
            "value": row.get("patient_id") or "—",
            "source": _display_source("clinical", history),
        },
        {
            "field": "Diagnosis",
            "value": ", ".join(diagnosis) if diagnosis else "—",
            "source": _display_source("clinical", history),
        },
        {
            "field": "Clinical note",
            "value": row.get("clinical_notes_summary") or "—",
            "source": _display_source("clinical", history),
        },
        {
            "field": "Denial code",
            "value": row.get("denial_reason_code")
            or row.get("canonical_denial_description")
            or "—",
            "source": _display_source("denial", history),
        },
        {
            "field": "Appeal req.",
            "value": json.dumps(row.get("appeal_requirements"))
            if row.get("appeal_requirements")
            else "—",
            "source": _display_source("payer", history),
        },
    ]
    checklist = []
    present_map = {
        "claim_id": bool(row.get("claim_id")),
        "patient_id": bool(row.get("patient_id")),
        "service_date": bool(row.get("service_date")),
        "diagnosis_codes": bool(diagnosis),
        "procedure_codes": bool(procedures),
        "clinical_notes_summary": bool(row.get("clinical_notes_summary")),
        "denial_reason_code": bool(row.get("denial_reason_code")),
        "payer_name": bool(row.get("payer_name")),
    }
    for rule in rules:
        if rule.get("rule_type") != "required_field":
            continue
        field = (rule.get("rule_config") or {}).get("field")
        if not field:
            continue
        checklist.append(
            {
                "label": field.replace("_", " ").title(),
                "present": bool(present_map.get(field)),
                "optional": False,
                "detail": row.get(field) if field in row else None,
            }
        )
    checklist.append(
        {
            "label": "Diagnosis codes",
            "present": bool(diagnosis),
            "optional": True,
            "detail": ", ".join(diagnosis) if diagnosis else None,
        }
    )
    checklist.append(
        {
            "label": "Prior imaging",
            "present": "missing_optional:prior_imaging_history" not in flags
            and bool(row.get("clinical_notes_summary")),
            "optional": True,
            "detail": None,
        }
    )
    payload = dict(row)
    payload.update(
        {
            "patient_initials": _patient_initials(row.get("patient_id")),
            "patient_full_name": _patient_full_name(row.get("patient_id")),
            "days_until_deadline": (row["payer_appeal_deadline"] - date.today()).days
            if row.get("payer_appeal_deadline")
            else None,
            "evidence": evidence,
            "checklist": checklist,
            "outcomes": outcomes,
            "workflow_rules": rules,
        }
    )
    return _jsonable(payload)


@serve_router.post("/case/{claim_id}/outcome")
def record_case_outcome(
    claim_id: str,
    body: OutcomeBody,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    if user.get("role") == "readonly":
        raise _forbidden()
    method = APPEAL_METHODS.get(body.appeal_method)
    if not method:
        raise HTTPException(status_code=400, detail="Invalid appeal method")
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT service_date, assembled_at FROM denial_contexts WHERE claim_id = %s", (claim_id,))
        case = cur.fetchone()
        if not case:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Case not found")
        hours = None
        filed_at = utcnow() if body.appeal_filed else None
        start = case.get("assembled_at") or case.get("service_date")
        if filed_at and start:
            start_dt = start if isinstance(start, datetime) else datetime.combine(start, datetime.min.time())
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
            hours = max(0, int((filed_at - start_dt).total_seconds() // 3600))
        cur.execute(
            """
            INSERT INTO denial_outcomes (
                claim_id, appeal_filed_at, appeal_method, appeal_outcome,
                time_to_resolution_hours, staff_minutes_saved, amount_recovered, agent_used
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, claim_id, appeal_filed_at, appeal_method, appeal_outcome,
                      time_to_resolution_hours, staff_minutes_saved, amount_recovered,
                      agent_used, created_at
            """,
            (
                claim_id,
                filed_at,
                method,
                body.appeal_outcome,
                hours,
                body.staff_minutes_saved,
                body.amount_recovered,
                body.agent_used or user.get("full_name"),
            ),
        )
        row = cur.fetchone()
    conn.commit()
    log_audit_event(
        request,
        action="recorded_outcome",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="denial_context",
        resource_id=claim_id,
        details={"outcome": body.appeal_outcome, "method": method},
    )
    return {"ok": True, "outcome": _jsonable(dict(row))}


@serve_router.get("/pipeline-health")
def pipeline_health(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        cur.execute(
            """
            SELECT DISTINCT ON (source)
                source,
                extractor_name,
                started_at,
                completed_at,
                status,
                records_read,
                records_inserted,
                error_message,
                EXTRACT(EPOCH FROM (completed_at - started_at)) AS run_duration_seconds
            FROM (
                SELECT
                    CASE
                        WHEN position(':' IN extractor_name) > 0
                            THEN split_part(extractor_name, ':', 1)
                        ELSE extractor_name
                    END AS source,
                    extractor_name,
                    started_at,
                    completed_at,
                    status,
                    records_read,
                    records_inserted,
                    error_message
                FROM extraction_log
                WHERE extractor_name NOT ILIKE '%eob%'
                  AND extractor_name NOT ILIKE '%bluebutton%'
                  AND extractor_name NOT ILIKE '%era%'
            ) runs
            ORDER BY source, completed_at DESC NULLS LAST
            """
        )
        sources = []
        for row in cur.fetchall():
            duration = row.get("run_duration_seconds")
            sources.append(
                {
                    "source": row["source"],
                    "extractor_name": row["extractor_name"],
                    "last_run_at": row["completed_at"].isoformat()
                    if row.get("completed_at")
                    else None,
                    "status": row["status"],
                    "records_extracted": int(row.get("records_read") or 0),
                    "records_inserted": int(row.get("records_inserted") or 0),
                    "error_message": row.get("error_message"),
                    "run_duration_seconds": max(0, int(duration)) if duration is not None else None,
                }
            )
        cur.execute(
            """
            SELECT COUNT(*) AS n FROM raw_fhir_responses
            WHERE COALESCE(resource_type, '') <> 'ExplanationOfBenefit'
            """
        )
        total_raw = int(cur.fetchone()["n"] or 0)
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (
                    WHERE validation_status IN ('clean', 'flagged')
                ) AS total_clean,
                COUNT(*) FILTER (
                    WHERE COALESCE(cardinality(data_quality_flags), 0) > 0
                ) AS total_flagged
            FROM prior_auth_contexts
            """
        )
        counts = cur.fetchone()
        cur.execute(
            """
            SELECT COUNT(*) AS n
            FROM quarantine_records
            WHERE COALESCE(workflow, %s) = %s
            """,
            (WORKFLOW_COMPLETENESS, WORKFLOW_COMPLETENESS),
        )
        total_quarantine = int(cur.fetchone()["n"] or 0)
        cur.execute(
            """
            SELECT
                DATE(completed_at AT TIME ZONE 'UTC') AS day,
                CASE
                    WHEN position(':' IN extractor_name) > 0
                        THEN split_part(extractor_name, ':', 1)
                    ELSE extractor_name
                END AS source,
                bool_or(status = 'success') AS any_success,
                bool_or(status = 'failed') AS any_failed
            FROM extraction_log
            WHERE completed_at >= NOW() - INTERVAL '7 days'
              AND extractor_name NOT ILIKE '%eob%'
              AND extractor_name NOT ILIKE '%bluebutton%'
              AND extractor_name NOT ILIKE '%era%'
            GROUP BY 1, 2
            ORDER BY 1
            """
        )
        timeline = [
            {
                "day": row["day"].isoformat(),
                "source": row["source"],
                "status": "failed"
                if row["any_failed"] and not row["any_success"]
                else "success"
                if row["any_success"]
                else "unknown",
            }
            for row in cur.fetchall()
        ]
        cur.execute(
            """
            SELECT MAX(completed_at) AS last_run_at
            FROM extraction_log
            WHERE extractor_name NOT ILIKE '%eob%'
              AND extractor_name NOT ILIKE '%bluebutton%'
              AND extractor_name NOT ILIKE '%era%'
            """
        )
        last_run = cur.fetchone()["last_run_at"]

    now = utcnow()
    last_dt = last_run.replace(tzinfo=timezone.utc) if last_run and last_run.tzinfo is None else last_run
    failed_24 = False
    success_24 = False
    for src in sources:
        if not src["last_run_at"]:
            continue
        ts = datetime.fromisoformat(src["last_run_at"])
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if (now - ts) <= timedelta(hours=24):
            if src["status"] == "failed":
                failed_24 = True
            if src["status"] == "success":
                success_24 = True

    if last_dt is None or (now - last_dt) > timedelta(hours=48):
        pipeline_status = "down"
    elif failed_24:
        pipeline_status = "degraded"
    elif success_24:
        pipeline_status = "healthy"
    else:
        pipeline_status = "stale"

    return {
        "pipeline_status": pipeline_status,
        "last_run_at": last_dt.isoformat() if last_dt else None,
        "hours_since_last_run": _relative_hours(last_dt),
        "sources": sources,
        "summary": {
            "total_raw": total_raw,
            "total_clean": int(counts["total_clean"] or 0),
            "total_quarantine": total_quarantine,
            "total_flagged": int(counts["total_flagged"] or 0),
        },
        "timeline": timeline,
    }


def _run_extractor_job(workflow: str = WORKFLOW_DEFAULT) -> None:
    extractors_dir = str(_ROOT / "extractors")
    transformers_dir = str(_ROOT / "transformers")
    for path in (extractors_dir, transformers_dir, str(_ROOT)):
        if path not in sys.path:
            sys.path.insert(0, path)
    from order_extractor import OrderExtractor  # type: ignore
    from completeness_transformer import CompletenessTransformer  # type: ignore

    extractor = OrderExtractor()
    try:
        extractor.run()
    finally:
        extractor.close()
    transformer = CompletenessTransformer()
    try:
        transformer.run()
    finally:
        transformer.close()


@serve_router.post("/manual-run")
def manual_run(
    body: ManualRunBody,
    request: Request,
    background: BackgroundTasks,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO extraction_log (
                extractor_name, started_at, status, records_read, records_inserted
            )
            VALUES (%s, NOW(), 'running', 0, 0)
            RETURNING id, started_at
            """,
            (f"manual:{body.source or 'all'}",),
        )
        row = cur.fetchone()
    conn.commit()
    workflow = WORKFLOW_COMPLETENESS
    try:
        background.add_task(_run_extractor_job, workflow)
    except Exception:
        threading.Thread(target=_run_extractor_job, args=(workflow,), daemon=True).start()
    log_audit_event(
        request,
        action="manual_run_triggered",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="pipeline",
        resource_id=str(row["id"]),
        details={"workflow": body.workflow, "source": body.source},
    )
    return {
        "run_id": str(row["id"]),
        "triggered_at": row["started_at"].isoformat(),
        "status": "triggered",
    }


@serve_router.get("/outcomes")
def get_outcomes(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    workflow: str = WORKFLOW_DEFAULT,
    date_from: date | None = None,
    date_to: date | None = None,
    payer_name: str | None = None,
) -> dict[str, Any]:
    del workflow
    if date_to is None:
        date_to = date.today()
    if date_from is None:
        date_from = date_to - timedelta(days=30)
    clauses = ["o.created_at::date BETWEEN %s AND %s"]
    params: list[Any] = [date_from, date_to]
    if payer_name:
        clauses.append("dc.payer_name = %s")
        params.append(payer_name)
    where_sql = " AND ".join(clauses)
    with _cursor(request) as cur:
        cur.execute(
            f"""
            SELECT
                COUNT(*) AS total_worked,
                COUNT(*) FILTER (WHERE o.appeal_filed_at IS NOT NULL) AS appeals_filed,
                COUNT(*) FILTER (WHERE o.appeal_outcome = 'approved') AS approved,
                COUNT(*) FILTER (WHERE o.appeal_outcome = 'denied') AS denied,
                COUNT(*) FILTER (WHERE o.appeal_outcome = 'pending') AS pending,
                AVG(o.time_to_resolution_hours) AS avg_time_to_resolution_hours,
                COALESCE(SUM(o.amount_recovered), 0) AS total_amount_recovered,
                AVG(o.staff_minutes_saved) AS avg_staff_minutes_saved,
                COALESCE(SUM(o.staff_minutes_saved), 0) AS total_staff_minutes_saved
            FROM denial_outcomes o
            LEFT JOIN denial_contexts dc ON dc.claim_id = o.claim_id
            WHERE {where_sql}
            """,
            params,
        )
        summary = dict(cur.fetchone() or {})
        cur.execute(
            f"""
            SELECT COALESCE(dc.payer_name, 'Unknown') AS payer_name,
                   COUNT(*) FILTER (WHERE o.appeal_outcome = 'approved') AS approved,
                   COUNT(*) FILTER (WHERE o.appeal_outcome = 'denied') AS denied,
                   COUNT(*) FILTER (WHERE o.appeal_outcome = 'pending') AS pending
            FROM denial_outcomes o
            LEFT JOIN denial_contexts dc ON dc.claim_id = o.claim_id
            WHERE {where_sql}
            GROUP BY 1
            ORDER BY COUNT(*) DESC
            """,
            params,
        )
        by_payer = [_jsonable(dict(row)) for row in cur.fetchall()]
        cur.execute(
            """
            SELECT d::date AS day, COUNT(o.id) AS worked
            FROM generate_series(%s::date, %s::date, interval '1 day') AS d
            LEFT JOIN denial_outcomes o
              ON o.created_at::date = d::date
            GROUP BY 1
            ORDER BY 1
            """,
            (date_from, date_to),
        )
        series = [
            {"day": row["day"].isoformat(), "worked": int(row["worked"] or 0)}
            for row in cur.fetchall()
        ]
        cur.execute(
            f"""
            SELECT o.claim_id, dc.payer_name, dc.procedure_codes,
                   o.appeal_filed_at, o.appeal_outcome, o.appeal_method,
                   o.time_to_resolution_hours, o.amount_recovered, o.agent_used,
                   o.created_at
            FROM denial_outcomes o
            LEFT JOIN denial_contexts dc ON dc.claim_id = o.claim_id
            WHERE {where_sql}
            ORDER BY o.created_at DESC
            LIMIT 200
            """,
            params,
        )
        rows = []
        for row in cur.fetchall():
            procedures = row.get("procedure_codes") or []
            rows.append(
                {
                    "claim_id": row["claim_id"],
                    "payer_name": row.get("payer_name"),
                    "procedure_code": procedures[0] if procedures else None,
                    "filed": row["appeal_filed_at"].isoformat() if row.get("appeal_filed_at") else None,
                    "outcome": row.get("appeal_outcome"),
                    "method": row.get("appeal_method"),
                    "days_to_resolve": round((row["time_to_resolution_hours"] or 0) / 24, 1)
                    if row.get("time_to_resolution_hours") is not None
                    else None,
                    "amount_recovered": float(row["amount_recovered"] or 0),
                    "agent_used": row.get("agent_used"),
                    "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
                }
            )
    total_worked = int(summary.get("total_worked") or 0)
    approved = int(summary.get("approved") or 0)
    appeals_filed = int(summary.get("appeals_filed") or 0)
    minutes = float(summary.get("total_staff_minutes_saved") or 0)
    return {
        "date_from": date_from.isoformat(),
        "date_to": date_to.isoformat(),
        "totals": {
            "total_worked": total_worked,
            "appeals_filed": appeals_filed,
            "approved": approved,
            "denied": int(summary.get("denied") or 0),
            "pending": int(summary.get("pending") or 0),
            "avg_time_to_resolution_hours": float(summary["avg_time_to_resolution_hours"])
            if summary.get("avg_time_to_resolution_hours") is not None
            else None,
            "total_amount_recovered": float(summary.get("total_amount_recovered") or 0),
            "avg_staff_minutes_saved": float(summary["avg_staff_minutes_saved"])
            if summary.get("avg_staff_minutes_saved") is not None
            else None,
            "approval_rate_pct": round((approved / appeals_filed) * 100, 1)
            if appeals_filed
            else 0,
            "estimated_hours_saved_total": round(minutes / 60, 1),
        },
        "by_payer": by_payer,
        "series": series,
        "rows": rows,
    }


@serve_router.get("/vendors")
def list_vendors(
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> list[dict[str, Any]]:
    with _cursor(request) as cur:
        cur.execute(
            """
            SELECT id, vendor_name, vendor_type, api_key_prefix, workflows,
                   is_active, last_query_at, total_queries, created_at
            FROM portal_vendor_connections
            WHERE client_id = %s
            ORDER BY created_at DESC
            """,
            (user.get("client_id") or "demo-practice",),
        )
        rows = cur.fetchall()
    return [_jsonable(dict(row)) for row in rows]


@serve_router.post("/vendors")
def create_vendor(
    body: VendorBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    raw_key = "kal_" + secrets.token_urlsafe(32)
    prefix = raw_key[:12]
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO portal_vendor_connections (
                client_id, vendor_name, vendor_type, api_key_hash, api_key_prefix,
                workflows, created_by
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id, vendor_name
            """,
            (
                user.get("client_id") or "demo-practice",
                body.vendor_name.strip(),
                body.vendor_type or "other",
                hash_token(raw_key),
                prefix,
                body.workflows or [WORKFLOW_DEFAULT],
                str(user["id"]),
            ),
        )
        row = cur.fetchone()
    conn.commit()
    log_audit_event(
        request,
        action="generated_vendor_api_key",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="vendor",
        resource_id=str(row["id"]),
        details={"vendor_name": body.vendor_name},
    )
    return {
        "vendor_id": str(row["id"]),
        "vendor_name": row["vendor_name"],
        "api_key": raw_key,
        "warning": "Save this key now. It will not be shown again.",
    }


@serve_router.delete("/vendors/{vendor_id}")
def revoke_vendor(
    vendor_id: UUID,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            UPDATE portal_vendor_connections
            SET is_active = FALSE
            WHERE id = %s AND client_id = %s
            RETURNING id
            """,
            (str(vendor_id), user.get("client_id") or "demo-practice"),
        )
        row = cur.fetchone()
    if not row:
        conn.rollback()
        raise HTTPException(status_code=404, detail="Vendor not found")
    conn.commit()
    log_audit_event(
        request,
        action="revoked_vendor_api_key",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="vendor",
        resource_id=str(vendor_id),
    )
    return {"ok": True}


@serve_router.get("/query-log")
def query_log(
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
    vendor_id: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    clauses = ["resource_type = 'mcp_query'"]
    params: list[Any] = []
    if vendor_id:
        clauses.append("resource_id = %s")
        params.append(vendor_id)
    if date_from:
        clauses.append("created_at::date >= %s")
        params.append(date_from)
    if date_to:
        clauses.append("created_at::date <= %s")
        params.append(date_to)
    params.append(limit)
    with _cursor(request) as cur:
        cur.execute(
            f"""
            SELECT id, user_email, action, resource_id, details, success,
                   error_message, created_at
            FROM portal_audit_log
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC
            LIMIT %s
            """,
            params,
        )
        rows = cur.fetchall()
    out = []
    for row in rows:
        details = row.get("details") or {}
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {}
        sanitized = {
            key: value
            for key, value in details.items()
            if key not in {"patient_name", "patient_full_name", "clinical_notes_summary"}
        }
        out.append(
            {
                "id": row["id"],
                "vendor_name": sanitized.get("vendor_name") or row.get("user_email"),
                "tool_called": sanitized.get("tool_called") or row.get("action"),
                "input_params": sanitized.get("input_params") or {},
                "response_row_count": sanitized.get("response_row_count"),
                "duration_ms": sanitized.get("duration_ms"),
                "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
                "success": bool(row.get("success")),
            }
        )
    return out


@audit_router.post("/log")
def frontend_audit_log(
    body: AuditBody,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, bool]:
    details = dict(body.details or {})
    details.pop("patient_name", None)
    details.pop("patient_full_name", None)
    log_audit_event(
        request,
        action=body.action,
        success=body.success,
        user_id=user["id"],
        user_email=user["email"],
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        details=details,
        error_message=body.error_message,
    )
    return {"ok": True}
