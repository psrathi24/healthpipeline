"""Prior-auth completeness APIs — auth rules, LCD/NCD lookup, policy drafts."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field

from .auth_router import get_current_user, log_audit_event
from .clean_router import require_staff
from .serve_router import _jsonable, require_admin
from .workflows import WORKFLOW_COMPLETENESS

completeness_router = APIRouter(tags=["completeness"])

CRITERION_HINTS = {
    "conservative": "criterion:conservative_therapy",
    "physical therapy": "criterion:conservative_therapy",
    "nsaid": "criterion:conservative_therapy",
    "neurolog": "criterion:neuro_exam",
    "six week": "criterion:failed_conservative_duration",
    "6 week": "criterion:failed_conservative_duration",
    "specialist": "criterion:specialist_note",
    "mri": "criterion:recent_imaging",
}


class AuthRequiredBody(BaseModel):
    payer_name: str | None = None
    procedure_code: str = Field(min_length=3, max_length=12)
    place_of_service: str | None = None
    auth_required: bool = True
    source: str = "manual"
    notes: str | None = None
    active: bool = True


class PolicyDraftBody(BaseModel):
    payer_name: str | None = None
    procedure_code: str | None = None
    text: str = Field(min_length=20, max_length=200000)
    filename: str | None = None


class PolicyReviewBody(BaseModel):
    status: str = Field(pattern="^(accepted|dismissed)$")


def _db(request: Request):
    return request.app.state.db


def _cursor(request: Request):
    return _db(request).cursor(cursor_factory=RealDictCursor)


def suggest_criteria(text: str) -> list[dict[str, Any]]:
    lines = [line.strip(" -\t") for line in text.splitlines() if line.strip()]
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in lines:
        if len(line) < 8 or len(line) > 240:
            continue
        source = None
        lowered = line.lower()
        for needle, field in CRITERION_HINTS.items():
            if needle in lowered:
                source = field
                break
        key = source or line.lower()
        if key in seen:
            continue
        seen.add(key)
        items.append(
            {
                "label": line[:160],
                "description": "Drafted from uploaded payer policy. Confirm before activating.",
                "field_source": source,
                "required": source is not None,
            }
        )
        if len(items) >= 12:
            break
    if not items:
        items.append(
            {
                "label": "Review policy manually",
                "description": "No structured bullets were detected in the uploaded text.",
                "field_source": None,
                "required": False,
            }
        )
    return items


@completeness_router.get("/auth-required")
def list_auth_required(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    payer_name: str | None = None,
    procedure_code: str | None = None,
) -> dict[str, Any]:
    clauses = ["active = TRUE"]
    params: list[Any] = []
    if payer_name:
        clauses.append("lower(payer_name) = lower(%s)")
        params.append(payer_name)
    if procedure_code:
        clauses.append("procedure_code = %s")
        params.append(procedure_code)
    with _cursor(request) as cur:
        cur.execute(
            f"""
            SELECT id, client_id, payer_name, procedure_code, place_of_service,
                   auth_required, source, notes, active, updated_at
            FROM auth_required_rules
            WHERE {' AND '.join(clauses)}
            ORDER BY payer_name NULLS LAST, procedure_code
            LIMIT 500
            """,
            params,
        )
        rows = cur.fetchall()
    return {"items": [_jsonable(dict(row)) for row in rows]}


@completeness_router.post("/auth-required")
def upsert_auth_required(
    body: AuthRequiredBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    client_id = user.get("client_id")
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id FROM auth_required_rules
            WHERE COALESCE(client_id, '') = COALESCE(%s, '')
              AND COALESCE(payer_name, '') = COALESCE(%s, '')
              AND procedure_code = %s
              AND COALESCE(place_of_service, '') = COALESCE(%s, '')
            LIMIT 1
            """,
            (client_id, body.payer_name, body.procedure_code.strip(), body.place_of_service),
        )
        existing = cur.fetchone()
        if existing:
            cur.execute(
                """
                UPDATE auth_required_rules
                SET auth_required = %s, source = %s, notes = %s, active = %s, updated_at = NOW()
                WHERE id = %s
                RETURNING *
                """,
                (body.auth_required, body.source, body.notes, body.active, existing["id"]),
            )
        else:
            cur.execute(
                """
                INSERT INTO auth_required_rules (
                    client_id, payer_name, procedure_code, place_of_service,
                    auth_required, source, notes, active, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                RETURNING *
                """,
                (
                    client_id,
                    body.payer_name,
                    body.procedure_code.strip(),
                    body.place_of_service,
                    body.auth_required,
                    body.source,
                    body.notes,
                    body.active,
                ),
            )
        row = cur.fetchone()
    conn.commit()
    log_audit_event(
        request,
        action="auth_required_rule_saved",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="auth_required_rule",
        resource_id=str(row["id"]),
        details={"procedure_code": body.procedure_code, "auth_required": body.auth_required},
    )
    return _jsonable(dict(row))


@completeness_router.get("/coverage-policies")
def list_coverage_policies(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    procedure_code: str | None = None,
) -> dict[str, Any]:
    params: list[Any] = []
    where = "active = TRUE"
    if procedure_code:
        where += " AND procedure_code = %s"
        params.append(procedure_code)
    with _cursor(request) as cur:
        cur.execute(
            f"""
            SELECT id, source, payer_name, procedure_code, jurisdiction, citation,
                   title, auth_required, criteria, url
            FROM coverage_policies
            WHERE {where}
            ORDER BY procedure_code, source
            """,
            params,
        )
        rows = cur.fetchall()
    return {"items": [_jsonable(dict(row)) for row in rows]}


@completeness_router.post("/policy-drafts")
def create_policy_draft(
    body: PolicyDraftBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    suggested = suggest_criteria(body.text)
    with _cursor(request) as cur:
        cur.execute(
            """
            INSERT INTO policy_drafts (
                client_id, payer_name, procedure_code, source_filename,
                raw_text, suggested_items, status
            )
            VALUES (%s, %s, %s, %s, %s, %s::jsonb, 'pending')
            RETURNING id, payer_name, procedure_code, suggested_items, status, created_at
            """,
            (
                user.get("client_id"),
                body.payer_name,
                body.procedure_code,
                body.filename,
                body.text,
                json.dumps(suggested),
            ),
        )
        row = cur.fetchone()
    request.app.state.db.commit()
    log_audit_event(
        request,
        action="policy_draft_created",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="policy_draft",
        resource_id=str(row["id"]),
        details={"item_count": len(suggested)},
    )
    return _jsonable(dict(row))


@completeness_router.get("/policy-drafts")
def list_policy_drafts(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    status: str | None = Query(None),
) -> dict[str, Any]:
    clauses = ["1=1"]
    params: list[Any] = []
    if status:
        clauses.append("status = %s")
        params.append(status)
    with _cursor(request) as cur:
        cur.execute(
            f"""
            SELECT id, payer_name, procedure_code, source_filename, suggested_items,
                   status, created_at, template_id
            FROM policy_drafts
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC
            LIMIT 100
            """,
            params,
        )
        rows = cur.fetchall()
    return {"items": [_jsonable(dict(row)) for row in rows]}


@completeness_router.post("/policy-drafts/{draft_id}/review")
def review_policy_draft(
    draft_id: UUID,
    body: PolicyReviewBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM policy_drafts WHERE id = %s", (str(draft_id),))
        draft = cur.fetchone()
        if not draft:
            raise HTTPException(status_code=404, detail="Policy draft not found")
        template_id = draft.get("template_id")
        if body.status == "accepted":
            cur.execute(
                """
                INSERT INTO package_requirement_templates
                    (client_id, workflow, payer_name, procedure_code, source, created_by)
                VALUES (%s, %s, %s, %s, 'policy_draft', %s)
                RETURNING id
                """,
                (
                    user.get("client_id"),
                    WORKFLOW_COMPLETENESS,
                    draft.get("payer_name"),
                    draft.get("procedure_code"),
                    str(user["id"]),
                ),
            )
            template_id = cur.fetchone()["id"]
            items = draft.get("suggested_items") or []
            if isinstance(items, str):
                items = json.loads(items)
            for index, item in enumerate(items):
                cur.execute(
                    """
                    INSERT INTO package_checklist_items
                        (template_id, label, description, field_source, required, sort_order)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(template_id),
                        item.get("label") or f"Criterion {index + 1}",
                        item.get("description"),
                        item.get("field_source"),
                        bool(item.get("required")),
                        index,
                    ),
                )
        cur.execute(
            """
            UPDATE policy_drafts
            SET status = %s, reviewed_at = NOW(), reviewed_by = %s, template_id = %s
            WHERE id = %s
            RETURNING *
            """,
            (body.status, str(user["id"]), str(template_id) if template_id else None, str(draft_id)),
        )
        row = cur.fetchone()
    conn.commit()
    log_audit_event(
        request,
        action="policy_draft_reviewed",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="policy_draft",
        resource_id=str(draft_id),
        details={"status": body.status, "template_id": str(template_id) if template_id else None},
    )
    return _jsonable(dict(row))
