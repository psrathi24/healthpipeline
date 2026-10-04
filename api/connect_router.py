"""
Provider portal Connect API — data sources, onboarding, file uploads.

Verification checklist (manual):
□ Onboarding checklist matches DB flags
□ Connector status dots match last_test_success and last run time
□ Sensitive fields never returned after save
□ Private key PEM validation rejects invalid keys
□ Connection test returns error_type, not raw upstream errors
□ Disconnect soft-deletes (active=false) and retains extraction data
□ BAA acknowledgment requires admin and is audited
□ Credential operations log no secret values
"""

from __future__ import annotations

import json
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from psycopg2 import IntegrityError
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field

from .auth_router import get_current_user, log_audit_event
from .auth_security import encrypt_secret, load_public_key, utcnow
from .serve_router import FORBIDDEN, WORKFLOW_DEFAULT, _forbidden, _jsonable, require_admin
from .workflows import is_completeness

connect_router = APIRouter(tags=["connect"])

_ROOT = Path(__file__).resolve().parent.parent
UPLOAD_ROOT = _ROOT / "uploads"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
PEM_RE = re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")

CATALOG: list[dict[str, Any]] = [
    {
        "connector_type": "epic_fhir",
        "display_name": "Epic (FHIR R4)",
        "category": "ehr",
        "description": "Connect your Epic EHR instance via FHIR Backend Services API. Requires your IT team to register the app in Epic's developer portal.",
        "auth_method": "smart_backend_services",
        "fhir_resources": ["ExplanationOfBenefit", "Claim", "Patient", "Coverage", "DocumentReference", "ServiceRequest"],
        "workflows_supported": ["prior_auth_completeness", "prior_auth_denial", "eligibility_verification", "remittance_processing"],
        "setup_complexity": "complex",
        "it_required": True,
        "documentation_url": "https://fhir.epic.com/",
        "required_fields": ["epic_client_id", "epic_fhir_base_url", "epic_token_url", "private_key_pem"],
    },
    {
        "connector_type": "athena_fhir",
        "display_name": "athenahealth (FHIR R4)",
        "category": "ehr",
        "description": "Connect athenaOne via FHIR. Your IT team registers the app in the athenahealth developer portal.",
        "auth_method": "oauth2",
        "fhir_resources": ["ExplanationOfBenefit", "Claim", "Patient", "Coverage", "ServiceRequest"],
        "workflows_supported": ["prior_auth_completeness", "prior_auth_denial", "eligibility_verification"],
        "setup_complexity": "moderate",
        "it_required": True,
        "documentation_url": "https://docs.athenahealth.com/",
        "required_fields": ["athena_client_id", "athena_client_secret", "athena_practice_id", "athena_fhir_base_url"],
    },
    {
        "connector_type": "cerner_fhir",
        "display_name": "Oracle Health / Cerner (FHIR R4)",
        "category": "ehr",
        "description": "Connect Oracle Health (Cerner) via SMART Backend Services.",
        "auth_method": "smart_backend_services",
        "fhir_resources": ["ExplanationOfBenefit", "Claim", "Patient", "Coverage", "DocumentReference", "ServiceRequest"],
        "workflows_supported": ["prior_auth_completeness", "prior_auth_denial", "eligibility_verification"],
        "setup_complexity": "complex",
        "it_required": True,
        "documentation_url": "https://fhir.cerner.com/",
        "required_fields": ["cerner_client_id", "cerner_fhir_base_url", "private_key_pem"],
    },
    {
        "connector_type": "ecw_fhir",
        "display_name": "eClinicalWorks (FHIR R4)",
        "category": "ehr",
        "description": "Connect eClinicalWorks via FHIR R4.",
        "auth_method": "oauth2",
        "fhir_resources": ["ExplanationOfBenefit", "Claim", "Patient", "Coverage", "ServiceRequest"],
        "workflows_supported": ["prior_auth_completeness", "prior_auth_denial"],
        "setup_complexity": "moderate",
        "it_required": True,
        "documentation_url": "https://fhir.eclinicalworks.com/",
        "required_fields": ["ecw_client_id", "ecw_client_secret", "ecw_fhir_base_url"],
    },
    {
        "connector_type": "cms_bluebutton",
        "display_name": "CMS Blue Button 2.0",
        "category": "payer",
        "description": "Medicare beneficiary claims via Blue Button 2.0. Sandbox available for testing.",
        "auth_method": "oauth2",
        "fhir_resources": ["ExplanationOfBenefit", "Patient", "Coverage"],
        "workflows_supported": ["prior_auth_denial", "remittance_processing"],
        "setup_complexity": "moderate",
        "it_required": True,
        "documentation_url": "https://bluebutton.cms.gov/",
        "required_fields": ["bb_client_id", "bb_client_secret"],
    },
    {
        "connector_type": "hapi_fhir",
        "display_name": "HAPI FHIR (sandbox)",
        "category": "ehr",
        "description": "Public HAPI FHIR R4 sandbox. No credentials required. Use this to validate the pipeline before connecting a production EHR.",
        "auth_method": "none",
        "fhir_resources": ["ExplanationOfBenefit", "Claim", "Patient", "Coverage", "ServiceRequest", "DocumentReference"],
        "workflows_supported": ["prior_auth_completeness", "prior_auth_denial"],
        "setup_complexity": "simple",
        "it_required": False,
        "documentation_url": "https://hapi.fhir.org/",
        "required_fields": ["base_url"],
    },
    {
        "connector_type": "payer_fhir_generic",
        "display_name": "Generic payer FHIR",
        "category": "payer",
        "description": "Connect a payer FHIR endpoint for prior authorization and denial detail. Most payers will have mandated APIs by 2027.",
        "auth_method": "oauth2",
        "fhir_resources": ["ExplanationOfBenefit", "Claim", "Coverage"],
        "workflows_supported": ["prior_auth_completeness", "prior_auth_denial", "eligibility_verification"],
        "setup_complexity": "moderate",
        "it_required": True,
        "documentation_url": "https://hl7.org/fhir/",
        "required_fields": ["client_id", "client_secret", "fhir_base_url", "token_url"],
    },
    {
        "connector_type": "payer_crd",
        "display_name": "Payer CRD (Coverage Requirements Discovery stub)",
        "category": "payer",
        "description": "Stub for Da Vinci CRD. Connecting this records that a Coverage Requirements Discovery endpoint is configured; live CRD questionnaire fetch is Phase 3. Completeness still uses local auth rules and LCD/NCD samples until the payer API answers.",
        "auth_method": "oauth2",
        "fhir_resources": ["Coverage", "Questionnaire"],
        "workflows_supported": ["prior_auth_completeness"],
        "setup_complexity": "moderate",
        "it_required": True,
        "documentation_url": "https://hl7.org/fhir/us/davinci-crd/",
        "required_fields": ["client_id", "client_secret", "fhir_base_url", "token_url"],
    },
    {
        "connector_type": "availity_eligibility",
        "display_name": "Availity Eligibility",
        "category": "clearinghouse",
        "description": "Real-time eligibility and benefits via Availity.",
        "auth_method": "oauth2",
        "fhir_resources": [],
        "workflows_supported": ["eligibility_verification"],
        "setup_complexity": "moderate",
        "it_required": True,
        "documentation_url": "https://developer.availity.com/",
        "required_fields": ["availity_client_id", "availity_client_secret", "availity_org_id"],
    },
    {
        "connector_type": "optum_eligibility",
        "display_name": "Optum Eligibility",
        "category": "clearinghouse",
        "description": "Eligibility verification through Optum APIs.",
        "auth_method": "api_key",
        "fhir_resources": [],
        "workflows_supported": ["eligibility_verification"],
        "setup_complexity": "moderate",
        "it_required": True,
        "documentation_url": "https://developer.optum.com/",
        "required_fields": ["optum_client_id", "optum_client_secret"],
    },
    {
        "connector_type": "change_healthcare_era",
        "display_name": "Change Healthcare ERA",
        "category": "clearinghouse",
        "description": "ERA 835 remittance data — denial reason codes and payment detail.",
        "auth_method": "oauth2",
        "fhir_resources": [],
        "workflows_supported": ["remittance_processing", "prior_auth_denial"],
        "setup_complexity": "moderate",
        "it_required": True,
        "documentation_url": "https://developers.changehealthcare.com/",
        "required_fields": ["chc_client_id", "chc_client_secret", "submitter_id"],
    },
    {
        "connector_type": "availity_era",
        "display_name": "Availity ERA",
        "category": "clearinghouse",
        "description": "ERA 835 remittance files via Availity.",
        "auth_method": "oauth2",
        "fhir_resources": [],
        "workflows_supported": ["remittance_processing", "prior_auth_denial"],
        "setup_complexity": "moderate",
        "it_required": True,
        "documentation_url": "https://developer.availity.com/",
        "required_fields": ["availity_client_id", "availity_client_secret", "availity_org_id"],
    },
    {
        "connector_type": "file_upload_era",
        "display_name": "Manual ERA 835 upload",
        "category": "file",
        "description": "Upload ERA 835 files manually. Supported formats: X12 835, CSV remittance.",
        "auth_method": "file_upload",
        "fhir_resources": [],
        "workflows_supported": ["prior_auth_denial", "remittance_processing"],
        "setup_complexity": "simple",
        "it_required": False,
        "documentation_url": None,
        "required_fields": [],
    },
    {
        "connector_type": "file_upload_fhir",
        "display_name": "Manual FHIR bundle upload",
        "category": "file",
        "description": "Upload FHIR JSON bundles. Supports R4 ServiceRequest, Claim, EOB, and Patient resources.",
        "auth_method": "file_upload",
        "fhir_resources": ["ExplanationOfBenefit", "Claim", "Patient", "ServiceRequest"],
        "workflows_supported": ["prior_auth_completeness", "prior_auth_denial"],
        "setup_complexity": "simple",
        "it_required": False,
        "documentation_url": None,
        "required_fields": [],
    },
    {
        "connector_type": "file_upload_custom",
        "display_name": "Custom file upload",
        "category": "file",
        "description": "Upload CSV order extracts or payer policy text when a payer has no API connection.",
        "auth_method": "file_upload",
        "fhir_resources": [],
        "workflows_supported": ["prior_auth_completeness", "prior_auth_denial"],
        "setup_complexity": "simple",
        "it_required": False,
        "documentation_url": None,
        "required_fields": [],
    },
]

CATALOG_BY_TYPE = {item["connector_type"]: item for item in CATALOG}
EXTRACTOR_MATCH = {
    "epic_fhir": "%epic%",
    "hapi_fhir": "%hapi%",
    "cms_bluebutton": "%bluebutton%",
    "athena_fhir": "%athena%",
    "cerner_fhir": "%cerner%",
}


class ConnectionCreateBody(BaseModel):
    connector_type: str
    display_name: str = Field(min_length=1, max_length=160)
    credentials: dict[str, Any] = Field(default_factory=dict)
    workflows: list[str] = Field(default_factory=lambda: [WORKFLOW_DEFAULT])
    custom_instructions: str | None = None
    notify_on_failure: bool = False
    notify_email: str | None = None


class ConnectionPatchBody(BaseModel):
    display_name: str | None = None
    workflows: list[str] | None = None
    custom_instructions: str | None = None
    notify_on_failure: bool | None = None
    notify_email: str | None = None


class RotateBody(BaseModel):
    credentials: dict[str, Any]


class DisconnectBody(BaseModel):
    confirm: bool
    reason: str = Field(min_length=3, max_length=2000)


class DraftTestBody(BaseModel):
    connector_type: str
    credentials: dict[str, Any] = Field(default_factory=dict)


def _db(request: Request):
    return request.app.state.db


def _cursor(request: Request):
    return _db(request).cursor(cursor_factory=RealDictCursor)


def require_connect_view(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if user.get("role") not in {"admin", "billing"}:
        raise _forbidden()
    return user


def _client_id(user: dict[str, Any]) -> str:
    return user.get("client_id") or "demo-practice"


def _catalog(connector_type: str) -> dict[str, Any]:
    item = CATALOG_BY_TYPE.get(connector_type)
    if not item:
        raise HTTPException(status_code=400, detail="Unknown connector type")
    return item


def _validate_credentials(connector_type: str, credentials: dict[str, Any]) -> None:
    spec = _catalog(connector_type)
    creds = credentials or {}
    for field in spec["required_fields"]:
        value = creds.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        if field.endswith("_url") or field in {"base_url", "fhir_base_url", "epic_fhir_base_url", "epic_token_url"}:
            if not str(value).startswith("https://"):
                raise HTTPException(status_code=400, detail=f"{field} must be an https URL")
        if field == "private_key_pem" and not PEM_RE.search(str(value)):
            raise HTTPException(status_code=400, detail="Private key must be PEM formatted")


def _fhir_base(connector_type: str, credentials: dict[str, Any]) -> str | None:
    keys = [
        "epic_fhir_base_url",
        "athena_fhir_base_url",
        "cerner_fhir_base_url",
        "ecw_fhir_base_url",
        "fhir_base_url",
        "base_url",
    ]
    for key in keys:
        if credentials.get(key):
            return str(credentials[key]).rstrip("/")
    if connector_type == "hapi_fhir":
        return "https://hapi.fhir.org/baseR4"
    return None


def _friendly_http_error(code: int, connector_type: str) -> dict[str, Any]:
    if code in {401, 403}:
        return {
            "success": False,
            "error_type": "auth_failed" if code == 401 else "scope_denied",
            "error_message": "The FHIR server rejected this connection.",
            "error_detail": (
                "The client ID or private key was rejected. Check that the client ID matches your app registration "
                "and that the public key on file matches the private key entered here."
                if code == 401
                else "Authentication succeeded but required FHIR resources were not granted. Confirm Incoming APIs "
                "include ExplanationOfBenefit.read, Claim.read, Patient.read, and Coverage.read."
            ),
        }
    if code == 404:
        return {
            "success": False,
            "error_type": "fhir_version_mismatch",
            "error_message": "No FHIR metadata document was found at this URL.",
            "error_detail": "Confirm the FHIR base URL points at an R4 server CapabilityStatement (/metadata).",
        }
    return {
        "success": False,
        "error_type": "network_error",
        "error_message": "Could not complete the FHIR handshake.",
        "error_detail": "Verify the FHIR base URL and that outbound HTTPS is allowed from this environment.",
    }


def run_connection_test(connector_type: str, credentials: dict[str, Any]) -> dict[str, Any]:
    spec = _catalog(connector_type)
    started = time.perf_counter()
    tested_at = utcnow().isoformat()
    if spec["auth_method"] in {"file_upload", "none"} and connector_type.startswith("file_upload"):
        UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
        probe = UPLOAD_ROOT / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return {
            "success": True,
            "tested_at": tested_at,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "fhir_version": None,
            "resources_available": None,
            "error_type": None,
            "error_message": None,
            "error_detail": None,
            "warnings": [],
        }
    base = _fhir_base(connector_type, credentials)
    if not base:
        latency = int((time.perf_counter() - started) * 1000)
        return {
            "success": True,
            "tested_at": tested_at,
            "latency_ms": latency,
            "fhir_version": None,
            "resources_available": None,
            "error_type": None,
            "error_message": None,
            "error_detail": None,
            "warnings": ["Credential format validated. Live ping is not available for this connector yet."],
        }
    url = f"{base}/metadata"
    try:
        request = UrlRequest(url, headers={"Accept": "application/fhir+json, application/json"})
        with urlopen(request, timeout=30) as response:
            raw = response.read()
        payload = json.loads(raw.decode("utf-8"))
        fhir_version = str(payload.get("fhirVersion") or payload.get("fhir_version") or "")
        resources: list[str] = []
        for rest in payload.get("rest") or []:
            for resource in rest.get("resource") or []:
                if resource.get("type"):
                    resources.append(str(resource["type"]))
        expected = spec.get("fhir_resources") or []
        missing = [name for name in expected if name not in resources]
        warnings = [f"Resource not advertised in CapabilityStatement: {name}" for name in missing]
        if fhir_version and not fhir_version.startswith("4"):
            return {
                "success": False,
                "tested_at": tested_at,
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "fhir_version": fhir_version,
                "resources_available": resources[:40],
                "error_type": "fhir_version_mismatch",
                "error_message": f"Server reported FHIR {fhir_version}; Kalamon requires R4.",
                "error_detail": "Point the FHIR base URL at an R4 endpoint.",
                "warnings": warnings,
            }
        return {
            "success": True,
            "tested_at": tested_at,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "fhir_version": fhir_version or "R4",
            "resources_available": resources[:40],
            "error_type": None,
            "error_message": None,
            "error_detail": None,
            "warnings": warnings,
        }
    except HTTPError as exc:
        mapped = _friendly_http_error(exc.code, connector_type)
        mapped.update(
            {
                "tested_at": tested_at,
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "fhir_version": None,
                "resources_available": None,
                "warnings": [],
            }
        )
        return mapped
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
        return {
            "success": False,
            "tested_at": tested_at,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "fhir_version": None,
            "resources_available": None,
            "error_type": "network_error",
            "error_message": "Could not reach the FHIR endpoint.",
            "error_detail": "Verify the FHIR base URL is correct and that outbound HTTPS to this host is allowed.",
            "warnings": [],
        }


def _public_connection(row: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(row)
    payload.pop("encrypted_credentials", None)
    payload["has_credentials"] = bool(row.get("encrypted_credentials"))
    if extra:
        payload.update(extra)
    return _jsonable(payload)


def _decrypt_creds(row: dict[str, Any]) -> dict[str, Any]:
    blob = row.get("encrypted_credentials")
    if not blob:
        return {}
    from .auth_security import decrypt_secret

    try:
        return json.loads(decrypt_secret(blob))
    except Exception:
        return {}


def _ensure_client(cur, client_id: str) -> None:
    cur.execute(
        """
        INSERT INTO portal_clients (id, practice_name)
        VALUES (%s, %s)
        ON CONFLICT (id) DO NOTHING
        """,
        (client_id, "Practice"),
    )


def _extractor_pattern(connector_type: str) -> str:
    return EXTRACTOR_MATCH.get(connector_type, f"%{connector_type}%")


def _run_stats(cur, connector_type: str) -> dict[str, Any]:
    cur.execute(
        """
        SELECT completed_at, status, records_inserted, error_message
        FROM extraction_log
        WHERE extractor_name ILIKE %s
        ORDER BY completed_at DESC NULLS LAST
        LIMIT 1
        """,
        (_extractor_pattern(connector_type),),
    )
    last = cur.fetchone()
    cur.execute(
        """
        SELECT COUNT(*) FILTER (WHERE status = 'success') AS ok,
               COUNT(*) AS n,
               COALESCE(AVG(records_inserted) FILTER (WHERE status = 'success'), 0) AS avg_records
        FROM extraction_log
        WHERE extractor_name ILIKE %s
          AND completed_at >= NOW() - INTERVAL '7 days'
        """,
        (_extractor_pattern(connector_type),),
    )
    week = cur.fetchone() or {}
    return {
        "last_run_at": last["completed_at"].isoformat() if last and last.get("completed_at") else None,
        "last_run_status": last["status"] if last else None,
        "last_run_records": int(last["records_inserted"] or 0) if last else 0,
        "last_run_error": last.get("error_message") if last else None,
        "runs_last_7_days": int(week.get("n") or 0),
        "success_rate_7d": round((int(week.get("ok") or 0) / int(week["n"])) * 100, 1) if week.get("n") else None,
        "avg_records_per_run": float(week.get("avg_records") or 0),
    }


@connect_router.get("/public-key")
def public_key(user: dict[str, Any] = Depends(require_connect_view)) -> dict[str, str]:
    return {"public_key": load_public_key()}


@connect_router.get("/connectors")
def list_connectors(
    request: Request,
    user: dict[str, Any] = Depends(require_connect_view),
) -> dict[str, Any]:
    client_id = _client_id(user)
    with _cursor(request) as cur:
        cur.execute(
            """
            SELECT *
            FROM portal_connector_connections
            WHERE client_id = %s AND active = TRUE
            """,
            (client_id,),
        )
        connected = {row["connector_type"]: dict(row) for row in cur.fetchall()}
        items = []
        for spec in CATALOG:
            row = connected.get(spec["connector_type"])
            stats = _run_stats(cur, spec["connector_type"]) if row else {}
            items.append(
                {
                    **{key: spec[key] for key in spec if key != "required_fields"},
                    "status": {
                        "connected": bool(row),
                        "connection_id": str(row["id"]) if row else None,
                        "display_name": row["display_name"] if row else None,
                        "last_successful_run": stats.get("last_run_at") or (row.get("last_successful_run_at").isoformat() if row and row.get("last_successful_run_at") else None),
                        "last_error": (row.get("last_test_error") if row and not row.get("last_test_success") else None),
                        "last_test_success": row.get("last_test_success") if row else None,
                        "last_tested_at": row["last_tested_at"].isoformat() if row and row.get("last_tested_at") else None,
                        "workflows": list(row.get("workflows") or []) if row else [],
                        "last_run_records": stats.get("last_run_records", 0),
                    },
                }
            )
    return {"items": items}


@connect_router.get("/connections")
def list_connections(
    request: Request,
    user: dict[str, Any] = Depends(require_connect_view),
) -> dict[str, Any]:
    client_id = _client_id(user)
    with _cursor(request) as cur:
        cur.execute(
            """
            SELECT *
            FROM portal_connector_connections
            WHERE client_id = %s AND active = TRUE
            ORDER BY created_at DESC
            """,
            (client_id,),
        )
        rows = cur.fetchall()
        items = []
        for row in rows:
            stats = _run_stats(cur, row["connector_type"])
            items.append(_public_connection(dict(row), stats))
    return {"items": items}


@connect_router.post("/test")
def test_draft_connection(
    body: DraftTestBody,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Live test without persisting credentials."""
    _validate_credentials(body.connector_type, body.credentials)
    return run_connection_test(body.connector_type, body.credentials)


@connect_router.post("/connections")
def create_connection(
    body: ConnectionCreateBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    spec = _catalog(body.connector_type)
    _validate_credentials(body.connector_type, body.credentials)
    client_id = _client_id(user)
    blob = encrypt_secret(json.dumps(body.credentials)) if body.credentials else None
    test = run_connection_test(body.connector_type, body.credentials)
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        _ensure_client(cur, client_id)
        try:
            cur.execute(
            """
            INSERT INTO portal_connector_connections (
                client_id, connector_type, display_name, category, auth_method,
                encrypted_credentials, workflows, custom_instructions,
                notify_on_failure, notify_email, created_by,
                last_tested_at, last_test_success, last_test_error
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s)
            RETURNING *
            """,
            (
                client_id,
                body.connector_type,
                body.display_name.strip(),
                spec["category"],
                spec["auth_method"],
                blob,
                body.workflows or [WORKFLOW_DEFAULT],
                body.custom_instructions,
                body.notify_on_failure,
                body.notify_email,
                str(user["id"]),
                test["success"],
                test.get("error_message"),
            ),
            )
            row = cur.fetchone()
        except IntegrityError as exc:
            conn.rollback()
            raise HTTPException(
                status_code=409,
                detail="An active connection of this type already exists.",
            ) from exc
    conn.commit()
    log_audit_event(
        request,
        action="connector_added",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="connector",
        resource_id=str(row["id"]),
        details={"connector_type": body.connector_type, "workflows": body.workflows},
    )
    return {"connection_id": str(row["id"]), "connection": _public_connection(dict(row)), "test_result": test}


@connect_router.post("/connections/{connection_id}/test")
def test_connection(
    connection_id: UUID,
    request: Request,
    user: dict[str, Any] = Depends(require_connect_view),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM portal_connector_connections WHERE id = %s AND client_id = %s",
            (str(connection_id), _client_id(user)),
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Connection not found")
        creds = _decrypt_creds(dict(row))
        test = run_connection_test(row["connector_type"], creds)
        cur.execute(
            """
            UPDATE portal_connector_connections
            SET last_tested_at = NOW(), last_test_success = %s, last_test_error = %s, updated_at = NOW()
            WHERE id = %s
            """,
            (test["success"], test.get("error_message"), str(connection_id)),
        )
    conn.commit()
    log_audit_event(
        request,
        action="connection_tested",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="connector",
        resource_id=str(connection_id),
        details={"connector_type": row["connector_type"], "success": test["success"]},
    )
    return test


@connect_router.patch("/connections/{connection_id}")
def patch_connection(
    connection_id: UUID,
    body: ConnectionPatchBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM portal_connector_connections WHERE id = %s AND client_id = %s",
            (str(connection_id), _client_id(user)),
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Connection not found")
        before_workflows = list(row.get("workflows") or [])
        cur.execute(
            """
            UPDATE portal_connector_connections
            SET display_name = COALESCE(%s, display_name),
                workflows = COALESCE(%s, workflows),
                custom_instructions = COALESCE(%s, custom_instructions),
                notify_on_failure = COALESCE(%s, notify_on_failure),
                notify_email = COALESCE(%s, notify_email),
                updated_at = NOW()
            WHERE id = %s
            RETURNING *
            """,
            (
                body.display_name,
                body.workflows,
                body.custom_instructions,
                body.notify_on_failure,
                body.notify_email,
                str(connection_id),
            ),
        )
        updated = cur.fetchone()
    conn.commit()
    log_audit_event(
        request,
        action="connector_updated",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="connector",
        resource_id=str(connection_id),
        details={
            "connector_type": row["connector_type"],
            "before": before_workflows,
            "after": body.workflows or before_workflows,
        },
    )
    return _public_connection(dict(updated))


@connect_router.post("/connections/{connection_id}/rotate-credentials")
def rotate_credentials(
    connection_id: UUID,
    body: RotateBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM portal_connector_connections WHERE id = %s AND client_id = %s AND active = TRUE",
            (str(connection_id), _client_id(user)),
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Connection not found")
        _validate_credentials(row["connector_type"], body.credentials)
        test = run_connection_test(row["connector_type"], body.credentials)
        cur.execute(
            """
            UPDATE portal_connector_connections
            SET encrypted_credentials = %s,
                last_tested_at = NOW(),
                last_test_success = %s,
                last_test_error = %s,
                updated_at = NOW()
            WHERE id = %s
            """,
            (
                encrypt_secret(json.dumps(body.credentials)),
                test["success"],
                test.get("error_message"),
                str(connection_id),
            ),
        )
    conn.commit()
    log_audit_event(
        request,
        action="credentials_rotated",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="connector",
        resource_id=str(connection_id),
        details={"connector_type": row["connector_type"]},
    )
    return {"test_result": test}


@connect_router.delete("/connections/{connection_id}")
def disconnect_connection(
    connection_id: UUID,
    body: DisconnectBody,
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, bool]:
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required")
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM portal_connector_connections WHERE id = %s AND client_id = %s AND active = TRUE",
            (str(connection_id), _client_id(user)),
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Connection not found")
        cur.execute(
            """
            UPDATE portal_connector_connections
            SET active = FALSE, disconnected_at = NOW(), disconnected_reason = %s, updated_at = NOW()
            WHERE id = %s
            """,
            (body.reason.strip(), str(connection_id)),
        )
    conn.commit()
    log_audit_event(
        request,
        action="connector_disconnected",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="connector",
        resource_id=str(connection_id),
        details={"connector_type": row["connector_type"], "reason": body.reason},
    )
    return {"ok": True}


@connect_router.get("/connections/{connection_id}/health")
def connection_health(
    connection_id: UUID,
    request: Request,
    user: dict[str, Any] = Depends(require_connect_view),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        cur.execute(
            "SELECT * FROM portal_connector_connections WHERE id = %s AND client_id = %s",
            (str(connection_id), _client_id(user)),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Connection not found")
        pattern = _extractor_pattern(row["connector_type"])
        cur.execute(
            """
            SELECT DATE(completed_at AT TIME ZONE 'UTC') AS day,
                   bool_or(status = 'success') AS any_ok,
                   bool_or(status = 'failed') AS any_fail,
                   SUM(COALESCE(records_inserted, 0)) AS records,
                   MAX(error_message) FILTER (WHERE status = 'failed') AS error_message
            FROM extraction_log
            WHERE extractor_name ILIKE %s
              AND completed_at >= NOW() - INTERVAL '7 days'
            GROUP BY 1
            ORDER BY 1
            """,
            (pattern,),
        )
        by_day = {day_row["day"]: dict(day_row) for day_row in cur.fetchall()}
        stats = _run_stats(cur, row["connector_type"])
        cur.execute(
            """
            SELECT completed_at, error_message
            FROM extraction_log
            WHERE extractor_name ILIKE %s AND status = 'failed'
            ORDER BY completed_at DESC NULLS LAST
            LIMIT 1
            """,
            (pattern,),
        )
        failed = cur.fetchone()
    history = []
    today = utcnow().date()
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        hit = by_day.get(day)
        if not hit:
            status_name = "none"
        elif hit.get("any_fail") and not hit.get("any_ok"):
            status_name = "failed"
        elif hit.get("any_fail"):
            status_name = "warning"
        else:
            status_name = "success"
        history.append(
            {
                "date": day.isoformat(),
                "status": status_name,
                "records": int(hit["records"]) if hit else 0,
                "error_message": hit.get("error_message") if hit else None,
            }
        )
    last_success = stats.get("last_run_at")
    if row.get("last_test_success") is False:
        overall = "failed"
    elif not last_success and not stats.get("runs_last_7_days"):
        overall = "never_run" if not row.get("last_tested_at") else "healthy"
        if row.get("last_test_success"):
            overall = "healthy"
    elif stats.get("success_rate_7d") is not None and stats["success_rate_7d"] < 80:
        overall = "degraded"
    else:
        overall = "healthy"
    return {
        "connection_id": str(connection_id),
        "connector_type": row["connector_type"],
        "display_name": row["display_name"],
        "overall_status": overall,
        "last_successful_run": last_success,
        "last_failed_run": failed["completed_at"].isoformat() if failed and failed.get("completed_at") else None,
        "runs_last_7_days": stats.get("runs_last_7_days") or 0,
        "success_rate_7d": stats.get("success_rate_7d"),
        "avg_records_per_run": stats.get("avg_records_per_run") or 0,
        "last_error": failed.get("error_message") if failed else row.get("last_test_error"),
        "daily_history": history,
        "last_tested_at": row["last_tested_at"].isoformat() if row.get("last_tested_at") else None,
        "last_test_success": row.get("last_test_success"),
        "has_credentials": bool(row.get("encrypted_credentials")),
        "workflows": list(row.get("workflows") or []),
        "custom_instructions": row.get("custom_instructions"),
        "notify_on_failure": bool(row.get("notify_on_failure")),
        "notify_email": row.get("notify_email"),
    }


def _validate_magic(data: bytes, file_type: str) -> None:
    head = data[:256].lstrip()
    if file_type == "fhir_bundle":
        if not (head.startswith(b"{") or head.startswith(b"[")):
            raise HTTPException(status_code=400, detail="Expected a FHIR JSON bundle.")
    elif file_type == "era_835":
        if not (b"ISA" in data[:1024] or b"ST*835" in data[:2048] or head.startswith(b"ISA")):
            if not (head[:3].isascii() and b"," in head[:200]):
                raise HTTPException(status_code=400, detail="Expected X12 835 EDI format.")
    elif file_type in {"custom", "policy_text"}:
        if not head:
            raise HTTPException(status_code=400, detail="File is empty.")


def _extract_count(data: bytes, file_type: str) -> int:
    if file_type == "fhir_bundle":
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 0
        if isinstance(payload, dict) and isinstance(payload.get("entry"), list):
            return len(payload["entry"])
        return 1 if payload else 0
    if file_type == "era_835":
        return max(1, data.count(b"ST*835") or data.count(b"CLP"))
    text = data.decode("utf-8", errors="ignore")
    lines = [line for line in text.splitlines() if line.strip()]
    return max(0, len(lines) - 1)


def _process_completeness_upload(app_db, data: bytes, job: dict[str, Any]) -> int:
    text = data.decode("utf-8", errors="ignore")
    header = (text.splitlines()[0] if text.strip() else "").lower()
    file_type = job.get("file_type")
    if file_type != "policy_text" and "order_id" in header:
        transformers_dir = str(_ROOT / "transformers")
        if transformers_dir not in sys.path:
            sys.path.insert(0, transformers_dir)
        if str(_ROOT) not in sys.path:
            sys.path.insert(0, str(_ROOT))
        from completeness_transformer import CompletenessTransformer  # type: ignore

        transformer = CompletenessTransformer()
        try:
            counts = transformer.ingest_orders_csv(text)
        finally:
            transformer.close()
        return int(counts.get("rows") or 0)
    from .completeness_router import suggest_criteria

    suggested = suggest_criteria(text)
    transformers_dir = str(_ROOT / "transformers")
    if transformers_dir not in sys.path:
        sys.path.insert(0, transformers_dir)
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
    from completeness_transformer import CompletenessTransformer  # type: ignore

    transformer = CompletenessTransformer()
    try:
        transformer.ensure_schema()
        with transformer.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO policy_drafts (
                    client_id, source_filename, raw_text, suggested_items, status
                )
                VALUES (%s, %s, %s, %s::jsonb, 'pending')
                """,
                (
                    job.get("client_id"),
                    job.get("original_filename"),
                    text[:200000],
                    json.dumps(suggested),
                ),
            )
        transformer.conn.commit()
    finally:
        transformer.close()
    del app_db
    return len(suggested)


def _process_upload(app_db, upload_id: str) -> None:
    with app_db.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM file_upload_jobs WHERE id = %s", (upload_id,))
        job = cur.fetchone()
        if not job:
            app_db.rollback()
            return
        path = Path(job["storage_path"])
        try:
            data = path.read_bytes()
            count = _extract_count(data, job["file_type"])
            if is_completeness(job.get("workflow")):
                count = _process_completeness_upload(app_db, data, dict(job)) or count
            cur.execute(
                """
                UPDATE file_upload_jobs
                SET status = 'complete', records_extracted = %s, completed_at = NOW()
                WHERE id = %s
                """,
                (count, upload_id),
            )
        except Exception as exc:
            cur.execute(
                """
                UPDATE file_upload_jobs
                SET status = 'failed', error_message = %s, completed_at = NOW()
                WHERE id = %s
                """,
                ("File format not recognized. Check that the file matches the selected type.", upload_id),
            )
            del exc
    app_db.commit()


@connect_router.post("/files/upload")
async def upload_file(
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
    file: UploadFile = File(...),
    file_type: str = Form(...),
    workflow: str = Form(WORKFLOW_DEFAULT),
    description: str | None = Form(None),
) -> dict[str, Any]:
    if file_type not in {"era_835", "fhir_bundle", "custom", "policy_text"}:
        raise HTTPException(status_code=400, detail="Invalid file type")
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File exceeds 50MB limit")
    if not data:
        raise HTTPException(status_code=400, detail="File is empty")
    _validate_magic(data, file_type)
    client_id = _client_id(user)
    upload_id = uuid.uuid4()
    filename = Path(file.filename or "upload.bin").name
    dest_dir = UPLOAD_ROOT / client_id / str(upload_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / filename
    dest.write_bytes(data)
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO file_upload_jobs (
                id, client_id, original_filename, storage_path, file_type, workflow,
                description, file_size_bytes, uploaded_by, status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'processing')
            RETURNING *
            """,
            (
                str(upload_id),
                client_id,
                filename,
                str(dest),
                file_type,
                workflow,
                description,
                len(data),
                str(user["id"]),
            ),
        )
        row = cur.fetchone()
    conn.commit()
    _process_upload(conn, str(upload_id))
    log_audit_event(
        request,
        action="file_uploaded",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="file_upload",
        resource_id=str(upload_id),
        details={"file_type": file_type, "workflow": workflow, "filename": filename},
    )
    return {
        "upload_id": str(upload_id),
        "filename": filename,
        "size_bytes": len(data),
        "status": "processing",
        "job": _jsonable(dict(row)),
    }


@connect_router.get("/files")
def list_files(
    request: Request,
    user: dict[str, Any] = Depends(require_connect_view),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        cur.execute(
            """
            SELECT id, original_filename, file_type, workflow, description, file_size_bytes,
                   status, records_extracted, error_message, uploaded_at, completed_at
            FROM file_upload_jobs
            WHERE client_id = %s
            ORDER BY uploaded_at DESC
            LIMIT 100
            """,
            (_client_id(user),),
        )
        rows = cur.fetchall()
    return {"items": [_jsonable(dict(row)) for row in rows]}


@connect_router.get("/files/{upload_id}/status")
def file_status(
    upload_id: UUID,
    request: Request,
    user: dict[str, Any] = Depends(require_connect_view),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        cur.execute(
            """
            SELECT status, records_extracted, error_message, completed_at, original_filename
            FROM file_upload_jobs
            WHERE id = %s AND client_id = %s
            """,
            (str(upload_id), _client_id(user)),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")
    return _jsonable(dict(row))


def _onboarding_steps(cur, user: dict[str, Any]) -> list[dict[str, Any]]:
    client_id = _client_id(user)
    _ensure_client(cur, client_id)
    cur.execute("SELECT * FROM portal_clients WHERE id = %s", (client_id,))
    client = cur.fetchone() or {}
    cur.execute(
        """
        SELECT COUNT(*) AS n, COALESCE(bool_or(cardinality(workflows) > 0), FALSE) AS has_workflow,
               COALESCE(bool_or(notify_email IS NOT NULL AND btrim(notify_email) <> ''), FALSE) AS has_notify,
               COALESCE(bool_or(category = 'ehr'), FALSE) AS has_ehr
        FROM portal_connector_connections
        WHERE client_id = %s AND active = TRUE
        """,
        (client_id,),
    )
    cons = cur.fetchone() or {}
    cur.execute(
        """
        SELECT COUNT(*) AS n FROM extraction_log WHERE status = 'success'
        """
    )
    extracts = int((cur.fetchone() or {}).get("n") or 0)
    cur.execute(
        """
        SELECT COUNT(*) AS n FROM file_upload_jobs
        WHERE client_id = %s AND status = 'complete'
        """,
        (client_id,),
    )
    uploads = int((cur.fetchone() or {}).get("n") or 0)
    cur.execute("SELECT COUNT(*) AS n FROM prior_auth_contexts")
    packets = int((cur.fetchone() or {}).get("n") or 0)
    cur.execute("SELECT COUNT(*) AS n FROM denial_contexts")
    denials = int((cur.fetchone() or {}).get("n") or 0)
    has_data = uploads > 0 or packets > 0 or denials > 0
    cur.execute("SELECT COUNT(*) AS n FROM portal_vendor_connections WHERE client_id = %s AND is_active = TRUE", (client_id,))
    vendors = int((cur.fetchone() or {}).get("n") or 0)
    ehr = bool(cons.get("has_ehr")) or has_data
    workflow = bool(cons.get("has_workflow")) or has_data
    payers = bool(client.get("payer_mappings_reviewed_at"))
    first_run = (bool(cons.get("has_ehr")) and extracts > 0) or has_data
    baa = bool(client.get("baa_acknowledged_at"))
    return [
        {
            "id": "ehr_connected",
            "label": "Connect your EHR system",
            "description": "Connect the system that holds claims and clinical data, or upload an orders CSV.",
            "complete": ehr,
            "required": True,
            "action_url": "/portal/connect/sources",
            "action_label": "Connect EHR",
        },
        {
            "id": "workflow_assigned",
            "label": "Assign at least one workflow",
            "description": "Tell the pipeline which work this source should feed.",
            "complete": workflow,
            "required": True,
            "action_url": "/portal/connect/sources",
            "action_label": "Assign workflow",
        },
        {
            "id": "payer_mappings_reviewed",
            "label": "Review payer name mappings",
            "description": "Confirm raw payer names resolve to canonical payers.",
            "complete": payers,
            "required": True,
            "action_url": "/portal/clean/payers",
            "action_label": "Review mappings",
        },
        {
            "id": "first_extraction_complete",
            "label": "Run first pipeline extraction",
            "description": "Pull the first batch of claims after connecting.",
            "complete": first_run,
            "required": True,
            "action_url": "/portal/connect",
            "action_label": "Run now",
        },
        {
            "id": "baa_acknowledged",
            "label": "Acknowledge BAA is in place",
            "description": "Confirm a Business Associate Agreement covers this integration.",
            "complete": baa,
            "required": True,
            "action_url": None,
            "action_label": "Acknowledge BAA",
        },
        {
            "id": "mfa_enabled",
            "label": "Enable two-factor authentication",
            "description": "Protect this account with an authenticator app.",
            "complete": bool(user.get("mfa_enabled")),
            "required": False,
            "action_url": "/portal/connect",
            "action_label": "Recommended",
        },
        {
            "id": "notification_email_set",
            "label": "Set pipeline failure notifications",
            "description": "Get an email if a connection fails overnight.",
            "complete": bool(cons.get("has_notify")),
            "required": False,
            "action_url": "/portal/connect/sources",
            "action_label": "Add notification",
        },
        {
            "id": "test_vendor_connected",
            "label": "Connect a test vendor via MCP",
            "description": "Issue an API key so an agent can query the worklist.",
            "complete": vendors > 0,
            "required": False,
            "action_url": "/portal/serve/vendors",
            "action_label": "Optional",
        },
    ]


@connect_router.get("/onboarding-status")
def onboarding_status(
    request: Request,
    user: dict[str, Any] = Depends(require_connect_view),
) -> dict[str, Any]:
    with _cursor(request) as cur:
        steps = _onboarding_steps(cur, user)
        required_done = all(step["complete"] for step in steps if step["required"])
        if required_done:
            cur.execute(
                """
                UPDATE portal_clients
                SET onboarding_complete_at = COALESCE(onboarding_complete_at, NOW())
                WHERE id = %s
                """,
                (_client_id(user),),
            )
            _db(request).commit()
    ehr = next(step for step in steps if step["id"] == "ehr_connected")
    return {
        "overall_complete": required_done,
        "ehr_connected": bool(ehr["complete"]),
        "steps": steps,
    }


@connect_router.post("/onboarding/acknowledge-baa")
def acknowledge_baa(
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        _ensure_client(cur, _client_id(user))
        cur.execute(
            """
            UPDATE portal_clients
            SET baa_acknowledged_at = NOW(), baa_acknowledged_by = %s
            WHERE id = %s
            """,
            (str(user["id"]), _client_id(user)),
        )
    conn.commit()
    log_audit_event(
        request,
        action="baa_acknowledged",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="portal_client",
        resource_id=_client_id(user),
    )
    return {"ok": True}


@connect_router.post("/onboarding/review-payers")
def review_payers(
    request: Request,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        _ensure_client(cur, _client_id(user))
        cur.execute(
            """
            UPDATE portal_clients
            SET payer_mappings_reviewed_at = NOW()
            WHERE id = %s
            """,
            (_client_id(user),),
        )
    conn.commit()
    log_audit_event(
        request,
        action="payer_mappings_reviewed",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="portal_client",
        resource_id=_client_id(user),
    )
    return {"ok": True}
