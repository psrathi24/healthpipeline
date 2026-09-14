"""
FastAPI service for clean denial records.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import psycopg2
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from psycopg2.extras import RealDictCursor

from .auth_router import auth_router
from .models import DenialRecord
from .clean_router import clean_router
from .serve_router import audit_router, serve_router

_HEALTHPIPELINE_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_HEALTHPIPELINE_ROOT / ".env")

_DENIAL_COLUMNS = """
    claim_id,
    patient_id,
    service_date,
    denial_reason_code,
    canonical_denial_code,
    canonical_denial_description,
    denial_category,
    payer_name,
    total_claim_amount,
    diagnosis_codes,
    procedure_codes,
    validation_status,
    data_quality_flags
"""


def _cors_origins() -> list[str]:
    origins = {
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://kalamon.cloud",
        "https://www.kalamon.cloud",
    }
    frontend = os.environ.get("PORTAL_FRONTEND_URL", "").rstrip("/")
    if frontend:
        origins.add(frontend)
    extra = os.environ.get("PORTAL_CORS_ORIGINS", "")
    for origin in extra.split(","):
        origin = origin.strip().rstrip("/")
        if origin:
            origins.add(origin)
    return sorted(origins)


def _connect_db() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ.get("PGDATABASE", "healthpipeline"),
        user=os.environ.get("PGUSER", os.environ.get("USER", "postgres")),
        password=os.environ.get("PGPASSWORD", ""),
    )


def _row_to_denial(row: dict[str, Any]) -> DenialRecord:
    return DenialRecord.model_validate(row)


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = _connect_db()
    app.state.db = conn
    try:
        yield
    finally:
        conn.close()


app = FastAPI(title="Health Pipeline Denial API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/auth")
app.include_router(serve_router, prefix="/serve")
app.include_router(audit_router, prefix="/audit")
app.include_router(clean_router, prefix="/clean")


def _get_db(request: Request) -> psycopg2.extensions.connection:
    return request.app.state.db


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/denial/{claim_id}", response_model=DenialRecord)
def get_denial_by_claim_id(claim_id: str, request: Request) -> DenialRecord:
    sql = f"""
    SELECT {_DENIAL_COLUMNS}
    FROM clean_denial_records
    WHERE claim_id = %s
    ORDER BY created_at DESC
    LIMIT 1;
    """
    conn = _get_db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (claim_id,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"No denial record for claim_id={claim_id!r}")
    return _row_to_denial(row)


@app.get("/denials", response_model=list[DenialRecord])
def list_denials(
    request: Request,
    limit: int = Query(20, ge=1, le=500),
    status: str | None = Query(None, description="Filter by validation_status"),
) -> list[DenialRecord]:
    clauses = ["1=1"]
    params: list[Any] = []
    if status is not None:
        clauses.append("validation_status = %s")
        params.append(status)
    where_sql = " AND ".join(clauses)
    sql = f"""
    SELECT {_DENIAL_COLUMNS}
    FROM clean_denial_records
    WHERE {where_sql}
    ORDER BY created_at DESC
    LIMIT %s;
    """
    params.append(limit)
    conn = _get_db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    return [_row_to_denial(row) for row in rows]