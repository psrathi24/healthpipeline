"""Pull ServiceRequest (and supporting Patient/Coverage/DocumentReference) into raw_fhir_responses."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg2
from dotenv import load_dotenv
from loguru import logger

from fhir_client import FHIRClient

EXTRACTOR_NAME = "order_extractor"
ORDER_TYPES = ("ServiceRequest", "Claim")
SUPPORT_TYPES = ("Patient", "Coverage", "DocumentReference")


class OrderExtractor:
    def __init__(self) -> None:
        env_path = Path(__file__).resolve().parent.parent / ".env"
        load_dotenv(env_path)
        base_url = os.environ.get("FHIR_BASE_URL", "").strip()
        if not base_url:
            raise ValueError("FHIR_BASE_URL is empty in environment/.env")
        self.client = FHIRClient(base_url=base_url)
        self.conn = psycopg2.connect(
            host=os.environ.get("PGHOST", "localhost"),
            port=os.environ.get("PGPORT", "5432"),
            dbname=os.environ.get("PGDATABASE", "healthpipeline"),
            user=os.environ.get("PGUSER", os.environ.get("USER", "postgres")),
            password=os.environ.get("PGPASSWORD", ""),
        )

    def close(self) -> None:
        self.conn.close()

    def ensure_tables(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS raw_fhir_responses (
                    resource_id text PRIMARY KEY,
                    resource_type text NOT NULL,
                    payload jsonb NOT NULL,
                    fetched_at timestamptz NOT NULL DEFAULT now()
                );
                ALTER TABLE raw_fhir_responses
                  ADD COLUMN IF NOT EXISTS processed_at timestamptz;
                ALTER TABLE raw_fhir_responses
                  ADD COLUMN IF NOT EXISTS source text;
                CREATE TABLE IF NOT EXISTS extraction_log (
                    id bigserial PRIMARY KEY,
                    extractor_name text NOT NULL,
                    started_at timestamptz NOT NULL,
                    completed_at timestamptz,
                    status text NOT NULL,
                    records_read integer NOT NULL DEFAULT 0,
                    records_inserted integer NOT NULL DEFAULT 0,
                    last_updated_watermark text,
                    error_message text
                );
                """
            )
        self.conn.commit()

    def insert_raw_resource(self, resource: dict[str, Any], source: str = "fhir") -> bool:
        resource_id = resource.get("id")
        resource_type = resource.get("resourceType")
        if not resource_id or not resource_type:
            return False
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO raw_fhir_responses (resource_id, resource_type, payload, source)
                VALUES (%s, %s, %s::jsonb, %s)
                ON CONFLICT (resource_id) DO UPDATE SET
                    payload = EXCLUDED.payload,
                    fetched_at = now(),
                    source = COALESCE(EXCLUDED.source, raw_fhir_responses.source),
                    processed_at = CASE
                        WHEN raw_fhir_responses.resource_type IN ('ServiceRequest', 'Claim')
                         AND raw_fhir_responses.payload IS DISTINCT FROM EXCLUDED.payload
                        THEN NULL
                        ELSE raw_fhir_responses.processed_at
                    END
                """,
                (str(resource_id), str(resource_type), json.dumps(resource), source),
            )
            return cur.rowcount >= 1

    def log_completion(
        self,
        started_at: datetime,
        records_read: int,
        records_inserted: int,
        watermark: str | None,
        status: str,
        error_message: str | None = None,
    ) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO extraction_log (
                    extractor_name, started_at, completed_at, status,
                    records_read, records_inserted, last_updated_watermark, error_message
                )
                VALUES (%s, %s, now(), %s, %s, %s, %s, %s)
                """,
                (
                    EXTRACTOR_NAME,
                    started_at,
                    status,
                    records_read,
                    records_inserted,
                    watermark,
                    error_message,
                ),
            )

    def run(self) -> None:
        self.ensure_tables()
        started_at = datetime.now(timezone.utc)
        records_read = 0
        records_inserted = 0
        max_seen: str | None = None
        try:
            for resource_type in (*ORDER_TYPES, *SUPPORT_TYPES):
                params: dict[str, Any] = {"_count": "50"}
                logger.info("Starting {} extraction", resource_type)
                for resource in self.client.get_resources(resource_type, params):
                    records_read += 1
                    if self.insert_raw_resource(resource):
                        records_inserted += 1
                    meta = resource.get("meta") or {}
                    lu = meta.get("lastUpdated")
                    if isinstance(lu, str) and (max_seen is None or lu > max_seen):
                        max_seen = lu
                    if records_read % 100 == 0:
                        self.conn.commit()
            self.log_completion(started_at, records_read, records_inserted, max_seen, "success")
            self.conn.commit()
            logger.info(
                "Order extraction complete. read={} inserted={}",
                records_read,
                records_inserted,
            )
        except Exception as exc:
            self.conn.rollback()
            with self.conn:
                self.log_completion(
                    started_at,
                    records_read,
                    records_inserted,
                    max_seen,
                    "failed",
                    str(exc),
                )
            logger.exception("Order extraction failed: {}", exc)
            raise


if __name__ == "__main__":
    extractor = OrderExtractor()
    try:
        extractor.run()
    finally:
        extractor.close()
