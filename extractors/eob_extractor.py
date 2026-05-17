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


class EOBExtractor:
    """
    Incremental EOB extractor:
    - reads last watermark from extraction_log
    - fetches ExplanationOfBenefit from FHIR API using _lastUpdated
    - inserts raw JSON into raw_fhir_responses with ON CONFLICT DO NOTHING
    - writes completion row to extraction_log
    """

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
        ddl = """
        CREATE TABLE IF NOT EXISTS raw_fhir_responses (
            resource_id text PRIMARY KEY,
            resource_type text NOT NULL,
            payload jsonb NOT NULL,
            fetched_at timestamptz NOT NULL DEFAULT now()
        );

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
        with self.conn.cursor() as cur:
            cur.execute(ddl)
        self.conn.commit()

    def get_last_watermark(self) -> str | None:
        sql = """
        SELECT last_updated_watermark
        FROM extraction_log
        WHERE extractor_name = %s
          AND status = 'success'
          AND last_updated_watermark IS NOT NULL
        ORDER BY completed_at DESC NULLS LAST, id DESC
        LIMIT 1;
        """
        with self.conn.cursor() as cur:
            cur.execute(sql, ("eob_extractor",))
            row = cur.fetchone()
        return row[0] if row else None

    def insert_raw_resource(self, resource: dict[str, Any]) -> bool:
        resource_id = resource.get("id")
        if not resource_id:
            return False

        sql = """
        INSERT INTO raw_fhir_responses (resource_id, resource_type, payload)
        VALUES (%s, %s, %s::jsonb)
        ON CONFLICT (resource_id) DO NOTHING;
        """
        with self.conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    str(resource_id),
                    str(resource.get("resourceType", "")),
                    json.dumps(resource),
                ),
            )
            inserted = cur.rowcount == 1
        return inserted

    def log_completion(
        self,
        started_at: datetime,
        records_read: int,
        records_inserted: int,
        watermark: str | None,
        status: str,
        error_message: str | None = None,
    ) -> None:
        sql = """
        INSERT INTO extraction_log (
            extractor_name, started_at, completed_at, status,
            records_read, records_inserted, last_updated_watermark, error_message
        )
        VALUES (%s, %s, now(), %s, %s, %s, %s, %s);
        """
        with self.conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    "eob_extractor",
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
        last_watermark = self.get_last_watermark()
        params: dict[str, Any] = {"_count": "100"}
        if last_watermark:
            params["_lastUpdated"] = f"gt{last_watermark}"

        logger.info("Starting EOB extraction with params={}", params)

        records_read = 0
        records_inserted = 0
        max_seen_last_updated: str | None = last_watermark

        try:
            for resource in self.client.get_resources("ExplanationOfBenefit", params):
                records_read += 1

                if self.insert_raw_resource(resource):
                    records_inserted += 1

                meta = resource.get("meta") or {}
                lu = meta.get("lastUpdated")
                if isinstance(lu, str):
                    if max_seen_last_updated is None or lu > max_seen_last_updated:
                        max_seen_last_updated = lu

                if records_read % 100 == 0:
                    self.conn.commit()
                    logger.info(
                        "Progress: read={}, inserted={}",
                        records_read,
                        records_inserted,
                    )

            self.log_completion(
                started_at=started_at,
                records_read=records_read,
                records_inserted=records_inserted,
                watermark=max_seen_last_updated,
                status="success",
            )
            self.conn.commit()

            logger.info(
                "EOB extraction complete. read={}, inserted={}, watermark={}",
                records_read,
                records_inserted,
                max_seen_last_updated,
            )

        except Exception as exc:
            self.conn.rollback()
            # Write failure log row in a clean transaction
            with self.conn:
                self.log_completion(
                    started_at=started_at,
                    records_read=records_read,
                    records_inserted=records_inserted,
                    watermark=max_seen_last_updated,
                    status="failed",
                    error_message=str(exc),
                )
            logger.exception("EOB extraction failed: {}", exc)
            raise


if __name__ == "__main__":
    extractor = EOBExtractor()
    try:
        extractor.run()
    finally:
        extractor.close()