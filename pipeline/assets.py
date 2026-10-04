"""
Dagster assets for the healthpipeline EOB extract → transform flow.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg2
from dagster import MaterializeResult, MetadataValue, asset
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Import path: healthpipeline/, extractors/, transformers/
# ---------------------------------------------------------------------------
_HEALTHPIPELINE_ROOT = Path(__file__).resolve().parent.parent
for _p in (
    _HEALTHPIPELINE_ROOT,
    _HEALTHPIPELINE_ROOT / "extractors",
    _HEALTHPIPELINE_ROOT / "transformers",
):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

from eob_extractor import EOBExtractor  # noqa: E402
from eob_transformer import EOBTransformer  # noqa: E402
from order_extractor import OrderExtractor  # noqa: E402
from completeness_transformer import CompletenessTransformer  # noqa: E402

load_dotenv(_HEALTHPIPELINE_ROOT / ".env")


def _connect():
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ.get("PGDATABASE", "healthpipeline"),
        user=os.environ.get("PGUSER", os.environ.get("USER", "postgres")),
        password=os.environ.get("PGPASSWORD", ""),
    )


def _latest_extraction_inserted(extractor_name: str = "eob_extractor") -> tuple[int, int]:
    """(records_read, records_inserted) from the latest successful extractor run."""
    sql = """
    SELECT records_read, records_inserted
    FROM extraction_log
    WHERE extractor_name = %s AND status = 'success'
    ORDER BY completed_at DESC NULLS LAST, id DESC
    LIMIT 1;
    """
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (extractor_name,))
            row = cur.fetchone()
    if not row:
        return 0, 0
    return int(row[0] or 0), int(row[1] or 0)


def _max_table_id(table: str) -> int:
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}")
            return int(cur.fetchone()[0])


def _transform_counts_since(
    clean_id_floor: int, quarantine_id_floor: int
) -> tuple[int, int, int]:
    """(clean, flagged, rejected) rows created in this transform run."""
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT validation_status, COUNT(*)::int
                FROM clean_denial_records
                WHERE id > %s
                GROUP BY validation_status
                """,
                (clean_id_floor,),
            )
            clean_rows = {row[0]: row[1] for row in cur.fetchall()}
            cur.execute(
                "SELECT COUNT(*)::int FROM quarantine_records WHERE id > %s",
                (quarantine_id_floor,),
            )
            rejected = int(cur.fetchone()[0] or 0)
    return (
        int(clean_rows.get("clean", 0)),
        int(clean_rows.get("flagged", 0)),
        rejected,
    )


@asset
def raw_eob_data(context) -> None:
    """Fetch EOBs from FHIR API into raw_fhir_responses."""
    extractor = EOBExtractor()
    try:
        extractor.run()
    finally:
        extractor.close()

    records_read, rows_inserted = _latest_extraction_inserted()
    context.add_output_metadata({
        "records_read": MetadataValue.int(records_read),
        "rows_inserted": MetadataValue.int(rows_inserted),
    })



@asset(deps=[raw_eob_data])
def clean_denial_records(context) -> None:
    """Transform unprocessed raw EOB JSON into clean / quarantine tables."""
    clean_floor = _max_table_id("clean_denial_records")
    quarantine_floor = _max_table_id("quarantine_records")

    transformer = EOBTransformer()
    try:
        transformer.run()
    finally:
        transformer.close()

    clean_n, flagged_n, rejected_n = _transform_counts_since(clean_floor, quarantine_floor)
    context.add_output_metadata({
        "clean": MetadataValue.int(clean_n),
        "flagged": MetadataValue.int(flagged_n),
        "rejected": MetadataValue.int(rejected_n),
        "total_processed": MetadataValue.int(clean_n + flagged_n + rejected_n),
    })


@asset
def raw_order_data(context) -> None:
    """Fetch ServiceRequest/Claim plus supporting FHIR resources."""
    extractor = OrderExtractor()
    try:
        extractor.run()
    finally:
        extractor.close()
    records_read, rows_inserted = _latest_extraction_inserted("order_extractor")
    context.add_output_metadata({
        "records_read": MetadataValue.int(records_read),
        "rows_inserted": MetadataValue.int(rows_inserted),
    })


@asset(deps=[raw_order_data])
def prior_auth_contexts(context) -> None:
    """Assemble prior-auth completeness packets from orders + chart + payer rules."""
    transformer = CompletenessTransformer()
    try:
        transformer.run()
    finally:
        transformer.close()
    context.add_output_metadata({"status": MetadataValue.text("completeness transform finished")})