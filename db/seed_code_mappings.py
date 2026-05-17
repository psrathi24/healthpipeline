"""
Scrape X12 Claim Adjustment Reason Codes (HTML), load CARC rows into code_mappings.

Run from healthpipeline:
  ./venv/bin/python db/seed_code_mappings.py

Installs beautifulsoup4 at runtime if missing.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

import psycopg2
import requests
from dotenv import load_dotenv
from loguru import logger
from psycopg2.extras import execute_values

CARC_PAGE_URL = "https://x12.org/codes/claim-adjustment-reason-codes"
SOURCE_SYSTEM = "X12"

_STOP_RE = re.compile(r"Stop:\s*(\d{1,2}/\d{1,2}/\d{4})", re.IGNORECASE)
_CODE_RE = re.compile(r"^[\dA-Za-z]{1,6}$")

_CATEGORY_RULES: list[tuple[tuple[str, ...], str]] = [
    (("authorization", "prior authorization", "precertification", "pre-cert"), "authorization_required"),
    (("duplicate",), "duplicate_claim"),
    (("timely filing", "time limit", "filing limit"), "timely_filing"),
    (("non-covered", "not covered", "no coverage"), "not_covered"),
    (("coinsurance", "co-insurance", "deductible", "copayment", "co-payment"), "patient_responsibility"),
    (("experimental", "investigational"), "experimental_or_investigational"),
    (("maximum", "benefit maximum", "plan maximum"), "benefit_maximum"),
    (("denied", "denial", "processed as denial"), "denied"),
    (("processed as primary", "secondary payment", "coordination of benefits", " cob "), "coordination_of_benefits"),
]

DDL = """
CREATE TABLE IF NOT EXISTS code_mappings (
    id bigserial PRIMARY KEY,
    source_code text NOT NULL,
    source_system text NOT NULL DEFAULT 'X12',
    canonical_code text NOT NULL,
    canonical_description text,
    category text,
    UNIQUE (source_system, source_code)
);
"""

INSERT_SQL = """
INSERT INTO code_mappings (
    source_code, source_system, canonical_code, canonical_description, category
) VALUES %s
ON CONFLICT (source_system, source_code) DO NOTHING;
"""


def _ensure_bs4() -> None:
    try:
        import bs4  # noqa: F401
    except ImportError:
        logger.info("Installing beautifulsoup4 …")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "beautifulsoup4"],
            stdout=sys.stdout,
            stderr=sys.stderr,
        )


def _root() -> Path:
    return Path(__file__).resolve().parent.parent


def connect():
    load_dotenv(_root() / ".env")
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ.get("PGDATABASE", "healthpipeline"),
        user=os.environ.get("PGUSER", os.environ.get("USER", "postgres")),
        password=os.environ.get("PGPASSWORD", ""),
    )


def fetch_html(url: str) -> str:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    r = requests.get(url, headers=headers, timeout=120)
    r.raise_for_status()
    return r.text


def _derive_category(description: str) -> str:
    if not description or not isinstance(description, str):
        return "uncategorized"
    text = description.lower()
    for keywords, cat in _CATEGORY_RULES:
        if any(k in text for k in keywords):
            return cat
    return "other"


def _parse_stop_dates(text: str) -> list[date]:
    out: list[date] = []
    for m in _STOP_RE.finditer(text):
        try:
            out.append(datetime.strptime(m.group(1), "%m/%d/%Y").date())
        except ValueError:
            continue
    return out


def _is_deactivated_or_stopped(code_cell: str, desc_cell: str) -> bool:
    if "deactivated" in code_cell.lower():
        return True
    combined = f"{code_cell}\n{desc_cell}"
    stops = _parse_stop_dates(combined)
    today = date.today()
    return any(sd < today for sd in stops)


def _normalize_description(desc_cell: str) -> str:
    return " ".join(desc_cell.split()).strip()


def parse_carc_table(html: str) -> list[tuple[str, str, str, str, str]]:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        raise RuntimeError("No <table> elements found on page — layout may have changed.")

    rows_out: list[tuple[str, str, str, str, str]] = []

    for table in tables:
        for tr in table.find_all("tr"):
            cells = tr.find_all(["td", "th"])
            if len(cells) < 2:
                continue
            code_cell = cells[0].get_text("\n", strip=True)
            desc_cell = cells[1].get_text("\n", strip=True)
            if not code_cell or not desc_cell:
                continue

            first_line = code_cell.split("\n", 1)[0].strip()
            first_token = first_line.split()[0] if first_line else ""
            if not _CODE_RE.match(first_token):
                continue
            source_code = first_token

            if _is_deactivated_or_stopped(code_cell, desc_cell):
                continue

            canonical_description = _normalize_description(desc_cell)
            if not canonical_description:
                continue

            category = _derive_category(canonical_description)
            rows_out.append(
                (
                    source_code,
                    SOURCE_SYSTEM,
                    source_code,
                    canonical_description,
                    category,
                )
            )

    if not rows_out:
        raise RuntimeError(
            "Parsed zero CARC rows. The X12 page structure may have changed; "
            "inspect the HTML tables manually."
        )

    seen: set[str] = set()
    unique: list[tuple[str, str, str, str, str]] = []
    for row in rows_out:
        sc = row[0]
        if sc in seen:
            continue
        seen.add(sc)
        unique.append(row)

    return unique


def main() -> None:
    _ensure_bs4()

    url = os.environ.get("CARC_PAGE_URL", CARC_PAGE_URL)
    logger.info("Fetching {}", url)
    html = fetch_html(url)
    logger.info("Fetched {} characters of HTML", len(html))

    mapped = parse_carc_table(html)
    logger.info("Parsed {} active CARC row(s)", len(mapped))

    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(DDL)
            cur.execute("SELECT COUNT(*) FROM code_mappings")
            before = cur.fetchone()[0]

        with conn.cursor() as cur:
            execute_values(cur, INSERT_SQL, mapped, page_size=500)

        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM code_mappings")
            after = cur.fetchone()[0]

        conn.commit()
        inserted = after - before
        logger.info("Rows inserted (net new in table): {}", inserted)
    finally:
        conn.close()


if __name__ == "__main__":
    main()