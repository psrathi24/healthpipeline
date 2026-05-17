"""
Look up canonical code metadata from code_mappings (cached, one DB read per instance).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import psycopg2
from dotenv import load_dotenv
from loguru import logger


@dataclass(frozen=True)
class MappedCode:
    canonical_code: str
    canonical_description: str | None
    category: str | None


class CodeMapper:
    """
    Connects using ``healthpipeline/.env``, loads ``code_mappings`` once into a dict,
    then answers ``map(source_code, source_system)`` from memory.
    """

    def __init__(self) -> None:
        env_path = Path(__file__).resolve().parent.parent / ".env"
        load_dotenv(env_path)
        self._conn = psycopg2.connect(
            host=os.environ.get("PGHOST", "localhost"),
            port=os.environ.get("PGPORT", "5432"),
            dbname=os.environ.get("PGDATABASE", "healthpipeline"),
            user=os.environ.get("PGUSER", os.environ.get("USER", "postgres")),
            password=os.environ.get("PGPASSWORD", ""),
        )
        self._mapping: dict[tuple[str, str], MappedCode] = {}
        self._load_mappings()

    def close(self) -> None:
        self._conn.close()

    def _load_mappings(self) -> None:
        sql = """
        SELECT source_code, source_system, canonical_code, canonical_description, category
        FROM code_mappings;
        """
        with self._conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
        for source_code, source_system, canonical_code, description, category in rows:
            key = (str(source_system).strip(), str(source_code).strip())
            self._mapping[key] = MappedCode(
                canonical_code=str(canonical_code).strip(),
                canonical_description=None if description is None else str(description),
                category=None if category is None else str(category),
            )
        logger.info("Loaded {} code_mapping row(s) into memory", len(self._mapping))

    def map(self, source_code: str, source_system: str = "X12") -> MappedCode | None:
        key = (source_system.strip(), str(source_code).strip())
        hit = self._mapping.get(key)
        if hit is None:
            logger.warning(
                "No code_mapping for source_system={!r} source_code={!r}",
                source_system,
                source_code,
            )
        return hit


if __name__ == "__main__":
    cm = CodeMapper()
    try:
        print(cm.map("1"))
        print(cm.map("99999"))
    finally:
        cm.close()