"""
Transform raw ExplanationOfBenefit JSON from raw_fhir_responses into
clean_denial_records or quarantine_records.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

import psycopg2
from dotenv import load_dotenv
from loguru import logger

_TRANSFORMERS_DIR = Path(__file__).resolve().parent
if str(_TRANSFORMERS_DIR) not in sys.path:
    sys.path.insert(0, str(_TRANSFORMERS_DIR))

from code_mapper import CodeMapper, MappedCode  # noqa: E402
from validator import DenialRecordValidator  # noqa: E402

_UUID_TAIL = re.compile(
    r"(?:urn:uuid:)?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)


def _reference_id(ref: Any) -> str | None:
    if not ref:
        return None
    s = ref if isinstance(ref, str) else ref.get("reference") or ref.get("identifier")
    if not s or not isinstance(s, str):
        return None
    m = _UUID_TAIL.search(s)
    if m:
        return m.group(1).lower()
    if "/" in s:
        return s.rsplit("/", 1)[-1].split("?")[0]
    return s


def _parse_fhir_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        pass
    if len(value) >= 10 and value[4] == "-" and value[7] == "-":
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None
    return None


def _service_date(eob: dict[str, Any]) -> date | None:
    bp = eob.get("billablePeriod") or {}
    d = _parse_fhir_date(bp.get("start"))
    if d:
        return d
    d = _parse_fhir_date(eob.get("created"))
    if d:
        return d
    for item in eob.get("item") or []:
        sp = item.get("servicedPeriod") or {}
        d = _parse_fhir_date(sp.get("start")) or _parse_fhir_date(sp.get("end"))
        if d:
            return d
        sd = item.get("servicedDate")
        if sd and isinstance(sd, str):
            d = _parse_fhir_date(sd)
            if d:
                return d
    return None


def _claim_id(eob: dict[str, Any]) -> str | None:
    claim = eob.get("claim") or {}
    cid = _reference_id(claim.get("reference"))
    if cid:
        return cid
    for ident in eob.get("identifier") or []:
        sys = ident.get("system", "")
        if "clm_id" in sys or "claim" in sys.lower():
            v = ident.get("value")
            if v:
                return str(v)
    rid = eob.get("id")
    return str(rid) if rid else None


def _payer_name(eob: dict[str, Any]) -> str | None:
    ins = eob.get("insurer") or {}
    if ins.get("display"):
        return str(ins["display"])
    if ins.get("reference"):
        return str(ins["reference"])
    for row in eob.get("insurance") or []:
        cov = row.get("coverage") or {}
        if cov.get("display"):
            return str(cov["display"])
    for c in eob.get("contained") or []:
        if c.get("resourceType") == "Coverage":
            for p in c.get("payor") or []:
                if p.get("display"):
                    return str(p["display"])
            t = c.get("type") or {}
            if t.get("text"):
                return str(t["text"])
    return None


def _submitted_total(eob: dict[str, Any]) -> float | None:
    for t in eob.get("total") or []:
        cat = t.get("category") or {}
        codings = cat.get("coding") or []
        for c in codings:
            code = (c.get("code") or "").lower()
            disp = (c.get("display") or "").lower()
            if "submitted" in code or "submitted" in disp:
                amt = t.get("amount") or {}
                if "value" in amt:
                    return float(amt["value"])
        text = (cat.get("text") or "").lower()
        if "submitted" in text:
            amt = t.get("amount") or {}
            if "value" in amt:
                return float(amt["value"])
    if eob.get("total"):
        amt = eob["total"][0].get("amount") or {}
        if "value" in amt:
            return float(amt["value"])
    return None


def _denial_reason_code(eob: dict[str, Any]) -> str | None:
    parts: list[str] = []
    for err in eob.get("error") or []:
        for c in err.get("coding") or []:
            if c.get("code"):
                parts.append(str(c["code"]))
    for item in eob.get("item") or []:
        for adj in item.get("adjudication") or []:
            for r in adj.get("reason") or []:
                for c in r.get("coding") or []:
                    if c.get("code"):
                        parts.append(str(c["code"]))
            ro = adj.get("reviewOutcome")
            if isinstance(ro, str) and ro.strip():
                parts.append(ro.strip())
    if parts:
        return "; ".join(dict.fromkeys(parts))
    return None


def _diagnosis_codes(eob: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for d in eob.get("diagnosis") or []:
        cc = d.get("diagnosisCodeableConcept") or {}
        for coding in cc.get("coding") or []:
            code = coding.get("code")
            if code:
                out.append(str(code))
    for si in eob.get("supportingInfo") or []:
        vcc = si.get("valueCodeableConcept") or {}
        for coding in vcc.get("coding") or []:
            code = coding.get("code")
            if code:
                out.append(str(code))
    return list(dict.fromkeys(out))


def _procedure_codes(eob: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for item in eob.get("item") or []:
        ps = item.get("productOrService") or {}
        for coding in ps.get("coding") or []:
            code = coding.get("code")
            if code:
                out.append(str(code))
    return list(dict.fromkeys(out))


def eob_to_denial_record(eob: dict[str, Any]) -> dict[str, Any]:
    patient = _reference_id((eob.get("patient") or {}).get("reference"))
    svc = _service_date(eob)
    return {
        "eob_id": eob.get("id"),
        "claim_id": _claim_id(eob),
        "patient_id": patient,
        "service_date": svc.isoformat() if svc else None,
        "denial_reason_code": _denial_reason_code(eob),
        "payer_name": _payer_name(eob),
        "total_claim_amount": _submitted_total(eob),
        "diagnosis_codes": _diagnosis_codes(eob),
        "procedure_codes": _procedure_codes(eob),
    }


class EOBTransformer:
    """Read unprocessed EOB payloads, validate, map codes, route to clean or quarantine."""

    def __init__(self, mapper: CodeMapper | None = None) -> None:
        self._root = Path(__file__).resolve().parent.parent
        load_dotenv(self._root / ".env")
        self.conn = psycopg2.connect(
            host=os.environ.get("PGHOST", "localhost"),
            port=os.environ.get("PGPORT", "5432"),
            dbname=os.environ.get("PGDATABASE", "healthpipeline"),
            user=os.environ.get("PGUSER", os.environ.get("USER", "postgres")),
            password=os.environ.get("PGPASSWORD", ""),
        )
        self._own_mapper = mapper is None
        self.mapper = mapper or CodeMapper()

    def close(self) -> None:
        if self._own_mapper:
            self.mapper.close()
        self.conn.close()

    def ensure_schema(self) -> None:
        ddl = """
        ALTER TABLE raw_fhir_responses
            ADD COLUMN IF NOT EXISTS processed_at timestamptz;

        CREATE TABLE IF NOT EXISTS clean_denial_records (
            id bigserial PRIMARY KEY,
            raw_resource_id text NOT NULL,
            eob_id text,
            claim_id text,
            patient_id text,
            service_date date,
            denial_reason_code text,
            canonical_denial_code text,
            canonical_denial_description text,
            denial_category text,
            payer_name text,
            total_claim_amount numeric(14, 2),
            diagnosis_codes text[],
            procedure_codes text[],
            validation_status text NOT NULL,
            data_quality_flags text[],
            created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS quarantine_records (
            id bigserial PRIMARY KEY,
            raw_resource_id text NOT NULL,
            record jsonb NOT NULL,
            validation_status text NOT NULL,
            data_quality_flags text[],
            created_at timestamptz NOT NULL DEFAULT now()
        );
        """
        with self.conn.cursor() as cur:
            cur.execute(ddl)
        self.conn.commit()

    def _fetch_unprocessed(self) -> list[tuple[str, dict[str, Any]]]:
        sql = """
        SELECT resource_id, payload
        FROM raw_fhir_responses
        WHERE processed_at IS NULL
          AND resource_type = 'ExplanationOfBenefit'
        ORDER BY fetched_at NULLS LAST, resource_id;
        """
        out: list[tuple[str, dict[str, Any]]] = []
        with self.conn.cursor() as cur:
            cur.execute(sql)
            for rid, payload in cur.fetchall():
                if isinstance(payload, str):
                    payload = json.loads(payload)
                if not isinstance(payload, dict):
                    continue
                out.append((str(rid), payload))
        return out

    def _mark_processed(self, resource_id: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE raw_fhir_responses SET processed_at = now() WHERE resource_id = %s",
                (resource_id,),
            )

    @staticmethod
    def _first_code_token(codes: str | None) -> str | None:
        if not codes:
            return None
        first = codes.split(";", 1)[0].strip()
        return first or None

    def _apply_code_map(
        self, denial_code: str | None
    ) -> tuple[str | None, str | None, str | None, str | None]:
        """Returns (lookup_token, canonical_code, canonical_description, category)."""
        token = self._first_code_token(denial_code)
        if not token:
            return None, None, None, None
        hit: MappedCode | None = self.mapper.map(token, "X12")
        if hit is None:
            return token, None, None, None
        return token, hit.canonical_code, hit.canonical_description, hit.category

    def run(self) -> None:
        self.ensure_schema()
        rows = self._fetch_unprocessed()
        clean_n = flagged_n = rejected_n = 0

        insert_clean = """
        INSERT INTO clean_denial_records (
            raw_resource_id, eob_id, claim_id, patient_id, service_date,
            denial_reason_code, canonical_denial_code, canonical_denial_description,
            denial_category, payer_name, total_claim_amount,
            diagnosis_codes, procedure_codes, validation_status, data_quality_flags
        ) VALUES (
            %s, %s, %s, %s, %s::date, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        );
        """
        insert_quarantine = """
        INSERT INTO quarantine_records (
            raw_resource_id, record, validation_status, data_quality_flags
        ) VALUES (%s, %s::jsonb, %s, %s);
        """

        for raw_id, eob in rows:
            if eob.get("resourceType") != "ExplanationOfBenefit":
                self._mark_processed(raw_id)
                continue

            flat = eob_to_denial_record(eob)
            status, flags = DenialRecordValidator(flat).validate()

            _tok, canon_code, canon_desc, denial_cat = self._apply_code_map(
                flat.get("denial_reason_code")
            )

            if status == "rejected":
                with self.conn.cursor() as cur:
                    cur.execute(
                        insert_quarantine,
                        (raw_id, json.dumps(flat), status, flags),
                    )
                rejected_n += 1
            else:
                svc = flat.get("service_date")
                with self.conn.cursor() as cur:
                    cur.execute(
                        insert_clean,
                        (
                            raw_id,
                            flat.get("eob_id"),
                            flat.get("claim_id"),
                            flat.get("patient_id"),
                            svc,
                            flat.get("denial_reason_code"),
                            canon_code,
                            canon_desc,
                            denial_cat,
                            flat.get("payer_name"),
                            flat.get("total_claim_amount"),
                            flat.get("diagnosis_codes") or [],
                            flat.get("procedure_codes") or [],
                            status,
                            flags,
                        ),
                    )
                if status == "clean":
                    clean_n += 1
                else:
                    flagged_n += 1

            self._mark_processed(raw_id)

        self.conn.commit()
        logger.info(
            "EOB transform complete: clean={}, flagged={}, rejected={}",
            clean_n,
            flagged_n,
            rejected_n,
        )


def main() -> None:
    t = EOBTransformer()
    try:
        t.run()
    finally:
        t.close()


if __name__ == "__main__":
    main()