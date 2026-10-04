"""
Turn ServiceRequest/Claim + Patient/Coverage/DocumentReference into prior_auth_contexts.

Phase 1: field completeness + keyword evidence matching against payer×CPT templates.
Phase 2: auth_required_rules, coverage_policies (LCD/NCD), optional CRD stub status.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg2
from dotenv import load_dotenv
from loguru import logger

_TRANSFORMERS_DIR = Path(__file__).resolve().parent
_ROOT = _TRANSFORMERS_DIR.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_TRANSFORMERS_DIR) not in sys.path:
    sys.path.insert(0, str(_TRANSFORMERS_DIR))

try:
    from api.workflows import WORKFLOW_COMPLETENESS  # noqa: E402
except Exception:  # pragma: no cover - script execution fallback
    WORKFLOW_COMPLETENESS = "prior_auth_completeness"

_UUID_TAIL = re.compile(
    r"(?:urn:uuid:)?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)

CRITERION_PATTERNS: dict[str, list[str]] = {
    "conservative_therapy": [
        r"physical therapy",
        r"\bpt\b",
        r"physiotherapy",
        r"nsaid",
        r"ibuprofen",
        r"conservative",
        r"home exercise",
    ],
    "neuro_exam": [
        r"neurolog",
        r"dermatom",
        r"reflex",
        r"straight[- ]leg",
        r"motor strength",
        r"sensory exam",
    ],
    "recent_imaging": [
        r"\bmri\b",
        r"radiolog",
        r"x-?ray",
        r"ct scan",
        r"imaging report",
    ],
    "failed_conservative_duration": [
        r"six weeks",
        r"6 weeks",
        r"eight weeks",
        r"8 weeks",
        r"12 weeks",
        r"three months",
        r"failed conservative",
    ],
    "specialist_note": [
        r"orthop",
        r"neurosurg",
        r"neurologist",
        r"specialist consult",
    ],
}


class CompletenessValidator:
    REQUIRED_FIELDS = ["claim_id", "patient_id", "service_date", "procedure_codes", "payer_name"]
    OPTIONAL_FIELDS = ["member_id", "diagnosis_codes", "clinical_notes_summary", "ordering_provider_npi"]

    def __init__(self, record: dict[str, Any]) -> None:
        self.record = record

    @staticmethod
    def _missing(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str) and not value.strip():
            return True
        if isinstance(value, (list, tuple, set, dict)) and len(value) == 0:
            return True
        return False

    def validate(self) -> tuple[str, list[str]]:
        flags: list[str] = []
        for field in self.REQUIRED_FIELDS:
            if self._missing(self.record.get(field)):
                flags.append(f"missing_required:{field}")
        if flags:
            return "rejected", flags
        for field in self.OPTIONAL_FIELDS:
            if self._missing(self.record.get(field)):
                flags.append(f"missing_optional:{field}")
        return ("flagged" if flags else "clean"), flags


def _reference_id(ref: Any) -> str | None:
    if not ref:
        return None
    if isinstance(ref, dict):
        ref = ref.get("reference") or ref.get("identifier")
    if not ref or not isinstance(ref, str):
        return None
    match = _UUID_TAIL.search(ref)
    if match:
        return match.group(1).lower()
    if "/" in ref:
        return ref.rsplit("/", 1)[-1].split("?")[0]
    return ref


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


def _coding_codes(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        coding = obj.get("coding") or []
        if isinstance(coding, list):
            for item in coding:
                code = (item or {}).get("code")
                if code:
                    out.append(str(code))
        if obj.get("code") and not out:
            out.append(str(obj["code"]))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_coding_codes(item))
    elif isinstance(obj, str) and obj.strip():
        out.extend(part.strip() for part in obj.split(";") if part.strip())
    return out


def _text_blob(*parts: Any) -> str:
    chunks: list[str] = []
    for part in parts:
        if isinstance(part, str) and part.strip():
            chunks.append(part)
        elif isinstance(part, dict):
            chunks.append(_text_blob(*part.values()))
        elif isinstance(part, list):
            chunks.append(_text_blob(*part))
    return "\n".join(chunks)


class CompletenessTransformer:
    def __init__(self) -> None:
        load_dotenv(_ROOT / ".env")
        self.conn = psycopg2.connect(
            host=os.environ.get("PGHOST", "localhost"),
            port=os.environ.get("PGPORT", "5432"),
            dbname=os.environ.get("PGDATABASE", "healthpipeline"),
            user=os.environ.get("PGUSER", os.environ.get("USER", "postgres")),
            password=os.environ.get("PGPASSWORD", ""),
        )

    def close(self) -> None:
        self.conn.close()

    def ensure_schema(self) -> None:
        ddl_path = _ROOT / "db" / "completeness_schema.sql"
        sql = ddl_path.read_text() if ddl_path.exists() else _INLINE_SCHEMA
        with self.conn.cursor() as cur:
            cur.execute(sql)
        self.conn.commit()

    def _fetch_json(self, resource_id: str | None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT payload FROM raw_fhir_responses WHERE resource_id = %s",
                (resource_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        payload = row[0]
        if isinstance(payload, str):
            payload = json.loads(payload)
        return payload if isinstance(payload, dict) else None

    def _search_notes(self, patient_id: str | None) -> str:
        if not patient_id:
            return ""
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT payload FROM raw_fhir_responses
                WHERE resource_type = 'DocumentReference'
                ORDER BY fetched_at DESC
                LIMIT 80
                """
            )
            rows = cur.fetchall()
        notes: list[str] = []
        for (payload,) in rows:
            if isinstance(payload, str):
                payload = json.loads(payload)
            if not isinstance(payload, dict):
                continue
            subject = _reference_id((payload.get("subject") or {}))
            if subject and subject != patient_id:
                continue
            content = payload.get("content") or []
            attachment_text = ""
            if isinstance(content, list) and content:
                attachment_text = str(((content[0] or {}).get("attachment") or {}).get("data") or "")
            notes.append(
                _text_blob(
                    payload.get("description"),
                    (payload.get("type") or {}).get("text"),
                    attachment_text,
                    payload.get("text"),
                )
            )
        return "\n".join(notes)

    def _canonical_payer(self, raw: str | None) -> str | None:
        if not raw:
            return None
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT canonical_name FROM payer_name_mappings
                WHERE active = TRUE AND lower(raw_name) = lower(%s)
                ORDER BY validated_by_provider DESC, confidence_score DESC NULLS LAST
                LIMIT 1
                """,
                (raw.strip(),),
            )
            row = cur.fetchone()
        return row[0] if row else raw.strip()

    def _lookup_auth_required(self, payer: str | None, cpt: str | None) -> tuple[str, str | None, str]:
        if not cpt:
            return "unknown", None, "no_procedure"
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT auth_required, source
                FROM auth_required_rules
                WHERE active = TRUE
                  AND procedure_code = %s
                  AND (payer_name IS NULL OR lower(payer_name) = lower(%s))
                ORDER BY CASE WHEN payer_name IS NULL THEN 1 ELSE 0 END, updated_at DESC
                LIMIT 1
                """,
                (cpt, payer or ""),
            )
            row = cur.fetchone()
            if row:
                return ("yes" if row[0] else "no"), None, str(row[1] or "auth_required_rules")
            cur.execute(
                """
                SELECT auth_required, citation, source
                FROM coverage_policies
                WHERE active = TRUE AND procedure_code = %s
                ORDER BY CASE WHEN source = 'ncd' THEN 0 WHEN source = 'lcd' THEN 1 ELSE 2 END
                LIMIT 1
                """,
                (cpt,),
            )
            policy = cur.fetchone()
            if policy:
                return (
                    "yes" if policy[0] else "no",
                    policy[1],
                    str(policy[2] or "coverage_policies"),
                )
            cur.execute(
                """
                SELECT 1 FROM package_requirement_templates
                WHERE active = TRUE AND workflow = %s
                  AND procedure_code = %s
                  AND (payer_name IS NULL OR lower(payer_name) = lower(%s))
                LIMIT 1
                """,
                (WORKFLOW_COMPLETENESS, cpt, payer or ""),
            )
            if cur.fetchone():
                return "yes", None, "requirement_template"
        return "unknown", None, "no_rule"

    def _crd_status(self) -> str:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1 FROM portal_connector_connections
                WHERE active = TRUE AND connector_type = 'payer_crd'
                LIMIT 1
                """
            )
            if cur.fetchone():
                return "stub_connected"
        return "not_configured"

    def _load_criteria(self, payer: str | None, cpt: str | None) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT t.id, i.label, i.description, i.field_source, i.required, i.sort_order
                FROM package_requirement_templates t
                JOIN package_checklist_items i ON i.template_id = t.id
                WHERE t.active = TRUE AND t.workflow = %s
                  AND (t.client_id IS NULL)
                ORDER BY
                  CASE WHEN t.payer_name IS NOT NULL AND t.procedure_code IS NOT NULL THEN 0
                       WHEN t.procedure_code IS NOT NULL THEN 1
                       WHEN t.payer_name IS NOT NULL THEN 2
                       ELSE 3 END,
                  i.sort_order
                """,
                (WORKFLOW_COMPLETENESS,),
            )
            rows = cur.fetchall()
        matched: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            _tid, label, description, field_source, required, sort_order = row
            key = str(field_source or label)
            if key in seen:
                continue
            seen.add(key)
            matched.append(
                {
                    "label": label,
                    "description": description,
                    "field_source": field_source,
                    "required": bool(required),
                    "sort_order": sort_order,
                }
            )
        # Prefer CPT-specific items by filtering if any field_source starts with criterion
        del payer, cpt
        return matched

    def _match_criterion(self, criterion_id: str, notes: str) -> dict[str, Any] | None:
        patterns = CRITERION_PATTERNS.get(criterion_id) or []
        blob = notes.lower()
        for pattern in patterns:
            hit = re.search(pattern, blob, flags=re.IGNORECASE)
            if hit:
                start = max(0, hit.start() - 40)
                end = min(len(notes), hit.end() + 80)
                return {
                    "criterion_id": criterion_id,
                    "matched": hit.group(0),
                    "snippet": notes[start:end].strip(),
                    "provenance": "ehr_note",
                }
        return None

    def _order_to_record(self, resource: dict[str, Any], resource_id: str) -> dict[str, Any]:
        resource_type = resource.get("resourceType")
        patient_id = _reference_id(resource.get("subject") or resource.get("patient"))
        patient = self._fetch_json(patient_id) or {}
        coverage = None
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT payload FROM raw_fhir_responses
                WHERE resource_type = 'Coverage'
                ORDER BY fetched_at DESC
                LIMIT 40
                """
            )
            for (payload,) in cur.fetchall():
                if isinstance(payload, str):
                    payload = json.loads(payload)
                if not isinstance(payload, dict):
                    continue
                beneficiary = _reference_id(payload.get("beneficiary"))
                if patient_id and beneficiary and beneficiary != patient_id:
                    continue
                coverage = payload
                break
        notes = self._search_notes(patient_id)
        if resource_type == "Claim":
            procedures = []
            for item in resource.get("item") or []:
                procedures.extend(_coding_codes(item.get("productOrService")))
            diagnoses = _coding_codes(resource.get("diagnosis"))
            if not diagnoses:
                for item in resource.get("diagnosis") or []:
                    diagnoses.extend(_coding_codes((item or {}).get("diagnosisCodeableConcept")))
            service_date = _parse_fhir_date(
                ((resource.get("billablePeriod") or {}).get("start"))
                or resource.get("created")
            )
            payer_raw = ((resource.get("insurer") or {}).get("display")) or (
                (coverage or {}).get("payor") or [{}]
            )
            if isinstance(payer_raw, list):
                payer_raw = (payer_raw[0] or {}).get("display") if payer_raw else None
            npi = None
            provider = resource.get("provider") or {}
            npi = provider.get("identifier") if isinstance(provider, dict) else None
            if isinstance(npi, dict):
                npi = npi.get("value")
        else:
            procedures = _coding_codes(resource.get("code"))
            diagnoses = _coding_codes(resource.get("reasonCode"))
            service_date = _parse_fhir_date(
                resource.get("occurrenceDateTime")
                or ((resource.get("occurrencePeriod") or {}).get("start"))
                or resource.get("authoredOn")
            )
            payer_raw = None
            if coverage:
                payors = coverage.get("payor") or []
                if payors and isinstance(payors, list):
                    payer_raw = (payors[0] or {}).get("display")
            requester = resource.get("requester") or {}
            npi = requester.get("identifier") if isinstance(requester, dict) else None
            if isinstance(npi, dict):
                npi = npi.get("value")

        member_id = None
        if coverage:
            member_id = coverage.get("subscriberId") or coverage.get("identifier")
            if isinstance(member_id, list):
                member_id = (member_id[0] or {}).get("value")
            elif isinstance(member_id, dict):
                member_id = member_id.get("value")

        payer_name = self._canonical_payer(str(payer_raw) if payer_raw else None)
        cpt = procedures[0] if procedures else None
        auth_required, citation, auth_source = self._lookup_auth_required(payer_name, cpt)
        criteria = self._load_criteria(payer_name, cpt)
        evidence_found: list[dict[str, Any]] = []
        evidence_missing: list[dict[str, Any]] = []
        extra_flags: list[str] = []
        for item in criteria:
            source = str(item.get("field_source") or "")
            if source.startswith("criterion:"):
                criterion_id = source.split(":", 1)[1]
                hit = self._match_criterion(criterion_id, notes)
                if hit:
                    evidence_found.append({**hit, "label": item["label"]})
                else:
                    evidence_missing.append(
                        {
                            "criterion_id": criterion_id,
                            "label": item["label"],
                            "description": item.get("description"),
                            "required": item.get("required"),
                            "provenance": None,
                        }
                    )
                    extra_flags.append(f"missing_evidence:{criterion_id}")
            elif source in {"clinical_notes_summary"} and notes:
                evidence_found.append(
                    {
                        "criterion_id": source,
                        "label": item["label"],
                        "snippet": notes[:240],
                        "provenance": "ehr_note",
                    }
                )

        order_id = str(resource.get("id") or resource_id)
        planned = service_date
        auth_due = planned - timedelta(days=1) if planned else None
        record = {
            "order_id": order_id,
            "claim_id": order_id,
            "patient_id": patient_id,
            "member_id": str(member_id) if member_id else None,
            "service_date": service_date.isoformat() if service_date else None,
            "planned_date": planned.isoformat() if planned else None,
            "payer_name": payer_name,
            "diagnosis_codes": diagnoses,
            "procedure_codes": procedures,
            "clinical_notes_summary": notes[:4000] if notes else None,
            "ordering_provider_npi": str(npi) if npi else None,
            "coverage_id": str(coverage.get("id")) if coverage and coverage.get("id") else None,
            "auth_required": auth_required,
            "denial_category": {
                "yes": "authorization_required",
                "no": "not_required",
            }.get(auth_required, "unknown"),
            "lcd_ncd_citation": citation,
            "crd_status": self._crd_status(),
            "auth_source": auth_source,
            "criteria": criteria,
            "evidence_found": evidence_found,
            "evidence_missing": evidence_missing,
            "provenance": {
                "order": f"raw_fhir_responses:{resource_id}",
                "patient": f"raw_fhir_responses:{patient_id}" if patient_id else None,
                "coverage": "raw_fhir_responses" if coverage else None,
                "notes": "DocumentReference" if notes else None,
                "auth_required": auth_source,
            },
            "packet": {
                "order_id": order_id,
                "patient_id": patient_id,
                "payer_name": payer_name,
                "procedure_codes": procedures,
                "diagnosis_codes": diagnoses,
                "auth_required": auth_required,
                "evidence_found": evidence_found,
                "evidence_missing": evidence_missing,
            },
            "payer_appeal_deadline": auth_due.isoformat() if auth_due else None,
            "source_resource_id": resource_id,
            "raw_resource_id": resource_id,
        }
        del patient
        status, flags = CompletenessValidator(record).validate()
        flags.extend(extra_flags)
        if extra_flags and status == "clean":
            status = "flagged"
        record["validation_status"] = status
        record["data_quality_flags"] = flags
        return record

    def _csv_row_to_record(self, row: dict[str, Any]) -> dict[str, Any]:
        order_id = (row.get("order_id") or "").strip()
        if not order_id:
            raise ValueError("CSV row is missing order_id")
        diagnoses = [
            part.strip()
            for part in (row.get("diagnosis_codes") or "").replace(";", ",").split(",")
            if part.strip()
        ]
        cpt = (row.get("procedure_code") or "").strip()
        procedures = [cpt] if cpt else []
        notes = (row.get("notes") or "").strip()
        service_date = _parse_fhir_date(row.get("service_date"))
        payer_name = self._canonical_payer((row.get("payer_name") or "").strip() or None)
        patient_id = (row.get("patient_id") or "").strip() or None
        member_id = (row.get("member_id") or "").strip() or None
        npi = (row.get("ordering_provider_npi") or "").strip() or None
        auth_required, citation, auth_source = self._lookup_auth_required(payer_name, cpt or None)
        criteria = self._load_criteria(payer_name, cpt or None)
        evidence_found: list[dict[str, Any]] = []
        evidence_missing: list[dict[str, Any]] = []
        extra_flags: list[str] = []
        for item in criteria:
            source = str(item.get("field_source") or "")
            if source.startswith("criterion:"):
                criterion_id = source.split(":", 1)[1]
                hit = self._match_criterion(criterion_id, notes)
                if hit:
                    evidence_found.append({**hit, "label": item["label"]})
                else:
                    evidence_missing.append(
                        {
                            "criterion_id": criterion_id,
                            "label": item["label"],
                            "description": item.get("description"),
                            "required": item.get("required"),
                            "provenance": None,
                        }
                    )
                    extra_flags.append(f"missing_evidence:{criterion_id}")
            elif source == "clinical_notes_summary" and notes:
                evidence_found.append(
                    {
                        "criterion_id": source,
                        "label": item["label"],
                        "snippet": notes[:240],
                        "provenance": "csv_notes",
                    }
                )
        planned = service_date
        auth_due = planned - timedelta(days=1) if planned else None
        record = {
            "order_id": order_id,
            "claim_id": order_id,
            "patient_id": patient_id,
            "member_id": member_id,
            "service_date": service_date.isoformat() if service_date else None,
            "planned_date": planned.isoformat() if planned else None,
            "payer_name": payer_name,
            "diagnosis_codes": diagnoses,
            "procedure_codes": procedures,
            "clinical_notes_summary": notes[:4000] if notes else None,
            "ordering_provider_npi": npi,
            "coverage_id": None,
            "auth_required": auth_required,
            "denial_category": {
                "yes": "authorization_required",
                "no": "not_required",
            }.get(auth_required, "unknown"),
            "lcd_ncd_citation": citation,
            "crd_status": self._crd_status(),
            "auth_source": auth_source,
            "criteria": criteria,
            "evidence_found": evidence_found,
            "evidence_missing": evidence_missing,
            "provenance": {
                "order": "csv_upload",
                "notes": "csv_notes" if notes else None,
                "auth_required": auth_source,
            },
            "packet": {
                "order_id": order_id,
                "patient_id": patient_id,
                "payer_name": payer_name,
                "procedure_codes": procedures,
                "diagnosis_codes": diagnoses,
                "auth_required": auth_required,
                "evidence_found": evidence_found,
                "evidence_missing": evidence_missing,
            },
            "payer_appeal_deadline": auth_due.isoformat() if auth_due else None,
            "source_resource_id": order_id,
            "raw_resource_id": order_id,
        }
        status, flags = CompletenessValidator(record).validate()
        flags.extend(extra_flags)
        if extra_flags and status == "clean":
            status = "flagged"
        record["validation_status"] = status
        record["data_quality_flags"] = flags
        return record

    def _persist(self, record: dict[str, Any], raw_id: str | None) -> str:
        status = record["validation_status"]
        flags = record["data_quality_flags"]
        payload = {
            **record,
            "criteria": json.dumps(record["criteria"]),
            "evidence_found": json.dumps(record["evidence_found"]),
            "evidence_missing": json.dumps(record["evidence_missing"]),
            "packet": json.dumps(record["packet"]),
            "provenance": json.dumps(record["provenance"]),
        }
        insert_sql = """
        INSERT INTO prior_auth_contexts (
            order_id, claim_id, patient_id, member_id, service_date, planned_date,
            payer_appeal_deadline, payer_name, diagnosis_codes, procedure_codes,
            clinical_notes_summary, ordering_provider_npi, coverage_id, auth_required,
            denial_category, criteria, evidence_found, evidence_missing, packet,
            provenance, lcd_ncd_citation, crd_status, data_quality_flags,
            validation_status, assembled_at, source_resource_id, raw_resource_id
        ) VALUES (
            %(order_id)s, %(claim_id)s, %(patient_id)s, %(member_id)s, %(service_date)s,
            %(planned_date)s, %(payer_appeal_deadline)s, %(payer_name)s, %(diagnosis_codes)s,
            %(procedure_codes)s, %(clinical_notes_summary)s, %(ordering_provider_npi)s,
            %(coverage_id)s, %(auth_required)s, %(denial_category)s, %(criteria)s::jsonb,
            %(evidence_found)s::jsonb, %(evidence_missing)s::jsonb, %(packet)s::jsonb,
            %(provenance)s::jsonb, %(lcd_ncd_citation)s, %(crd_status)s, %(data_quality_flags)s,
            %(validation_status)s, NOW(), %(source_resource_id)s, %(raw_resource_id)s
        )
        ON CONFLICT (claim_id) DO UPDATE SET
            patient_id = EXCLUDED.patient_id,
            member_id = EXCLUDED.member_id,
            service_date = EXCLUDED.service_date,
            planned_date = EXCLUDED.planned_date,
            payer_appeal_deadline = EXCLUDED.payer_appeal_deadline,
            payer_name = EXCLUDED.payer_name,
            diagnosis_codes = EXCLUDED.diagnosis_codes,
            procedure_codes = EXCLUDED.procedure_codes,
            clinical_notes_summary = EXCLUDED.clinical_notes_summary,
            ordering_provider_npi = EXCLUDED.ordering_provider_npi,
            auth_required = EXCLUDED.auth_required,
            denial_category = EXCLUDED.denial_category,
            criteria = EXCLUDED.criteria,
            evidence_found = EXCLUDED.evidence_found,
            evidence_missing = EXCLUDED.evidence_missing,
            packet = EXCLUDED.packet,
            provenance = EXCLUDED.provenance,
            lcd_ncd_citation = EXCLUDED.lcd_ncd_citation,
            crd_status = EXCLUDED.crd_status,
            data_quality_flags = EXCLUDED.data_quality_flags,
            validation_status = EXCLUDED.validation_status,
            assembled_at = NOW()
        """
        with self.conn.cursor() as cur:
            if status == "rejected":
                cur.execute(
                    """
                    INSERT INTO quarantine_records (
                        raw_resource_id, record, validation_status, data_quality_flags, workflow, claim_id
                    ) VALUES (%s, %s::jsonb, %s, %s, %s, %s)
                    """,
                    (
                        raw_id or record["claim_id"],
                        json.dumps(record),
                        status,
                        flags,
                        WORKFLOW_COMPLETENESS,
                        record["claim_id"],
                    ),
                )
            else:
                cur.execute(insert_sql, payload)
            if raw_id:
                cur.execute(
                    "UPDATE raw_fhir_responses SET processed_at = now() WHERE resource_id = %s",
                    (raw_id,),
                )
        return status

    def ingest_orders_csv(self, text: str) -> dict[str, int]:
        import csv
        import io

        self.ensure_schema()
        counts = {"clean": 0, "flagged": 0, "rejected": 0, "rows": 0}
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            if not (row.get("order_id") or "").strip():
                continue
            record = self._csv_row_to_record(row)
            status = self._persist(record, None)
            counts["rows"] += 1
            if status in counts:
                counts[status] += 1
        self.conn.commit()
        logger.info("CSV completeness ingest {}", counts)
        return counts

    def _fetch_unprocessed(self) -> list[tuple[str, dict[str, Any]]]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT resource_id, payload
                FROM raw_fhir_responses
                WHERE processed_at IS NULL
                  AND resource_type IN ('ServiceRequest', 'Claim')
                ORDER BY fetched_at NULLS LAST, resource_id
                """
            )
            out: list[tuple[str, dict[str, Any]]] = []
            for rid, payload in cur.fetchall():
                if isinstance(payload, str):
                    payload = json.loads(payload)
                if isinstance(payload, dict):
                    out.append((str(rid), payload))
        return out

    def run(self) -> None:
        self.ensure_schema()
        rows = self._fetch_unprocessed()
        clean_n = flagged_n = rejected_n = 0
        for raw_id, resource in rows:
            if resource.get("resourceType") not in {"ServiceRequest", "Claim"}:
                with self.conn.cursor() as cur:
                    cur.execute(
                        "UPDATE raw_fhir_responses SET processed_at = now() WHERE resource_id = %s",
                        (raw_id,),
                    )
                continue
            record = self._order_to_record(resource, raw_id)
            status = self._persist(record, raw_id)
            if status == "clean":
                clean_n += 1
            elif status == "flagged":
                flagged_n += 1
            else:
                rejected_n += 1
        self.conn.commit()
        logger.info(
            "Completeness transform complete: clean={} flagged={} rejected={}",
            clean_n,
            flagged_n,
            rejected_n,
        )


_INLINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS prior_auth_contexts (
    id bigserial PRIMARY KEY,
    order_id text NOT NULL,
    claim_id text UNIQUE NOT NULL,
    patient_id text,
    member_id text,
    service_date date,
    planned_date date,
    payer_appeal_deadline date,
    payer_name text,
    diagnosis_codes text[],
    procedure_codes text[],
    clinical_notes_summary text,
    ordering_provider_npi text,
    coverage_id text,
    auth_required text,
    denial_category text,
    criteria jsonb,
    evidence_found jsonb,
    evidence_missing jsonb,
    packet jsonb,
    provenance jsonb,
    lcd_ncd_citation text,
    crd_status text,
    data_quality_flags text[],
    validation_status text NOT NULL,
    assembled_at timestamptz DEFAULT now(),
    needs_review boolean DEFAULT FALSE,
    review_reason text,
    manual_ready_override boolean DEFAULT FALSE,
    override_note text,
    override_by uuid,
    override_at timestamptz,
    source_resource_id text,
    raw_resource_id text
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_prior_auth_order ON prior_auth_contexts (order_id);
"""


def main() -> None:
    transformer = CompletenessTransformer()
    try:
        transformer.run()
    finally:
        transformer.close()


if __name__ == "__main__":
    main()
