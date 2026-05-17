from __future__ import annotations

from typing import Any


class DenialRecordValidator:
    REQUIRED_FIELDS = [
        "claim_id",
        "patient_id",
        "service_date"
    ]
    OPTIONAL_FIELDS = [
        "denial_reason_code",
        "payer_name", 
        "total_claim_amount",
        "diagnosis_codes",
        "procedure_codes",
    ]

    def __init__(self, record: dict[str, Any]) -> None:
        self.record = record

    @staticmethod
    def _is_missing(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str) and not value.strip():
            return True
        if isinstance(value, (list, tuple, set, dict)) and len(value) == 0:
            return True
        return False

    def validate(self) -> tuple[str, list[str]]:
        """
        Returns (status, data_quality_flags).

        status:
          - 'rejected' if any required field is missing/empty
          - 'flagged' if all required present but any optional missing/empty
          - 'clean' if required and optional are all present/non-empty
        """
        flags: list[str] = []

        for field in self.REQUIRED_FIELDS:
            if self._is_missing(self.record.get(field)):
                flags.append(f"missing_required:{field}")

        if flags:
            return "rejected", flags

        for field in self.OPTIONAL_FIELDS:
            if self._is_missing(self.record.get(field)):
                flags.append(f"missing_optional:{field}")

        if flags:
            return "flagged", flags

        return "clean", []