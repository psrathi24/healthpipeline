from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict


class DenialRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    claim_id: str | None = None
    patient_id: str | None = None
    service_date: date | None = None
    denial_reason_code: str | None = None
    canonical_denial_code: str | None = None
    canonical_denial_description: str | None = None
    denial_category: str | None = None
    payer_name: str | None = None
    total_claim_amount: float | None = None
    diagnosis_codes: list[str] = []
    procedure_codes: list[str] = []
    validation_status: str
    data_quality_flags: list[str] = []