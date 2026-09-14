-- healthpipeline schema
-- Pipeline tables (raw_fhir_responses, clean_denial_records, etc.) are created
-- by extractors/transformers via CREATE TABLE IF NOT EXISTS.
-- Portal auth tables below are the source of truth for the provider portal.

CREATE TABLE IF NOT EXISTS portal_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN (
        'admin',        -- practice owner, full access
        'billing',      -- billing coordinator, operational access
        'readonly'      -- auditor / IT reviewer, view only
    )),
    client_id TEXT,     -- which practice org this user belongs to
    mfa_secret TEXT,    -- TOTP secret for MFA (encrypted at rest)
    mfa_enabled BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS portal_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES portal_users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS portal_audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES portal_users(id),
    user_email TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details JSONB,
    ip_address TEXT,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES portal_users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_portal_sessions_user
  ON portal_sessions(user_id) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_audit_log_user
  ON portal_audit_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_created
  ON portal_audit_log(created_at DESC);

CREATE TABLE IF NOT EXISTS denial_contexts (
    id BIGSERIAL PRIMARY KEY,
    claim_id TEXT UNIQUE NOT NULL,
    patient_id TEXT,
    service_date DATE,
    denial_reason_code TEXT,
    denial_category TEXT,
    canonical_denial_description TEXT,
    payer_name TEXT,
    payer_appeal_deadline DATE,
    appeal_requirements JSONB,
    diagnosis_codes TEXT[],
    procedure_codes TEXT[],
    clinical_notes_summary TEXT,
    total_claim_amount NUMERIC(14, 2),
    prior_submission_history JSONB,
    data_quality_flags TEXT[],
    validation_status TEXT NOT NULL,
    assembled_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS denial_outcomes (
    id BIGSERIAL PRIMARY KEY,
    claim_id TEXT REFERENCES denial_contexts(claim_id),
    appeal_filed_at TIMESTAMPTZ,
    appeal_method TEXT,
    appeal_outcome TEXT,
    time_to_resolution_hours INTEGER,
    staff_minutes_saved NUMERIC,
    amount_recovered NUMERIC(14, 2),
    agent_used TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workflow_rules (
    id BIGSERIAL PRIMARY KEY,
    client_id TEXT,
    workflow VARCHAR(100) NOT NULL,
    rule_type VARCHAR(100) NOT NULL,
    rule_config JSONB NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS portal_vendor_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id TEXT NOT NULL,
    vendor_name TEXT NOT NULL,
    vendor_type TEXT,
    api_key_hash TEXT UNIQUE NOT NULL,
    api_key_prefix TEXT NOT NULL,
    workflows TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    last_query_at TIMESTAMPTZ,
    total_queries INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES portal_users(id)
);

CREATE INDEX IF NOT EXISTS idx_denial_contexts_deadline
  ON denial_contexts(payer_appeal_deadline ASC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_denial_outcomes_claim
  ON denial_outcomes(claim_id);
CREATE INDEX IF NOT EXISTS idx_vendor_connections_client
  ON portal_vendor_connections(client_id) WHERE is_active = TRUE;

ALTER TABLE workflow_rules
  ADD COLUMN IF NOT EXISTS editable_by_provider BOOLEAN DEFAULT FALSE;

ALTER TABLE denial_contexts
  ADD COLUMN IF NOT EXISTS needs_reprocessing BOOLEAN DEFAULT FALSE;

ALTER TABLE quarantine_records
  ADD COLUMN IF NOT EXISTS workflow TEXT DEFAULT 'prior_auth_denial',
  ADD COLUMN IF NOT EXISTS claim_id TEXT,
  ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES portal_users(id),
  ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS review_action TEXT
    CHECK (review_action IN ('approved', 'dismissed')),
  ADD COLUMN IF NOT EXISTS override_reason TEXT;

CREATE TABLE IF NOT EXISTS payer_name_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id TEXT,
    raw_name TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    canonical_payer_id TEXT,
    source TEXT DEFAULT 'auto',
    validated_by_provider BOOLEAN DEFAULT FALSE,
    validated_at TIMESTAMPTZ,
    validated_by UUID REFERENCES portal_users(id),
    confidence_score NUMERIC(3, 2) DEFAULT 1.0,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_payer_mappings_global
  ON payer_name_mappings (raw_name) WHERE client_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_payer_mappings_client
  ON payer_name_mappings (client_id, raw_name) WHERE client_id IS NOT NULL;

INSERT INTO payer_name_mappings
  (raw_name, canonical_name, source, validated_by_provider, confidence_score)
VALUES
  ('UHC', 'UnitedHealthcare', 'auto', TRUE, 1.00),
  ('BCBS', 'Blue Cross Blue Shield', 'auto', TRUE, 0.80),
  ('BCBSCA', 'Blue Cross Blue Shield of California', 'auto', TRUE, 0.90),
  ('Anthem', 'Anthem Blue Cross', 'auto', TRUE, 0.85),
  ('Aetna', 'Aetna', 'auto', TRUE, 1.00),
  ('Cigna', 'Cigna Health', 'auto', TRUE, 1.00),
  ('Humana', 'Humana', 'auto', TRUE, 1.00),
  ('Medicare', 'Medicare', 'auto', TRUE, 1.00),
  ('Medicaid', 'Medicaid', 'auto', TRUE, 1.00),
  ('Tricare', 'TRICARE', 'auto', TRUE, 1.00),
  ('KPNC', 'Kaiser Permanente Northern California', 'auto', TRUE, 0.90),
  ('KP', 'Kaiser Permanente', 'auto', TRUE, 0.75),
  ('MO_BCBS', 'Molina Healthcare', 'auto', FALSE, 0.60),
  ('CHP', 'Community Health Plan', 'auto', FALSE, 0.50)
ON CONFLICT (raw_name) WHERE client_id IS NULL DO NOTHING;

UPDATE quarantine_records
SET
  claim_id = COALESCE(claim_id, record->>'claim_id'),
  workflow = COALESCE(workflow, 'prior_auth_denial')
WHERE claim_id IS NULL OR workflow IS NULL;

ALTER TABLE denial_contexts
  ADD COLUMN IF NOT EXISTS ordering_provider_npi TEXT,
  ADD COLUMN IF NOT EXISTS needs_review BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS review_reason TEXT,
  ADD COLUMN IF NOT EXISTS manual_ready_override BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS override_note TEXT,
  ADD COLUMN IF NOT EXISTS override_by UUID REFERENCES portal_users(id),
  ADD COLUMN IF NOT EXISTS override_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_denial_contexts_readiness
  ON denial_contexts(validation_status, assembled_at);

CREATE TABLE IF NOT EXISTS package_requirement_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id TEXT,
    workflow TEXT NOT NULL,
    payer_name TEXT,
    procedure_code TEXT,
    procedure_description TEXT,
    source TEXT DEFAULT 'system',
    active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES portal_users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_package_templates_scope
  ON package_requirement_templates (
    COALESCE(client_id, ''),
    workflow,
    COALESCE(payer_name, ''),
    COALESCE(procedure_code, '')
  );

CREATE TABLE IF NOT EXISTS package_checklist_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID REFERENCES package_requirement_templates(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    description TEXT,
    field_source TEXT,
    required BOOLEAN DEFAULT TRUE,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS package_manual_checks (
    claim_id TEXT NOT NULL,
    item_id UUID NOT NULL REFERENCES package_checklist_items(id) ON DELETE CASCADE,
    confirmed_by UUID REFERENCES portal_users(id),
    confirmed_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (claim_id, item_id)
);

INSERT INTO package_requirement_templates (workflow, payer_name, procedure_code, source)
SELECT 'prior_auth_denial', NULL, NULL, 'system'
WHERE NOT EXISTS (
    SELECT 1 FROM package_requirement_templates
    WHERE workflow = 'prior_auth_denial'
      AND payer_name IS NULL
      AND procedure_code IS NULL
      AND client_id IS NULL
);

INSERT INTO package_checklist_items (template_id, label, description, field_source, required, sort_order)
SELECT t.id, v.label, v.description, v.field_source, v.required, v.sort_order
FROM package_requirement_templates t
CROSS JOIN (
    VALUES
      ('Claim identifier', 'Required to link this record to billing and EHR systems.', 'claim_id', TRUE, 0),
      ('Patient identifier', 'Required to associate the case with the patient chart.', 'patient_id', TRUE, 1),
      ('Member ID', 'Payer member identifier from coverage data.', 'member_id', TRUE, 2),
      ('Service date', 'Used to calculate appeal deadline and medical necessity window.', 'service_date', TRUE, 3),
      ('Procedure code', 'CPT/HCPCS that was denied and needs authorization.', 'procedure_codes', TRUE, 4),
      ('Payer name', 'Canonical payer used to apply appeal rules.', 'payer_name', TRUE, 5),
      ('Appeal deadline', 'Hard filing deadline for this payer.', 'payer_appeal_deadline', TRUE, 6),
      ('Denial reason code', 'Adjustment/reason code from EOB or ERA.', 'denial_reason_code', FALSE, 7),
      ('Diagnosis codes', 'ICD-10 codes supporting medical necessity.', 'diagnosis_codes', FALSE, 8),
      ('Clinical notes', 'Visit notes or medical necessity narrative.', 'clinical_notes_summary', FALSE, 9),
      ('Ordering provider NPI', 'Confirm the ordering provider on the original request.', 'provider_npi', FALSE, 10),
      ('Appeal requirements', 'Payer-specific documents required with the submission.', 'appeal_requirements', FALSE, 11),
      ('Conservative treatment documented', 'Staff must confirm conservative care is documented in the chart.', NULL, TRUE, 12)
) AS v(label, description, field_source, required, sort_order)
WHERE t.workflow = 'prior_auth_denial'
  AND t.payer_name IS NULL
  AND t.procedure_code IS NULL
  AND t.client_id IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM package_checklist_items i WHERE i.template_id = t.id
  );

INSERT INTO package_checklist_items (template_id, label, description, field_source, required, sort_order)
SELECT t.id,
       'Conservative treatment documented',
       'Staff must confirm conservative care is documented in the chart.',
       NULL,
       TRUE,
       12
FROM package_requirement_templates t
WHERE t.workflow = 'prior_auth_denial'
  AND t.payer_name IS NULL
  AND t.procedure_code IS NULL
  AND t.client_id IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM package_checklist_items i
      WHERE i.template_id = t.id
        AND i.label = 'Conservative treatment documented'
  );

CREATE TABLE IF NOT EXISTS portal_clients (
    id TEXT PRIMARY KEY,
    practice_name TEXT,
    baa_acknowledged_at TIMESTAMPTZ,
    baa_acknowledged_by UUID REFERENCES portal_users(id),
    payer_mappings_reviewed_at TIMESTAMPTZ,
    onboarding_complete_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO portal_clients (id, practice_name)
SELECT DISTINCT client_id, 'Demo Practice'
FROM portal_users
WHERE client_id IS NOT NULL
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS portal_connector_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    category TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    encrypted_credentials TEXT,
    workflows TEXT[] NOT NULL DEFAULT '{}',
    custom_instructions TEXT,
    notify_on_failure BOOLEAN DEFAULT FALSE,
    notify_email TEXT,
    active BOOLEAN DEFAULT TRUE,
    last_tested_at TIMESTAMPTZ,
    last_test_success BOOLEAN,
    last_test_error TEXT,
    last_successful_run_at TIMESTAMPTZ,
    disconnected_at TIMESTAMPTZ,
    disconnected_reason TEXT,
    created_by UUID REFERENCES portal_users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_portal_connectors_active
  ON portal_connector_connections (client_id, connector_type)
  WHERE active = TRUE;

CREATE TABLE IF NOT EXISTS file_upload_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id TEXT NOT NULL,
    connection_id UUID REFERENCES portal_connector_connections(id),
    original_filename TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    file_type TEXT NOT NULL,
    workflow TEXT NOT NULL,
    description TEXT,
    file_size_bytes BIGINT,
    status TEXT DEFAULT 'processing'
      CHECK (status IN ('processing','complete','failed')),
    records_extracted INTEGER,
    error_message TEXT,
    uploaded_by UUID REFERENCES portal_users(id),
    uploaded_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
