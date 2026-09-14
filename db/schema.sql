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
