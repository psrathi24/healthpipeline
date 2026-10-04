-- Phase 1–2 prior-auth completeness engine
-- Safe to re-run.

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

CREATE UNIQUE INDEX IF NOT EXISTS uq_prior_auth_order
  ON prior_auth_contexts (order_id);

ALTER TABLE raw_fhir_responses
  ADD COLUMN IF NOT EXISTS processed_at timestamptz;
ALTER TABLE raw_fhir_responses
  ADD COLUMN IF NOT EXISTS source text;

CREATE TABLE IF NOT EXISTS auth_required_rules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id text,
    payer_name text,
    procedure_code text NOT NULL,
    place_of_service text,
    auth_required boolean NOT NULL DEFAULT TRUE,
    source text DEFAULT 'manual',
    notes text,
    active boolean DEFAULT TRUE,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_required_scope
  ON auth_required_rules (
    COALESCE(client_id, ''),
    COALESCE(payer_name, ''),
    procedure_code,
    COALESCE(place_of_service, '')
  );

CREATE TABLE IF NOT EXISTS coverage_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source text NOT NULL,
    payer_name text,
    procedure_code text NOT NULL,
    jurisdiction text,
    citation text,
    title text,
    auth_required boolean DEFAULT TRUE,
    criteria jsonb,
    url text,
    active boolean DEFAULT TRUE,
    created_at timestamptz DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_coverage_policies
  ON coverage_policies (source, procedure_code, COALESCE(citation, ''));

CREATE TABLE IF NOT EXISTS policy_drafts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id text,
    payer_name text,
    procedure_code text,
    source_filename text,
    raw_text text,
    suggested_items jsonb NOT NULL DEFAULT '[]'::jsonb,
    template_id uuid REFERENCES package_requirement_templates(id),
    status text DEFAULT 'pending'
      CHECK (status IN ('pending', 'accepted', 'dismissed')),
    created_at timestamptz DEFAULT now(),
    reviewed_at timestamptz,
    reviewed_by uuid
);

INSERT INTO auth_required_rules (payer_name, procedure_code, auth_required, source, notes)
VALUES
  ('Aetna', '72148', TRUE, 'pa_list', 'Lumbar MRI typically requires prior auth'),
  ('Aetna', '72141', TRUE, 'pa_list', 'Cervical MRI typically requires prior auth'),
  ('UnitedHealthcare', '72148', TRUE, 'pa_list', 'Lumbar MRI typically requires prior auth'),
  ('UnitedHealthcare', '72141', TRUE, 'pa_list', 'Cervical MRI typically requires prior auth'),
  ('UnitedHealthcare', '70553', TRUE, 'pa_list', 'Brain MRI typically requires prior auth'),
  ('Medicare', '72148', TRUE, 'lcd_ncd', 'See LCD for MRI of the lumbar spine'),
  ('Medicare', '72141', TRUE, 'lcd_ncd', 'See LCD for MRI of the cervical spine'),
  ('Medicare', '70553', TRUE, 'lcd_ncd', 'See NCD/LCD for brain MRI'),
  (NULL, '73721', TRUE, 'pa_list', 'Lower extremity joint MRI commonly requires auth')
ON CONFLICT DO NOTHING;

INSERT INTO coverage_policies
  (source, payer_name, procedure_code, jurisdiction, citation, title, auth_required, url, criteria)
VALUES
  (
    'lcd', 'Medicare', '72148', 'national-sample', 'L35175',
    'MRI Lumbar Spine — sample LCD criteria for completeness matching',
    TRUE,
    'https://www.cms.gov/medicare-coverage-database',
    '[{"id":"conservative_therapy","label":"Conservative therapy documented"},{"id":"neuro_exam","label":"Neurological exam documented"}]'::jsonb
  ),
  (
    'lcd', 'Medicare', '72141', 'national-sample', 'L35175',
    'MRI Cervical Spine — sample LCD criteria',
    TRUE,
    'https://www.cms.gov/medicare-coverage-database',
    '[{"id":"conservative_therapy","label":"Conservative therapy documented"},{"id":"neuro_exam","label":"Neurological exam documented"}]'::jsonb
  ),
  (
    'ncd', 'Medicare', '70553', 'national', 'NCD 220.2',
    'Magnetic Resonance Imaging — sample NCD pointer',
    TRUE,
    'https://www.cms.gov/medicare-coverage-database/view/ncd.aspx?NCDId=164',
    '[{"id":"specialist_note","label":"Indicating specialist note"}]'::jsonb
  )
ON CONFLICT DO NOTHING;

INSERT INTO package_requirement_templates (workflow, payer_name, procedure_code, source)
SELECT 'prior_auth_completeness', NULL, NULL, 'system'
WHERE NOT EXISTS (
    SELECT 1 FROM package_requirement_templates
    WHERE workflow = 'prior_auth_completeness'
      AND payer_name IS NULL AND procedure_code IS NULL AND client_id IS NULL
);

INSERT INTO package_requirement_templates (workflow, payer_name, procedure_code, source)
SELECT 'prior_auth_completeness', 'Aetna', '72148', 'system'
WHERE NOT EXISTS (
    SELECT 1 FROM package_requirement_templates
    WHERE workflow = 'prior_auth_completeness' AND payer_name = 'Aetna' AND procedure_code = '72148'
);

INSERT INTO package_requirement_templates (workflow, payer_name, procedure_code, source)
SELECT 'prior_auth_completeness', 'UnitedHealthcare', '72148', 'system'
WHERE NOT EXISTS (
    SELECT 1 FROM package_requirement_templates
    WHERE workflow = 'prior_auth_completeness' AND payer_name = 'UnitedHealthcare' AND procedure_code = '72148'
);

INSERT INTO package_requirement_templates (workflow, payer_name, procedure_code, source)
SELECT 'prior_auth_completeness', 'Medicare', '72148', 'system'
WHERE NOT EXISTS (
    SELECT 1 FROM package_requirement_templates
    WHERE workflow = 'prior_auth_completeness' AND payer_name = 'Medicare' AND procedure_code = '72148'
);

INSERT INTO package_checklist_items (template_id, label, description, field_source, required, sort_order)
SELECT t.id, v.label, v.description, v.field_source, v.required, v.sort_order
FROM package_requirement_templates t
CROSS JOIN (
    VALUES
      ('Patient identifier', 'Patient must be linked to the order.', 'patient_id', TRUE, 0),
      ('Member ID', 'Payer member identifier from Coverage.', 'member_id', TRUE, 1),
      ('Service / planned date', 'Date the service is ordered or scheduled.', 'service_date', TRUE, 2),
      ('Procedure code', 'CPT/HCPCS for the ordered service.', 'procedure_codes', TRUE, 3),
      ('Payer name', 'Canonical payer used to apply auth rules.', 'payer_name', TRUE, 4),
      ('Diagnosis codes', 'ICD-10 supporting medical necessity.', 'diagnosis_codes', FALSE, 5),
      ('Clinical notes', 'Visit notes used as evidence.', 'clinical_notes_summary', FALSE, 6),
      ('Ordering provider NPI', 'Ordering clinician NPI.', 'ordering_provider_npi', FALSE, 7),
      ('Conservative therapy documented', 'Chart shows PT, NSAIDs, or other conservative care.', 'criterion:conservative_therapy', TRUE, 8),
      ('Neurological exam documented', 'Chart shows a neuro exam supporting imaging.', 'criterion:neuro_exam', TRUE, 9),
      ('Duration of failed conservative care', 'Notes mention 6+ weeks of conservative treatment.', 'criterion:failed_conservative_duration', FALSE, 10)
) AS v(label, description, field_source, required, sort_order)
WHERE t.workflow = 'prior_auth_completeness'
  AND NOT EXISTS (
      SELECT 1 FROM package_checklist_items i WHERE i.template_id = t.id
  );
