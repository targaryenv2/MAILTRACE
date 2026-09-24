/*
# Create MailTrace phishing detection schema

1. New Tables
- `phishing_cases`: Top-level case records for each analyzed email. Stores subject, sender, risk score, status, parsed email JSON, findings, MITRE tags, relay hops, blast radius, sandbox result, and transaction hash.
- `investigation_steps`: Step-by-step trail of the agentic investigation loop. Each row is one phase (ingest, parse, auth_verify, etc.) with status, timing, summary, and detail JSON.
- `exposures`: Per-recipient exposure records (opened, clicked, submitted credentials) linked to a case.

2. Security
- Enable RLS on all three tables.
- This is a single-tenant app (no sign-in screen), so all policies use `TO anon, authenticated` with `USING (true)` / `WITH CHECK (true)` because the data is intentionally shared/public within the tool.
- 4 policies per table (SELECT, INSERT, UPDATE, DELETE).

3. Important Notes
- JSONB columns store complex nested structures (parsed email, findings, steps, relay hops, blast radius, MITRE tags, sandbox results).
- `case_number` has a unique constraint.
- `detected_at` defaults to now().
- Indexes on `status` and `risk_level` for fast queue filtering.
*/

CREATE TABLE IF NOT EXISTS phishing_cases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_number text UNIQUE NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  risk_level text NOT NULL DEFAULT 'low',
  risk_score integer NOT NULL DEFAULT 0,
  subject text NOT NULL,
  sender_display text NOT NULL,
  sender_address text NOT NULL,
  detected_at timestamptz DEFAULT now(),
  parsed_email jsonb NOT NULL DEFAULT '{}',
  findings jsonb NOT NULL DEFAULT '[]',
  relay_hops jsonb NOT NULL DEFAULT '[]',
  blast_radius jsonb NOT NULL DEFAULT '{}',
  mitre_tags jsonb NOT NULL DEFAULT '[]',
  sandbox_result jsonb,
  transaction_hash text,
  approved_by text,
  approved_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_phishing_cases_status ON phishing_cases(status);
CREATE INDEX IF NOT EXISTS idx_phishing_cases_risk_level ON phishing_cases(risk_level);
CREATE INDEX IF NOT EXISTS idx_phishing_cases_detected_at ON phishing_cases(detected_at DESC);

CREATE TABLE IF NOT EXISTS investigation_steps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid NOT NULL REFERENCES phishing_cases(id) ON DELETE CASCADE,
  step_index integer NOT NULL,
  phase text NOT NULL,
  label text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  started_at timestamptz DEFAULT now(),
  completed_at timestamptz,
  duration_ms integer,
  summary text NOT NULL DEFAULT '',
  details jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_investigation_steps_case_id ON investigation_steps(case_id);
CREATE INDEX IF NOT EXISTS idx_investigation_steps_status ON investigation_steps(status);

CREATE TABLE IF NOT EXISTS exposures (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid NOT NULL REFERENCES phishing_cases(id) ON DELETE CASCADE,
  user_email text NOT NULL,
  department text NOT NULL,
  opened boolean NOT NULL DEFAULT false,
  clicked boolean NOT NULL DEFAULT false,
  submitted_credentials boolean NOT NULL DEFAULT false,
  timestamp timestamptz
);

CREATE INDEX IF NOT EXISTS idx_exposures_case_id ON exposures(case_id);

-- RLS: phishing_cases
ALTER TABLE phishing_cases ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_cases" ON phishing_cases;
CREATE POLICY "anon_select_cases" ON phishing_cases FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_cases" ON phishing_cases;
CREATE POLICY "anon_insert_cases" ON phishing_cases FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_cases" ON phishing_cases;
CREATE POLICY "anon_update_cases" ON phishing_cases FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_cases" ON phishing_cases;
CREATE POLICY "anon_delete_cases" ON phishing_cases FOR DELETE
  TO anon, authenticated USING (true);

-- RLS: investigation_steps
ALTER TABLE investigation_steps ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_steps" ON investigation_steps;
CREATE POLICY "anon_select_steps" ON investigation_steps FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_steps" ON investigation_steps;
CREATE POLICY "anon_insert_steps" ON investigation_steps FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_steps" ON investigation_steps;
CREATE POLICY "anon_update_steps" ON investigation_steps FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_steps" ON investigation_steps;
CREATE POLICY "anon_delete_steps" ON investigation_steps FOR DELETE
  TO anon, authenticated USING (true);

-- RLS: exposures
ALTER TABLE exposures ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_exposures" ON exposures;
CREATE POLICY "anon_select_exposures" ON exposures FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_exposures" ON exposures;
CREATE POLICY "anon_insert_exposures" ON exposures FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_exposures" ON exposures;
CREATE POLICY "anon_update_exposures" ON exposures FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_exposures" ON exposures;
CREATE POLICY "anon_delete_exposures" ON exposures FOR DELETE
  TO anon, authenticated USING (true);
