CREATE TABLE public.schedules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  asset_id uuid REFERENCES public.assets(id) ON DELETE SET NULL,
  name text NOT NULL,
  target text NOT NULL,
  template text NOT NULL DEFAULT 'basic_network_scan',
  cadence text NOT NULL DEFAULT 'daily',
  enabled boolean NOT NULL DEFAULT true,
  next_run_at timestamptz NOT NULL DEFAULT now(),
  last_run_at timestamptz,
  last_scan_id uuid,
  runs integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.schedules TO authenticated;
GRANT ALL ON public.schedules TO service_role;
ALTER TABLE public.schedules ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own schedules" ON public.schedules FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE INDEX schedules_due_idx ON public.schedules (enabled, next_run_at);

CREATE TABLE public.integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  kind text NOT NULL DEFAULT 'webhook',
  name text NOT NULL,
  endpoint text NOT NULL,
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  min_severity integer NOT NULL DEFAULT 3,
  enabled boolean NOT NULL DEFAULT true,
  last_status text,
  last_delivery_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.integrations TO authenticated;
GRANT ALL ON public.integrations TO service_role;
ALTER TABLE public.integrations ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own integrations" ON public.integrations FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE TABLE public.integration_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  integration_id uuid REFERENCES public.integrations(id) ON DELETE CASCADE,
  finding_id uuid,
  status text NOT NULL DEFAULT 'pending',
  http_status integer,
  detail text,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT ON public.integration_deliveries TO authenticated;
GRANT ALL ON public.integration_deliveries TO service_role;
ALTER TABLE public.integration_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own deliveries read" ON public.integration_deliveries FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "own deliveries write" ON public.integration_deliveries FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE INDEX integration_deliveries_created_idx ON public.integration_deliveries (user_id, created_at DESC);

CREATE TABLE public.wasm_plugins (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  plugin_id text NOT NULL,
  name text NOT NULL,
  family text NOT NULL DEFAULT 'custom',
  description text NOT NULL DEFAULT '',
  severity integer NOT NULL DEFAULT 2,
  version text NOT NULL DEFAULT '1.0.0',
  enabled boolean NOT NULL DEFAULT true,
  wasm_base64 text NOT NULL,
  size_bytes integer NOT NULL DEFAULT 0,
  last_run_at timestamptz,
  last_result text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, plugin_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.wasm_plugins TO authenticated;
GRANT ALL ON public.wasm_plugins TO service_role;
ALTER TABLE public.wasm_plugins ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own plugins" ON public.wasm_plugins FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE TABLE public.asset_changes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  asset_id uuid REFERENCES public.assets(id) ON DELETE CASCADE,
  scan_id uuid,
  kind text NOT NULL,
  summary text NOT NULL,
  before_value jsonb NOT NULL DEFAULT '{}'::jsonb,
  after_value jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, DELETE ON public.asset_changes TO authenticated;
GRANT ALL ON public.asset_changes TO service_role;
ALTER TABLE public.asset_changes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own changes" ON public.asset_changes FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE INDEX asset_changes_created_idx ON public.asset_changes (user_id, created_at DESC);

CREATE TABLE public.ai_insights (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  finding_id uuid,
  kind text NOT NULL DEFAULT 'remediation',
  content text NOT NULL,
  model text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, DELETE ON public.ai_insights TO authenticated;
GRANT ALL ON public.ai_insights TO service_role;
ALTER TABLE public.ai_insights ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own insights" ON public.ai_insights FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE INDEX ai_insights_finding_idx ON public.ai_insights (finding_id, kind);