CREATE TABLE public.workers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  name text NOT NULL,
  region text NOT NULL DEFAULT 'global',
  kind text NOT NULL DEFAULT 'rust',
  version text,
  capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'offline',
  max_concurrency integer NOT NULL DEFAULT 4,
  jobs_completed integer NOT NULL DEFAULT 0,
  last_heartbeat timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.workers TO authenticated;
GRANT ALL ON public.workers TO service_role;
ALTER TABLE public.workers ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own workers" ON public.workers FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE TABLE public.scan_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  scan_id uuid REFERENCES public.scans(id) ON DELETE CASCADE,
  worker_id uuid REFERENCES public.workers(id) ON DELETE SET NULL,
  region text NOT NULL DEFAULT 'any',
  target text NOT NULL,
  template text NOT NULL DEFAULT 'basic_network',
  status text NOT NULL DEFAULT 'queued',
  attempts integer NOT NULL DEFAULT 0,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  error text,
  claimed_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scan_jobs TO authenticated;
GRANT ALL ON public.scan_jobs TO service_role;
ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own scan jobs" ON public.scan_jobs FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE INDEX scan_jobs_queue_idx ON public.scan_jobs (status, region, created_at);

ALTER TABLE public.scans
  ADD COLUMN worker_id uuid REFERENCES public.workers(id) ON DELETE SET NULL,
  ADD COLUMN region text NOT NULL DEFAULT 'control-plane',
  ADD COLUMN mode text NOT NULL DEFAULT 'full',
  ADD COLUMN baseline_scan_id uuid REFERENCES public.scans(id) ON DELETE SET NULL;

ALTER TABLE public.findings
  ADD COLUMN verifications text[] NOT NULL DEFAULT '{}'::text[],
  ADD COLUMN is_new boolean NOT NULL DEFAULT true;