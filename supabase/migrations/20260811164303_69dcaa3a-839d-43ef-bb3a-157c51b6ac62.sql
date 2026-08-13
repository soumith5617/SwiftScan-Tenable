-- roles
create type public.app_role as enum ('owner','admin','analyst','viewer');

create table public.profiles (
  id uuid primary key,
  email text,
  full_name text,
  created_at timestamptz not null default now()
);
grant select, insert, update on public.profiles to authenticated;
grant all on public.profiles to service_role;
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for select to authenticated using (auth.uid() = id);
create policy "update own profile" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);
create policy "insert own profile" on public.profiles for insert to authenticated with check (auth.uid() = id);

create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  role public.app_role not null,
  created_at timestamptz not null default now(),
  unique (user_id, role)
);
grant select on public.user_roles to authenticated;
grant all on public.user_roles to service_role;
alter table public.user_roles enable row level security;
create policy "read own roles" on public.user_roles for select to authenticated using (auth.uid() = user_id);

create or replace function public.has_role(_user_id uuid, _role public.app_role)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role = _role)
$$;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email,'@',1)))
  on conflict (id) do nothing;
  insert into public.user_roles (user_id, role) values (new.id, 'owner')
  on conflict (user_id, role) do nothing;
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

-- assets
create table public.assets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  name text not null,
  target text not null,
  kind text not null default 'web',
  criticality text not null default 'medium',
  tags text[] not null default '{}',
  os text,
  technologies jsonb not null default '[]'::jsonb,
  internet_facing boolean not null default true,
  risk_score numeric not null default 0,
  first_seen timestamptz not null default now(),
  last_seen timestamptz,
  created_at timestamptz not null default now()
);
grant select, insert, update, delete on public.assets to authenticated;
grant all on public.assets to service_role;
alter table public.assets enable row level security;
create policy "own assets" on public.assets for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create index assets_user_idx on public.assets(user_id);

-- scans
create table public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  asset_id uuid references public.assets(id) on delete set null,
  name text not null,
  template text not null default 'web_audit',
  target text not null,
  status text not null default 'queued',
  progress int not null default 0,
  current_step text,
  source text not null default 'builtin',
  stats jsonb not null default '{}'::jsonb,
  error text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now()
);
grant select, insert, update, delete on public.scans to authenticated;
grant all on public.scans to service_role;
alter table public.scans enable row level security;
create policy "own scans" on public.scans for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create index scans_user_idx on public.scans(user_id, created_at desc);

-- findings
create table public.findings (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  scan_id uuid references public.scans(id) on delete cascade,
  asset_id uuid references public.assets(id) on delete cascade,
  plugin_id text not null,
  family text not null default 'general',
  title text not null,
  severity int not null default 0,
  cvss numeric,
  cvss_vector text,
  epss numeric,
  kev boolean not null default false,
  priority numeric not null default 0,
  confidence text not null default 'medium',
  cve_ids text[] not null default '{}',
  cwe text,
  attack_tactics text[] not null default '{}',
  port int,
  service text,
  description text,
  solution text,
  evidence text,
  refs jsonb not null default '[]'::jsonb,
  state text not null default 'open',
  assigned_to text,
  due_at timestamptz,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now()
);
grant select, insert, update, delete on public.findings to authenticated;
grant all on public.findings to service_role;
alter table public.findings enable row level security;
create policy "own findings" on public.findings for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create index findings_user_idx on public.findings(user_id, severity desc, priority desc);
create index findings_scan_idx on public.findings(scan_id);
create index findings_asset_idx on public.findings(asset_id);

-- cve intelligence cache (shared)
create table public.cve_cache (
  cve_id text primary key,
  description text,
  severity int not null default 0,
  cvss numeric,
  cvss_vector text,
  epss numeric,
  kev boolean not null default false,
  kev_due_date date,
  cwe text,
  vendor text,
  product text,
  published timestamptz,
  refs jsonb not null default '[]'::jsonb,
  synced_at timestamptz not null default now()
);
grant select on public.cve_cache to authenticated;
grant all on public.cve_cache to service_role;
alter table public.cve_cache enable row level security;
create policy "read cve cache" on public.cve_cache for select to authenticated using (true);
create index cve_kev_idx on public.cve_cache(kev);
create index cve_pub_idx on public.cve_cache(published desc);

-- audit log
create table public.audit_log (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  action text not null,
  entity text,
  entity_id text,
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
grant select, insert on public.audit_log to authenticated;
grant all on public.audit_log to service_role;
alter table public.audit_log enable row level security;
create policy "own audit read" on public.audit_log for select to authenticated using (auth.uid() = user_id);
create policy "own audit write" on public.audit_log for insert to authenticated with check (auth.uid() = user_id);
create index audit_user_idx on public.audit_log(user_id, created_at desc);

-- api keys for external agents
create table public.api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  name text not null,
  prefix text not null,
  key_hash text not null,
  last_used_at timestamptz,
  created_at timestamptz not null default now()
);
grant select, insert, delete on public.api_keys to authenticated;
grant all on public.api_keys to service_role;
alter table public.api_keys enable row level security;
create policy "own api keys" on public.api_keys for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);