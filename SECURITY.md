# Security Policy & Hardening Guidelines

## 1. Secrets Management & Key Rotation Notice

> [!IMPORTANT]
> Because `.env` was previously included in historical repository exports, all live production credentials (Supabase URL, API Keys, Service Role keys) MUST be rotated immediately in the Supabase Dashboard before production deployment.

### Best Practices:

- Store production secrets only in deployment environment variables or secret managers (e.g. AWS Secrets Manager, Doppler, Vault).
- `.env` is ignored in `.gitignore`. Use `.env.example` as a template for local development.

---

## 2. Content Sanitization & XSS Defense

All user-facing markdown, AI copilot responses, and scanner evidence rendered through HTML components are sanitized using `DOMPurify` via `src/lib/sanitize.ts`.

- **Allowed Elements**: `strong`, `em`, `b`, `i`, `code`, `pre`, `br`, `p`, `span`, `ul`, `ol`, `li`, `table`, `thead`, `tbody`, `tr`, `th`, `td`, `h1`-`h6`, `blockquote`, `a`.
- **Blocked Elements**: Any executable scripts (`<script>`), event handlers (`onerror`, `onload`, `onclick`), frames (`<iframe>`), objects, or unauthorized data attributes are automatically stripped.

---

## 3. Database Security & Row-Level Security (RLS)

Every table in the database has PostgreSQL Row-Level Security enabled and enforced with policies scoped to `auth.uid() = user_id`:

- `assets`, `findings`, `scans`, `cve_cache`
- `asset_groups`, `asset_group_memberships`
- `host_ports`
- `risk_overrides`, `risk_history`
- `saved_filters`
- `reports`, `organization_settings`
- `api_keys`

Server functions and endpoints accessing tables bypass RLS only through `supabaseAdmin` for authorized system workflows (e.g. background scan processing, unauthenticated public agent ingestion with hashed API key verification).

---

## 4. API Rate Limiting

The public ingestion endpoints enforce sliding-window per-key rate limits:

- `POST /api/public/agent/ingest`: 60 requests/minute per key.
- `GET /api/public/v1/findings`: 120 requests/minute per key.

_(For high-throughput multi-cluster deployments, replace in-memory sliding window with an Upstash or Redis token bucket)._

---

## 5. Type Generation & Schema Sync

To regenerate TypeScript definitions from your live Supabase database and prevent type drift:

```bash
# Using Supabase CLI:
npx supabase gen types typescript --project-id <your-project-id> > src/integrations/supabase/types.ts
```
