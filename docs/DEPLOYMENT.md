# AegisScan Production Deployment Guide

## 1. Prerequisites

- **Node.js**: v20+ or v22 LTS
- **Docker & Docker Compose** (for containerized deployments)
- **Supabase PostgreSQL Database** (hosted or self-hosted)

---

## 2. Environment Variables

Create a `.env` file in the project root:

```env
# Supabase Configuration
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-public-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# Server Port
PORT=3000
NODE_ENV=production
```

---

## 3. Database Migration

Run all database migrations from `supabase/migrations/`:

```bash
# Using Supabase CLI
supabase db push

# Or apply SQL files directly via PostgreSQL client:
psql -h <db_host> -U postgres -d postgres -f supabase/migrations/20260811164303_69dcaa3a-839d-43ef-bb3a-157c51b6ac62.sql
psql -h <db_host> -U postgres -d postgres -f supabase/migrations/20260813190000_enterprise_vulnerability_schema.sql
```

---

## 4. Running with Docker Compose (Recommended)

To build and run the production container:

```bash
docker compose up -d --build
```

The application will be accessible at `http://localhost:3000`.

---

## 5. Running Standalone Node.js

```bash
# 1. Install dependencies
npm ci

# 2. Build production bundle
npm run build

# 3. Start production server
node .output/server/index.mjs
```

---

## 6. Healthchecks & Monitoring

- The server exposes a root HTTP healthcheck endpoint returning `200 OK`.
- Docker containers run automatic healthchecks every 30 seconds.
