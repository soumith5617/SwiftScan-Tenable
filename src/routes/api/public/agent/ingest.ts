import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { priorityScore, slaDueDate } from "@/lib/severity";

const payload = z.object({
  target: z.string().min(1).max(255),
  agent: z.string().max(80).default("external-agent"),
  os: z.string().max(120).optional(),
  ports: z
    .array(
      z.object({
        port: z.number().int().min(1).max(65535),
        protocol: z.string().max(10),
        service: z.string().max(60).optional(),
        banner: z.string().max(500).optional(),
      }),
    )
    .max(500)
    .default([]),
  findings: z
    .array(
      z.object({
        plugin_id: z.string().max(80),
        title: z.string().min(1).max(300),
        severity: z.number().int().min(0).max(4),
        cvss: z.number().min(0).max(10).nullable().optional(),
        cve_ids: z.array(z.string().max(30)).max(50).default([]),
        port: z.number().int().nullable().optional(),
        service: z.string().max(60).nullable().optional(),
        description: z.string().max(4000).default(""),
        solution: z.string().max(2000).default(""),
        evidence: z.string().max(4000).default(""),
      }),
    )
    .max(2000)
    .default([]),
});

async function sha256Hex(value: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const keyRateLimits = new Map<string, RateLimitEntry>();
const MAX_REQUESTS_PER_MINUTE = 60;
const WINDOW_MS = 60_000;

function checkRateLimit(keyId: string, maxRequests = MAX_REQUESTS_PER_MINUTE): boolean {
  const now = Date.now();
  const entry = keyRateLimits.get(keyId);

  if (!entry || now > entry.resetAt) {
    keyRateLimits.set(keyId, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }

  if (entry.count >= maxRequests) {
    return false;
  }

  entry.count++;
  return true;
}

/**
 * Agent ingest API. Distributed scanning agents (raw sockets, SYN/UDP sweeps,
 * OS fingerprinting, credentialed SMB/SSH checks) POST their results here with
 * an API key; results are correlated and scored exactly like native scans.
 */
export const Route = createFileRoute("/api/public/agent/ingest")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const key = request.headers.get("x-agent-key");
        if (!key || key.length < 20) return json({ error: "Missing x-agent-key" }, 401);

        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const hash = await sha256Hex(key);
        const { data: apiKey } = await supabaseAdmin
          .from("api_keys")
          .select("id, user_id")
          .eq("key_hash", hash)
          .maybeSingle();
        if (!apiKey) return json({ error: "Invalid agent key" }, 401);

        if (!checkRateLimit(apiKey.id, 60)) {
          return json(
            { error: "Rate limit exceeded (60 requests per minute). Please throttle your agent." },
            429,
          );
        }

        let body: z.infer<typeof payload>;
        try {
          body = payload.parse(await request.json());
        } catch (err) {
          return json(
            { error: "Invalid payload", detail: err instanceof Error ? err.message : "" },
            400,
          );
        }

        const userId = apiKey.user_id;
        await supabaseAdmin
          .from("api_keys")
          .update({ last_used_at: new Date().toISOString() })
          .eq("id", apiKey.id);

        // Resolve or create the asset
        let assetId: string | null = null;
        const { data: existing } = await supabaseAdmin
          .from("assets")
          .select("id")
          .eq("user_id", userId)
          .eq("target", body.target)
          .maybeSingle();
        if (existing) {
          assetId = existing.id;
          await supabaseAdmin
            .from("assets")
            .update({ last_seen: new Date().toISOString(), os: body.os ?? null })
            .eq("id", assetId);
        } else {
          const { data: created } = await supabaseAdmin
            .from("assets")
            .insert({
              user_id: userId,
              name: body.target,
              target: body.target,
              kind: "host",
              os: body.os ?? null,
              last_seen: new Date().toISOString(),
            })
            .select("id")
            .single();
          assetId = created?.id ?? null;
        }

        const counts = [0, 0, 0, 0, 0];
        for (const f of body.findings) counts[f.severity]!++;

        const { data: scan } = await supabaseAdmin
          .from("scans")
          .insert({
            user_id: userId,
            asset_id: assetId,
            name: `Agent scan — ${body.target}`,
            target: body.target,
            template: "agent",
            status: "completed",
            progress: 100,
            source: "agent",
            started_at: new Date().toISOString(),
            finished_at: new Date().toISOString(),
            stats: {
              critical: counts[4],
              high: counts[3],
              medium: counts[2],
              low: counts[1],
              info: counts[0],
              total: body.findings.length,
              open_ports: body.ports,
              agent: body.agent,
              os: body.os ?? null,
            },
          })
          .select("id")
          .single();

        const cveIds = [...new Set(body.findings.flatMap((f) => f.cve_ids))].slice(0, 500);
        const intel = new Map<string, { epss: number | null; kev: boolean; cvss: number | null }>();
        if (cveIds.length) {
          const { data: rows } = await supabaseAdmin
            .from("cve_cache")
            .select("cve_id, epss, kev, cvss")
            .in("cve_id", cveIds);
          for (const r of rows ?? [])
            intel.set(r.cve_id, { epss: r.epss, kev: r.kev, cvss: r.cvss });
        }

        const rows = body.findings.map((f) => {
          const best = f.cve_ids.map((c) => intel.get(c)).find(Boolean);
          const cvss = f.cvss ?? best?.cvss ?? null;
          return {
            user_id: userId,
            scan_id: scan?.id ?? null,
            asset_id: assetId,
            plugin_id: f.plugin_id,
            family: "agent",
            title: f.title,
            severity: f.severity,
            cvss,
            epss: best?.epss ?? null,
            kev: best?.kev ?? false,
            priority: priorityScore({
              cvss,
              severity: f.severity,
              epss: best?.epss ?? null,
              kev: best?.kev ?? false,
              confidence: "high",
            }),
            confidence: "high",
            cve_ids: f.cve_ids,
            port: f.port ?? null,
            service: f.service ?? null,
            description: f.description,
            solution: f.solution,
            evidence: f.evidence,
            state: "open",
            due_at: slaDueDate(f.severity).toISOString(),
          };
        });

        for (let i = 0; i < rows.length; i += 500) {
          await supabaseAdmin.from("findings").insert(rows.slice(i, i + 500) as never);
        }

        return json({ ok: true, scan_id: scan?.id ?? null, findings: rows.length });
      },
      OPTIONS: async () =>
        new Response(null, {
          status: 204,
          headers: {
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "POST, OPTIONS",
            "access-control-allow-headers": "content-type, x-agent-key",
          },
        }),
    },
  },
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
  });
}
