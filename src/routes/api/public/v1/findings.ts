import { createFileRoute } from "@tanstack/react-router";

export async function sha256Hex(value: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const keyRateLimits = new Map<string, RateLimitEntry>();
const MAX_REQUESTS_PER_MINUTE = 120;
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

export async function authenticate(request: Request) {
  const key = request.headers.get("x-api-key") ?? request.headers.get("x-agent-key") ?? "";
  if (!key || key.length < 20)
    return { error: Response.json({ error: "Missing X-API-Key" }, { status: 401 }) };
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  const { data } = await supabaseAdmin
    .from("api_keys")
    .select("id, user_id")
    .eq("key_hash", await sha256Hex(key))
    .maybeSingle();
  if (!data) return { error: Response.json({ error: "Invalid API key" }, { status: 401 }) };

  if (!checkRateLimit(data.id, 120)) {
    return {
      error: Response.json(
        { error: "Rate limit exceeded (120 requests per minute)" },
        { status: 429 },
      ),
    };
  }

  await supabaseAdmin
    .from("api_keys")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", data.id);
  return { userId: data.user_id, supabase: supabaseAdmin };
}

const clamp = (v: string | null, def: number, max: number) =>
  Math.min(max, Math.max(1, Number.parseInt(v ?? "", 10) || def));

/** GET /api/public/v1/findings — paginated, filterable finding export. */
export const Route = createFileRoute("/api/public/v1/findings")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const auth = await authenticate(request);
        if ("error" in auth) return auth.error;

        const url = new URL(request.url);
        const limit = clamp(url.searchParams.get("limit"), 100, 1000);
        const offset = Math.max(0, Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0);
        const minSeverity = Math.min(
          4,
          Math.max(0, Number.parseInt(url.searchParams.get("min_severity") ?? "0", 10) || 0),
        );
        const state = url.searchParams.get("state");
        const kev = url.searchParams.get("kev");

        let query = auth.supabase
          .from("findings")
          .select(
            "id, plugin_id, family, title, severity, cvss, epss, kev, priority, confidence, cve_ids, cwe, port, service, state, due_at, first_seen, last_seen, asset_id, scan_id",
            { count: "exact" },
          )
          .eq("user_id", auth.userId)
          .gte("severity", minSeverity)
          .order("priority", { ascending: false })
          .range(offset, offset + limit - 1);

        if (state) query = query.eq("state", state);
        if (kev === "true") query = query.eq("kev", true);

        const { data, count, error } = await query;
        if (error) return Response.json({ error: error.message }, { status: 500 });

        return Response.json(
          { data, pagination: { limit, offset, total: count ?? 0 } },
          { headers: { "cache-control": "no-store" } },
        );
      },
    },
  },
});
