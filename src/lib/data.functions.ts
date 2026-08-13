import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

export const getDashboard = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const [findings, assets, scans, intel] = await Promise.all([
      supabase
        .from("findings")
        .select("id, severity, state, kev, priority, title, due_at, created_at, asset_id, cve_ids")
        .eq("user_id", userId)
        .limit(2000),
      supabase
        .from("assets")
        .select("id, name, target, risk_score, criticality, last_seen")
        .eq("user_id", userId),
      supabase
        .from("scans")
        .select("id, name, target, status, progress, current_step, stats, created_at, finished_at")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(8),
      supabase.from("cve_cache").select("cve_id", { count: "exact", head: true }),
    ]);

    const rows = findings.data ?? [];
    const open = rows.filter((f) => f.state === "open");
    const counts = [0, 0, 0, 0, 0];
    for (const f of open) counts[Math.min(4, Math.max(0, f.severity))]!++;
    const now = Date.now();

    return {
      severity: {
        info: counts[0]!,
        low: counts[1]!,
        medium: counts[2]!,
        high: counts[3]!,
        critical: counts[4]!,
      },
      totals: {
        findings: rows.length,
        open: open.length,
        fixed: rows.filter((f) => f.state === "fixed").length,
        accepted: rows.filter((f) => f.state === "accepted").length,
        kev: open.filter((f) => f.kev).length,
        overdue: open.filter((f) => f.due_at && new Date(f.due_at).getTime() < now).length,
        assets: assets.data?.length ?? 0,
        cves: intel.count ?? 0,
      },
      topRisks: [...open].sort((a, b) => b.priority - a.priority).slice(0, 8),
      assets: (assets.data ?? []).sort((a, b) => b.risk_score - a.risk_score).slice(0, 6),
      scans: scans.data ?? [],
      trend: buildTrend(rows),
    };
  });

function buildTrend(rows: { created_at: string; severity: number }[]) {
  const days: { day: string; total: number; critical: number }[] = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86_400_000);
    const key = d.toISOString().slice(0, 10);
    const same = rows.filter((r) => r.created_at.slice(0, 10) === key);
    days.push({
      day: key.slice(5),
      total: same.length,
      critical: same.filter((r) => r.severity >= 4).length,
    });
  }
  return days;
}

/* ---------------------------------- assets --------------------------------- */

export const listAssets = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data } = await context.supabase
      .from("assets")
      .select("*")
      .eq("user_id", context.userId)
      .order("risk_score", { ascending: false });
    const { data: findings } = await context.supabase
      .from("findings")
      .select("asset_id, severity, state")
      .eq("user_id", context.userId)
      .eq("state", "open");
    return (data ?? []).map((a) => {
      const mine = (findings ?? []).filter((f) => f.asset_id === a.id);
      return {
        ...a,
        openFindings: mine.length,
        critical: mine.filter((f) => f.severity >= 4).length,
        high: mine.filter((f) => f.severity === 3).length,
      };
    });
  });

const assetInput = z.object({
  name: z.string().min(1).max(120),
  target: z.string().min(1).max(255),
  kind: z.enum(["web", "host", "api", "cloud", "container"]).default("web"),
  criticality: z.enum(["low", "medium", "high", "critical"]).default("medium"),
  internet_facing: z.boolean().default(true),
  tags: z.array(z.string().max(30)).max(10).default([]),
});

export const createAsset = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => assetInput.parse(d))
  .handler(async ({ data, context }) => {
    const { data: row, error } = await context.supabase
      .from("assets")
      .insert({ ...data, user_id: context.userId })
      .select("*")
      .single();
    if (error) throw new Error(error.message);
    return row;
  });

export const deleteAsset = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    await context.supabase.from("assets").delete().eq("id", data.id).eq("user_id", context.userId);
    return { ok: true };
  });

/* ---------------------------------- scans ---------------------------------- */

export const listScans = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data } = await context.supabase
      .from("scans")
      .select("*")
      .eq("user_id", context.userId)
      .order("created_at", { ascending: false })
      .limit(100);
    return data ?? [];
  });

const scanInput = z.object({
  name: z.string().min(1).max(120),
  target: z.string().min(1).max(255),
  template: z.string().min(1).max(60),
  asset_id: z.string().uuid().nullable().optional(),
  createAsset: z.boolean().default(true),
});

export const createScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => scanInput.parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    let assetId = data.asset_id ?? null;

    if (!assetId && data.createAsset) {
      const host = data.target.replace(/^https?:\/\//, "").split("/")[0]!;
      const { data: existing } = await supabase
        .from("assets")
        .select("id")
        .eq("user_id", userId)
        .eq("target", host)
        .maybeSingle();
      if (existing) assetId = existing.id;
      else {
        const { data: created } = await supabase
          .from("assets")
          .insert({ user_id: userId, name: host, target: host, kind: "web" })
          .select("id")
          .single();
        assetId = created?.id ?? null;
      }
    }

    const { data: scan, error } = await supabase
      .from("scans")
      .insert({
        user_id: userId,
        asset_id: assetId,
        name: data.name,
        target: data.target,
        template: data.template,
        status: "queued",
        source: "engine",
      })
      .select("*")
      .single();
    if (error) throw new Error(error.message);
    return scan;
  });

export const getScan = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    const { data: scan } = await context.supabase
      .from("scans")
      .select("*")
      .eq("id", data.id)
      .eq("user_id", context.userId)
      .maybeSingle();
    const { data: findings } = await context.supabase
      .from("findings")
      .select("*")
      .eq("scan_id", data.id)
      .order("priority", { ascending: false });
    return { scan, findings: findings ?? [] };
  });

export const deleteScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    await context.supabase.from("scans").delete().eq("id", data.id).eq("user_id", context.userId);
    return { ok: true };
  });

/* --------------------------------- findings -------------------------------- */

export const listFindings = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data } = await context.supabase
      .from("findings")
      .select("*")
      .eq("user_id", context.userId)
      .order("priority", { ascending: false })
      .limit(1000);
    const { data: assets } = await context.supabase
      .from("assets")
      .select("id, name, target")
      .eq("user_id", context.userId);
    const map = new Map((assets ?? []).map((a) => [a.id, a]));
    return (data ?? []).map((f) => ({
      ...f,
      asset: f.asset_id ? (map.get(f.asset_id) ?? null) : null,
    }));
  });

export const updateFinding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) =>
    z
      .object({
        id: z.string().uuid(),
        state: z.enum(["open", "fixed", "accepted", "false_positive"]).optional(),
        notes: z.string().max(4000).optional(),
      })
      .parse(d),
  )
  .handler(async ({ data, context }) => {
    const patch: Record<string, unknown> = {};
    if (data.state) patch["state"] = data.state;
    if (data.notes !== undefined) patch["notes"] = data.notes;
    const { error } = await context.supabase
      .from("findings")
      .update(patch as never)
      .eq("id", data.id)
      .eq("user_id", context.userId);
    if (error) throw new Error(error.message);
    return { ok: true };
  });

/* -------------------------------- agent keys ------------------------------- */

export const listApiKeys = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data } = await context.supabase
      .from("api_keys")
      .select("id, name, prefix, created_at, last_used_at")
      .eq("user_id", context.userId)
      .order("created_at", { ascending: false });
    return data ?? [];
  });

export const createApiKey = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ name: z.string().min(1).max(60) }).parse(d))
  .handler(async ({ data, context }) => {
    const bytes = crypto.getRandomValues(new Uint8Array(24));
    const raw = `aeg_${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
    const hash = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    const { error } = await context.supabase.from("api_keys").insert({
      user_id: context.userId,
      name: data.name,
      prefix: raw.slice(0, 12),
      key_hash: hash,
    });
    if (error) throw new Error(error.message);
    return { key: raw };
  });

export const deleteApiKey = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    await context.supabase
      .from("api_keys")
      .delete()
      .eq("id", data.id)
      .eq("user_id", context.userId);
    return { ok: true };
  });
