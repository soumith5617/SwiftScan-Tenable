import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { RiskEngine } from "./risk/risk-engine";
import { SeverityLevel } from "./types/enterprise";

/* -------------------------------------------------------------------------- */
/*                                ASSET GROUPS                                */
/* -------------------------------------------------------------------------- */

const assetGroupInput = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).default(""),
  color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/)
    .default("#3b82f6"),
  dynamic_rule: z
    .object({
      tags: z.array(z.string()).optional(),
      criticality: z.enum(["low", "medium", "high", "critical"]).optional(),
      kind: z.enum(["web", "host", "api", "cloud", "container"]).optional(),
    })
    .nullable()
    .optional(),
});

export const listAssetGroups = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data: groups, error } = await supabase
      .from("asset_groups")
      .select("*")
      .eq("user_id", userId)
      .order("name", { ascending: true });
    if (error) throw new Error(error.message);

    const { data: memberships } = await supabase
      .from("asset_group_memberships")
      .select("group_id, asset_id")
      .eq("user_id", userId);

    const countMap = new Map<string, number>();
    for (const m of memberships ?? []) {
      countMap.set(m.group_id, (countMap.get(m.group_id) ?? 0) + 1);
    }

    return (groups ?? []).map((g) => ({
      ...g,
      asset_count: countMap.get(g.id) ?? 0,
    }));
  });

export const createAssetGroup = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => assetGroupInput.parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: group, error } = await supabase
      .from("asset_groups")
      .insert({
        user_id: userId,
        name: data.name,
        description: data.description,
        color: data.color,
        dynamic_rule: data.dynamic_rule as never,
      })
      .select("*")
      .single();
    if (error) throw new Error(error.message);
    return group;
  });

export const deleteAssetGroup = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await supabase.from("asset_groups").delete().eq("id", data.id).eq("user_id", userId);
    return { ok: true };
  });

/* -------------------------------------------------------------------------- */
/*                          HOST PORTS & SERVICES                             */
/* -------------------------------------------------------------------------- */

export const listHostPorts = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data: ports, error } = await supabase
      .from("host_ports")
      .select("*, assets(id, name, target, criticality)")
      .eq("user_id", userId)
      .order("port", { ascending: true });
    if (error) throw new Error(error.message);
    return ports ?? [];
  });

/* -------------------------------------------------------------------------- */
/*                       RISK OVERRIDES & EXCEPTIONS                          */
/* -------------------------------------------------------------------------- */

const riskOverrideInput = z.object({
  finding_id: z.string().uuid(),
  overridden_severity: z.union([
    z.literal(0),
    z.literal(1),
    z.literal(2),
    z.literal(3),
    z.literal(4),
  ]),
  reason: z.string().min(5).max(500),
  approved_by: z.string().optional(),
  expires_at: z.string().datetime().optional(),
});

export const listRiskOverrides = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data, error } = await supabase
      .from("risk_overrides")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });
    if (error) throw new Error(error.message);
    return data ?? [];
  });

export const applyRiskOverride = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => riskOverrideInput.parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;

    // 1. Fetch current finding
    const { data: finding, error: findingErr } = await supabase
      .from("findings")
      .select("*")
      .eq("id", data.finding_id)
      .eq("user_id", userId)
      .single();

    if (findingErr || !finding) throw new Error("Finding not found");

    // 2. Insert into risk_overrides
    const { error: overrideErr } = await supabase.from("risk_overrides").insert({
      user_id: userId,
      finding_id: data.finding_id,
      original_severity: finding.severity,
      overridden_severity: data.overridden_severity,
      reason: data.reason,
      approved_by: data.approved_by || context.userEmail || "Security Lead",
      expires_at: data.expires_at ?? null,
    });

    if (overrideErr) throw new Error(overrideErr.message);

    // 3. Recalculate finding priority based on overridden severity
    const riskResult = RiskEngine.calculateFindingRisk({
      cvssScore:
        finding.cvss ??
        (data.overridden_severity === 4 ? 9.5 : data.overridden_severity === 3 ? 7.5 : 5.0),
      isKev: finding.kev ?? false,
      epssScore: finding.epss ?? undefined,
      assetCriticality: "medium",
      isInternetFacing: true,
      customSeverityOverride: data.overridden_severity,
    });

    await supabase
      .from("findings")
      .update({
        severity: riskResult.effectiveSeverity,
        priority: riskResult.adjustedPriority,
      } as never)
      .eq("id", data.finding_id);

    // 4. Update asset risk score if linked
    if (finding.asset_id) {
      const { data: assetFindings } = await supabase
        .from("findings")
        .select("severity, priority, kev")
        .eq("asset_id", finding.asset_id)
        .eq("state", "open");

      const mappedFindings = (assetFindings ?? []).map((f) => ({
        severity: Math.min(4, Math.max(0, f.severity ?? 0)) as 0 | 1 | 2 | 3 | 4,
        priority: f.priority ?? 0,
        kev: Boolean(f.kev),
      }));

      const newAssetScore = RiskEngine.calculateAssetRiskScore("medium", true, mappedFindings);

      await supabase
        .from("assets")
        .update({ risk_score: newAssetScore } as never)
        .eq("id", finding.asset_id);
    }

    return { ok: true };
  });

/* -------------------------------------------------------------------------- */
/*                                SAVED FILTERS                               */
/* -------------------------------------------------------------------------- */

const savedFilterInput = z.object({
  name: z.string().min(1).max(80),
  entity_type: z.enum(["findings", "assets", "scans", "intel"]),
  query_params: z.record(z.unknown()),
  is_default: z.boolean().default(false),
  is_shared: z.boolean().default(false),
});

export const listSavedFilters = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) =>
    z.object({ entity_type: z.enum(["findings", "assets", "scans", "intel"]).optional() }).parse(d),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    let query = supabase.from("saved_filters").select("*").eq("user_id", userId);
    if (data.entity_type) query = query.eq("entity_type", data.entity_type);
    const { data: filters, error } = await query.order("name", { ascending: true });
    if (error) throw new Error(error.message);
    return filters ?? [];
  });

export const createSavedFilter = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => savedFilterInput.parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: filter, error } = await supabase
      .from("saved_filters")
      .insert({
        user_id: userId,
        name: data.name,
        entity_type: data.entity_type,
        query_params: data.query_params as never,
        is_default: data.is_default,
        is_shared: data.is_shared,
      })
      .select("*")
      .single();
    if (error) throw new Error(error.message);
    return filter;
  });

export const deleteSavedFilter = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await supabase.from("saved_filters").delete().eq("id", data.id).eq("user_id", userId);
    return { ok: true };
  });

/* -------------------------------------------------------------------------- */
/*                           ORGANIZATION SETTINGS                            */
/* -------------------------------------------------------------------------- */

export const getOrgSettings = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data, error } = await supabase
      .from("organization_settings")
      .select("*")
      .eq("user_id", userId)
      .maybeSingle();

    if (error) throw new Error(error.message);
    if (!data) {
      // Create initial settings if not exists
      const { data: created } = await supabase
        .from("organization_settings")
        .insert({
          user_id: userId,
          org_name: "Aegis Enterprise",
          mfa_required: false,
          session_timeout_minutes: 60,
          min_password_length: 12,
          smtp_config: {},
          branding: { primary_color: "#0f172a", logo_url: "" },
        })
        .select("*")
        .single();
      return created;
    }
    return data;
  });

export const updateOrgSettings = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) =>
    z
      .object({
        org_name: z.string().min(1).max(100),
        mfa_required: z.boolean(),
        session_timeout_minutes: z.number().int().min(5).max(1440),
        min_password_length: z.number().int().min(8).max(64),
        smtp_config: z.record(z.any()).default({}),
        branding: z.record(z.any()).default({}),
      })
      .parse(d),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: updated, error } = await supabase
      .from("organization_settings")
      .upsert({
        user_id: userId,
        ...data,
        updated_at: new Date().toISOString(),
      } as never)
      .select("*")
      .single();
    if (error) throw new Error(error.message);
    return updated;
  });

/* -------------------------------------------------------------------------- */
/*                               GLOBAL SEARCH                                */
/* -------------------------------------------------------------------------- */

export const globalSearch = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ query: z.string().min(1).max(100) }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const q = data.query.trim().toLowerCase();

    const [findingsRes, assetsRes, scansRes] = await Promise.all([
      supabase
        .from("findings")
        .select("id, title, severity, plugin_id, cve_ids, state, priority")
        .eq("user_id", userId)
        .ilike("title", `%${q}%`)
        .limit(8),
      supabase
        .from("assets")
        .select("id, name, target, kind, criticality, risk_score")
        .eq("user_id", userId)
        .or(`name.ilike.%${q}%,target.ilike.%${q}%`)
        .limit(8),
      supabase
        .from("scans")
        .select("id, name, target, status, template")
        .eq("user_id", userId)
        .or(`name.ilike.%${q}%,target.ilike.%${q}%`)
        .limit(8),
    ]);

    return {
      findings: findingsRes.data ?? [],
      assets: assetsRes.data ?? [],
      scans: scansRes.data ?? [],
    };
  });
