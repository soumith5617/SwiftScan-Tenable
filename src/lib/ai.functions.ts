import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

const explainInput = z.object({
  findingId: z.string().uuid(),
  kind: z.enum(["remediation", "explain", "script"]).default("remediation"),
  refresh: z.boolean().default(false),
});

/**
 * Evidence-driven AI analysis. The model never decides whether a vulnerability
 * exists — it only interprets evidence the scan engine already produced.
 */
export const analyseFinding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => explainInput.parse(data))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;

    if (!data.refresh) {
      const { data: cached } = await supabase
        .from("ai_insights")
        .select("content, model, created_at")
        .eq("finding_id", data.findingId)
        .eq("kind", data.kind)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (cached) return { content: cached.content, cached: true as const, model: cached.model };
    }

    const { data: finding, error } = await supabase
      .from("findings")
      .select("*")
      .eq("id", data.findingId)
      .single();
    if (error || !finding) throw new Error("Finding not found");

    const { generateAnalysis } = await import("./ai.server");
    const content = await generateAnalysis(data.kind, finding);

    await supabase.from("ai_insights").insert({
      user_id: userId,
      finding_id: data.findingId,
      kind: data.kind,
      content,
      model: "google/gemini-3.6-flash",
    });

    return { content, cached: false as const, model: "google/gemini-3.6-flash" };
  });

/** Cluster duplicate/related open findings and produce an executive risk narrative. */
export const correlateFindings = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data: findings } = await supabase
      .from("findings")
      .select("id, title, severity, priority, family, plugin_id, cve_ids, asset_id, kev, state")
      .eq("user_id", userId)
      .eq("state", "open")
      .order("priority", { ascending: false })
      .limit(200);

    if (!findings?.length) return { clusters: [], narrative: "No open findings to correlate." };

    const { clusterFindings, generateNarrative } = await import("./ai.server");
    const clusters = clusterFindings(findings);
    const narrative = await generateNarrative(findings, clusters);
    return { clusters, narrative };
  });
