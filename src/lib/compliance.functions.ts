import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { buildEvidence } from "./compliance.server";

/** Evaluate every compliance framework against current findings and asset posture. */
export const getCompliance = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;

    const [{ data: findings }, { data: assets }, { data: scans }] = await Promise.all([
      supabase
        .from("findings")
        .select("family, severity, title, state, plugin_id")
        .eq("user_id", userId)
        .eq("state", "open")
        .limit(5000),
      supabase
        .from("assets")
        .select("id, internet_facing, last_seen")
        .eq("user_id", userId)
        .limit(2000),
      supabase
        .from("scans")
        .select("id, asset_id, source, status")
        .eq("user_id", userId)
        .limit(2000),
    ]);

    return buildEvidence(findings ?? [], assets ?? [], scans ?? []);
  });
