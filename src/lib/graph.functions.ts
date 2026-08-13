import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { buildAttackGraph } from "./attack-graph";

/** Live inventory + exposure graph derived from assets and open findings. */
export const getAttackGraph = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const [assets, findings] = await Promise.all([
      supabase
        .from("assets")
        .select("id, name, target, kind, criticality, internet_facing, technologies, os")
        .eq("user_id", userId)
        .limit(300),
      supabase
        .from("findings")
        .select("id, asset_id, title, severity, kev, service, port, family, attack_tactics")
        .eq("user_id", userId)
        .eq("state", "open")
        .limit(2000),
    ]);
    return buildAttackGraph(assets.data ?? [], findings.data ?? []);
  });
