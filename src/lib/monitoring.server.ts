import type { SupabaseClient } from "@supabase/supabase-js";
import { priorityScore, slaDueDate, SCAN_TEMPLATES } from "./severity";

type Client = SupabaseClient;

export type ExecuteResult = { ok: boolean; findings: number; reason?: string };

/**
 * Headless scan execution used by the scheduler. Mirrors the interactive
 * runScan pipeline: engine -> intel correlation -> scoring -> drift -> dispatch.
 */
export async function executeScanById(
  supabase: Client,
  userId: string,
  scanId: string,
): Promise<ExecuteResult> {
  const { runEngine } = await import("./scan-engine.server");
  const { data: scan } = await supabase.from("scans").select("*").eq("id", scanId).single();
  if (!scan) return { ok: false, findings: 0, reason: "scan not found" };

  const template = SCAN_TEMPLATES.find((t) => t.id === scan.template);
  if (!template || template.mode !== "native") {
    await supabase
      .from("scans")
      .update({ status: "awaiting_agent", current_step: "Requires external agent" })
      .eq("id", scanId);
    return { ok: false, findings: 0, reason: "non-native template" };
  }

  await supabase
    .from("scans")
    .update({
      status: "running",
      started_at: new Date().toISOString(),
      progress: 5,
      current_step: "Scheduled run",
    })
    .eq("id", scanId);

  try {
    const result = await runEngine(scan.target, template.families);
    if (!result.reachable && result.ports.length === 0) {
      await supabase
        .from("scans")
        .update({
          status: "failed",
          progress: 100,
          finished_at: new Date().toISOString(),
          error: "Target did not respond over network ports or HTTP/HTTPS.",
        })
        .eq("id", scanId);
      return { ok: false, findings: 0, reason: "unreachable" };
    }

    // Record Discovered Ports into host_ports
    if (scan.asset_id && result.ports.length) {
      for (const p of result.ports) {
        await supabase.from("host_ports").upsert(
          {
            user_id: userId,
            asset_id: scan.asset_id,
            port: p.port,
            protocol: p.protocol,
            state: p.state,
            service_name: p.service,
            banner: p.banner ?? null,
            last_seen: new Date().toISOString(),
          } as never,
          { onConflict: "asset_id,port,protocol" },
        );
      }
    }

    const { data: asset } = scan.asset_id
      ? await supabase
          .from("assets")
          .select("criticality, internet_facing, technologies")
          .eq("id", scan.asset_id)
          .single()
      : { data: null };

    // Previous open findings for this asset/target — used for drift detection.
    const { data: previous } = await supabase
      .from("findings")
      .select("id, plugin_id, title, severity")
      .eq("user_id", userId)
      .eq("state", "open")
      .eq("asset_id", scan.asset_id ?? null);

    const previousKeys = new Set<string>(
      (previous ?? []).map((p: { plugin_id: string }) => p.plugin_id),
    );

    const rows: Record<string, unknown>[] = [];
    for (const f of result.findings) {
      let epss: number | null = null;
      let kev = false;
      let cvss: number | null = null;
      if (f.cve_ids?.length) {
        const { data: intel } = await supabase
          .from("cve_cache")
          .select("epss, kev, cvss")
          .in("cve_id", f.cve_ids)
          .order("cvss", { ascending: false })
          .limit(1)
          .maybeSingle();
        epss = intel?.epss ?? null;
        kev = intel?.kev ?? false;
        cvss = intel?.cvss ?? null;
      }
      rows.push({
        user_id: userId,
        scan_id: scanId,
        asset_id: scan.asset_id,
        plugin_id: f.plugin_id,
        family: f.family,
        title: f.title,
        severity: f.severity,
        cvss,
        epss,
        kev,
        priority: priorityScore({
          cvss,
          severity: f.severity,
          epss,
          kev,
          criticality: asset?.criticality ?? "medium",
          internetFacing: asset?.internet_facing ?? true,
          confidence: f.confidence,
        }),
        confidence: f.confidence,
        cve_ids: f.cve_ids ?? [],
        cwe: f.cwe ?? null,
        attack_tactics: f.attack_tactics ?? [],
        port: f.port ?? null,
        service: f.service ?? null,
        description: f.description,
        solution: f.solution,
        evidence: f.evidence,
        refs: f.refs ?? [],
        state: "open",
        due_at: slaDueDate(f.severity).toISOString(),
      });
    }

    let inserted: {
      id: string;
      title: string;
      severity: number;
      plugin_id: string;
      priority: number;
      kev: boolean;
    }[] = [];
    if (rows.length) {
      const { data } = await supabase
        .from("findings")
        .insert(rows)
        .select("id, title, severity, plugin_id, priority, kev");
      inserted = data ?? [];
    }

    // --- Drift detection -------------------------------------------------
    const changes: Record<string, unknown>[] = [];
    for (const f of inserted) {
      if (!previousKeys.has(f.plugin_id)) {
        changes.push({
          user_id: userId,
          asset_id: scan.asset_id,
          scan_id: scanId,
          kind: "new_finding",
          summary: `New: ${f.title}`,
          before_value: {},
          after_value: { plugin_id: f.plugin_id, severity: f.severity },
        });
      }
    }
    const currentKeys = new Set(inserted.map((f) => f.plugin_id));
    for (const p of previous ?? []) {
      if (!currentKeys.has(p.plugin_id)) {
        changes.push({
          user_id: userId,
          asset_id: scan.asset_id,
          scan_id: scanId,
          kind: "resolved",
          summary: `No longer detected: ${p.title}`,
          before_value: { plugin_id: p.plugin_id, severity: p.severity },
          after_value: {},
        });
      }
    }
    const prevTech = JSON.stringify(asset?.technologies ?? []);
    const nextTech = JSON.stringify(result.tech);
    if (asset && prevTech !== nextTech) {
      changes.push({
        user_id: userId,
        asset_id: scan.asset_id,
        scan_id: scanId,
        kind: "tech_change",
        summary: "Technology fingerprint changed",
        before_value: { technologies: asset.technologies ?? [] },
        after_value: { technologies: result.tech },
      });
    }
    if (changes.length) await supabase.from("asset_changes").insert(changes);

    const counts = [0, 0, 0, 0, 0];
    for (const f of result.findings) counts[Math.min(4, Math.max(0, f.severity))]!++;

    await supabase
      .from("scans")
      .update({
        status: "completed",
        progress: 100,
        current_step: "Complete",
        finished_at: new Date().toISOString(),
        stats: {
          critical: counts[4],
          high: counts[3],
          medium: counts[2],
          low: counts[1],
          info: counts[0],
          total: result.findings.length,
          response_ms: result.responseMs,
          technologies: result.tech,
          ports: result.ports,
          ports_count: result.ports.length,
          steps: result.steps,
          drift: changes.length,
        },
      } as never)
      .eq("id", scanId);

    if (scan.asset_id) {
      await supabase
        .from("assets")
        .update({
          last_seen: new Date().toISOString(),
          risk_score: Math.min(
            100,
            Math.round(counts[4]! * 20 + counts[3]! * 10 + counts[2]! * 4 + counts[1]! * 1.5),
          ),
          technologies: result.tech,
        })
        .eq("id", scan.asset_id);
    }

    // --- Outbound integrations ------------------------------------------
    if (inserted.length) {
      const { dispatchFindings } = await import("./integrations.server");
      await dispatchFindings(supabase, userId, inserted, { target: scan.target, scanId });
    }

    return { ok: true, findings: result.findings.length };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Scheduled scan failed";
    await supabase
      .from("scans")
      .update({
        status: "failed",
        progress: 100,
        error: message,
        finished_at: new Date().toISOString(),
      })
      .eq("id", scanId);
    return { ok: false, findings: 0, reason: message };
  }
}

export const CADENCE_MS: Record<string, number> = {
  hourly: 3_600_000,
  every6h: 21_600_000,
  daily: 86_400_000,
  weekly: 604_800_000,
};

export function nextRunFrom(cadence: string, from = Date.now()): string {
  return new Date(from + (CADENCE_MS[cadence] ?? CADENCE_MS["daily"]!)).toISOString();
}
