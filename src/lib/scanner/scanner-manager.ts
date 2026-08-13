import { SupabaseClient } from "@supabase/supabase-js";
import { PluginManager } from "./plugin-manager";
import { ScanContext } from "./plugin-interface";
import { normalizeTarget, probe, ProbeResult } from "../scan-engine.server";
import { runExtendedChecks } from "../scan-engine-extended.server";
import { RiskEngine } from "../risk/risk-engine";

export interface ScanTaskConfig {
  scanId: string;
  userId: string;
  assetId?: string | null;
  target: string;
  template: string;
  supabase: SupabaseClient;
}

export class ScannerManager {
  private static activeJobs: Set<string> = new Set();

  /**
   * Main scan worker execution loop
   */
  public static async processScanJob(config: ScanTaskConfig): Promise<void> {
    const { scanId, userId, assetId, target, template, supabase } = config;

    if (this.activeJobs.has(scanId)) {
      console.warn(`Scan ${scanId} is already running.`);
      return;
    }

    this.activeJobs.add(scanId);

    try {
      // 1. Mark scan as running (Progress 10%)
      await supabase
        .from("scans")
        .update({
          status: "running",
          progress: 10,
          current_step: "Initializing target probes & DNS resolution",
          started_at: new Date().toISOString(),
        } as never)
        .eq("id", scanId);

      // 2. Target validation & normalization
      const targetUrl = normalizeTarget(target);

      // 3. Root probe execution (Progress 25%)
      await supabase
        .from("scans")
        .update({ progress: 25, current_step: "Probing HTTP/HTTPS endpoints" } as never)
        .eq("id", scanId);

      const rootProbe = await probe(targetUrl.href);
      const httpsWorks = targetUrl.protocol === "https:" || (rootProbe?.status ?? 0) > 0;

      const scanCtx: ScanContext = {
        targetUrl,
        rootProbe,
        technologies: [],
        httpsSupported: httpsWorks,
        probes: new Map(),
      };

      // 4. Executing scan plugins & extended checks (Progress 50%)
      await supabase
        .from("scans")
        .update({ progress: 50, current_step: "Executing vulnerability plugins" } as never)
        .eq("id", scanId);

      const pluginFindings = await PluginManager.getInstance().executePlugins(scanCtx);
      const extendedFindings = await runExtendedChecks(targetUrl.href);

      const rawFindings = [...pluginFindings, ...extendedFindings];

      // 5. Port Inventory & Service Discovery Recording (Progress 75%)
      await supabase
        .from("scans")
        .update({ progress: 75, current_step: "Fingerprinting services & ports" } as never)
        .eq("id", scanId);

      if (assetId) {
        const port = targetUrl.port
          ? parseInt(targetUrl.port, 10)
          : targetUrl.protocol === "https:"
            ? 443
            : 80;
        await supabase.from("host_ports").upsert(
          {
            user_id: userId,
            asset_id: assetId,
            port,
            protocol: "tcp",
            state: "open",
            service_name: targetUrl.protocol.replace(":", ""),
            banner: rootProbe?.headers["server"] ?? "HTTP Web Server",
            last_seen: new Date().toISOString(),
          } as never,
          { onConflict: "asset_id,port,protocol" },
        );
      }

      // 6. Finding deduplication, risk scoring & DB insertion (Progress 90%)
      await supabase
        .from("scans")
        .update({ progress: 90, current_step: "Correlating risk & saving findings" } as never)
        .eq("id", scanId);

      let openCount = 0;
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;

      // Fetch asset criticality if available
      let assetCriticality: "low" | "medium" | "high" | "critical" = "medium";
      let isInternetFacing = true;

      if (assetId) {
        const { data: assetObj } = await supabase
          .from("assets")
          .select("criticality, internet_facing")
          .eq("id", assetId)
          .single();
        if (assetObj) {
          assetCriticality =
            (assetObj.criticality as "low" | "medium" | "high" | "critical") || "medium";
          isInternetFacing = assetObj.internet_facing ?? true;
        }
      }

      for (const f of rawFindings) {
        // Calculate risk using Risk Engine
        const riskResult = RiskEngine.calculateFindingRisk({
          cvssScore: f.severity === 4 ? 9.5 : f.severity === 3 ? 7.5 : f.severity === 2 ? 5.0 : 2.0,
          isKev: (f.cve_ids?.length ?? 0) > 0 && f.severity >= 3,
          assetCriticality,
          isInternetFacing,
        });

        if (f.severity === 4) criticalCount++;
        else if (f.severity === 3) highCount++;
        else if (f.severity === 2) mediumCount++;
        else if (f.severity === 1) lowCount++;
        openCount++;

        // Insert finding into DB
        await supabase.from("findings").insert({
          user_id: userId,
          scan_id: scanId,
          asset_id: assetId,
          plugin_id: f.plugin_id,
          family: f.family,
          title: f.title,
          severity: riskResult.effectiveSeverity,
          cvss: riskResult.baseCvss,
          priority: riskResult.adjustedPriority,
          confidence: f.confidence,
          description: f.description,
          solution: f.solution,
          evidence: f.evidence,
          port: f.port ?? (targetUrl.protocol === "https:" ? 443 : 80),
          service: f.service ?? targetUrl.protocol.replace(":", ""),
          cve_ids: f.cve_ids ?? [],
          cwe: f.cwe ?? null,
          attack_tactics: f.attack_tactics ?? [],
          refs: f.refs ?? [],
          state: "open",
        } as never);
      }

      // Update Asset Risk Score if asset associated
      if (assetId) {
        const { data: currentFindings } = await supabase
          .from("findings")
          .select("severity, priority, kev")
          .eq("asset_id", assetId)
          .eq("state", "open");

        const updatedAssetRisk = RiskEngine.calculateAssetRiskScore(
          assetCriticality,
          isInternetFacing,
          currentFindings || [],
        );

        await supabase
          .from("assets")
          .update({
            risk_score: updatedAssetRisk,
            last_seen: new Date().toISOString(),
          } as never)
          .eq("id", assetId);

        // Record risk history point
        await supabase.from("risk_history").insert({
          user_id: userId,
          asset_id: assetId,
          risk_score: updatedAssetRisk,
          open_critical: criticalCount,
          open_high: highCount,
          open_medium: mediumCount,
          open_low: lowCount,
        } as never);
      }

      // 7. Complete Scan (Progress 100%)
      await supabase
        .from("scans")
        .update({
          status: "completed",
          progress: 100,
          current_step: "Scan finished successfully",
          finished_at: new Date().toISOString(),
          stats: {
            total_findings: rawFindings.length,
            critical: criticalCount,
            high: highCount,
            medium: mediumCount,
            low: lowCount,
          },
        } as never)
        .eq("id", scanId);
    } catch (err: unknown) {
      console.error(`Scan ${scanId} failed:`, err);
      const errorMessage = err instanceof Error ? err.message : "Unknown scan engine error";
      await supabase
        .from("scans")
        .update({
          status: "failed",
          progress: 0,
          current_step: "Scan failed",
          error: errorMessage,
          finished_at: new Date().toISOString(),
        } as never)
        .eq("id", scanId);
    } finally {
      this.activeJobs.delete(scanId);
    }
  }
}
