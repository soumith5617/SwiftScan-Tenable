import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { priorityScore, slaDueDate, SCAN_TEMPLATES } from "./severity";
import { applyVerificationPolicy, methodsForFamily } from "./verification";
import { diffFindings, fingerprint } from "./differential";

const runInput = z.object({ scanId: z.string().uuid() });

export const runScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => runInput.parse(data))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { runEngine } = await import("./scan-engine.server");

    const { data: scan, error } = await supabase
      .from("scans")
      .select("*")
      .eq("id", data.scanId)
      .single();
    if (error || !scan) throw new Error("Scan not found");

    const template = SCAN_TEMPLATES.find((t) => t.id === scan.template);
    if (!template) throw new Error(`Unknown scan template: ${scan.template}`);

    await supabase
      .from("scans")
      .update({
        status: "running",
        started_at: new Date().toISOString(),
        progress: 5,
        current_step: "Initializing scan parameters",
      })
      .eq("id", scan.id);

    try {
      // 1. Compliance scan mode
      if (template.category === "Compliance" || template.framework) {
        await supabase
          .from("scans")
          .update({ current_step: "Gathering compliance evidence & posture", progress: 25 })
          .eq("id", scan.id);

        const { buildEvidence } = await import("./compliance.server");
        const [{ data: existingFindings }, { data: existingAssets }, { data: existingScans }] =
          await Promise.all([
            supabase
              .from("findings")
              .select("family, severity, title, state, plugin_id")
              .eq("user_id", userId),
            supabase.from("assets").select("id, internet_facing, last_seen").eq("user_id", userId),
            supabase.from("scans").select("id, asset_id, source, status").eq("user_id", userId),
          ]);

        const evidenceData = buildEvidence(
          (existingFindings ?? []).map((f) => ({
            family: f.family,
            severity: f.severity,
            title: f.title,
            state: f.state,
            plugin_id: f.plugin_id,
          })),
          (existingAssets ?? []).map((a) => ({
            id: a.id,
            internet_facing: a.internet_facing,
            last_seen: a.last_seen,
          })),
          (existingScans ?? []).map((s) => ({
            id: s.id,
            asset_id: s.asset_id,
            source: s.source,
            status: s.status,
          })),
        );

        await supabase
          .from("scans")
          .update({ current_step: "Evaluating benchmark controls", progress: 65 })
          .eq("id", scan.id);

        const targetFw = template.framework ?? "ALL";
        const relevantFrameworks =
          targetFw === "ALL"
            ? evidenceData.frameworks
            : evidenceData.frameworks.filter((f) => f.key.toUpperCase() === targetFw.toUpperCase());

        const complianceFindings: Record<string, unknown>[] = [];
        let totalPassed = 0;
        let totalFailed = 0;

        for (const fw of relevantFrameworks) {
          for (const item of fw.controls) {
            const c = item.control;
            if (item.status === "fail") {
              totalFailed++;
              complianceFindings.push({
                user_id: userId,
                scan_id: scan.id,
                asset_id: scan.asset_id,
                plugin_id: `COMPL-${fw.key}-${c.id}`,
                family: "compliance",
                title: `[${fw.key}] Control ${c.id} Failed: ${c.title}`,
                severity: c.minSeverity ?? 2,
                cvss: (c.minSeverity ?? 2) * 2.5,
                priority: (c.minSeverity ?? 2) * 2.2,
                confidence: "high",
                verifications: ["Compliance Evidence Analysis", "Policy Benchmark Rule"],
                is_new: true,
                cve_ids: [],
                cwe: "CWE-1008",
                attack_tactics: ["Defense Evasion", "Initial Access"],
                port: null,
                service: null,
                description: `Requirement: ${c.requirement}\n\nEvidence Summary: ${item.detail ?? "Control criteria not satisfied by current asset configuration."}`,
                solution: `Remediation Guidance: ${c.remediation}`,
                evidence: `Framework: ${fw.name} (${fw.key})\nControl: ${c.id}\nResult: Non-Compliant / Failing\nDetail: ${item.detail}`,
                refs: [{ title: `${fw.name} Reference`, url: "https://www.cisecurity.org/" }],
                state: "open",
                due_at: slaDueDate(c.minSeverity ?? 2).toISOString(),
              });
            } else if (item.status === "pass") {
              totalPassed++;
            }
          }
        }

        if (complianceFindings.length) {
          await supabase.from("findings").insert(complianceFindings as never);
        }

        const stats = {
          critical: complianceFindings.filter((f) => f["severity"] === 4).length,
          high: complianceFindings.filter((f) => f["severity"] === 3).length,
          medium: complianceFindings.filter((f) => f["severity"] === 2).length,
          low: complianceFindings.filter((f) => f["severity"] === 1).length,
          info: complianceFindings.filter((f) => f["severity"] === 0).length,
          total: complianceFindings.length,
          controls_passed: totalPassed,
          controls_failed: totalFailed,
          framework: targetFw,
        };

        await supabase
          .from("scans")
          .update({
            status: "completed",
            progress: 100,
            current_step: "Complete",
            finished_at: new Date().toISOString(),
            stats,
          })
          .eq("id", scan.id);

        return {
          ok: true as const,
          findings: complianceFindings.length,
          counts: [stats.info, stats.low, stats.medium, stats.high, stats.critical],
        };
      }

      // 2. Live results analysis mode
      if (template.id === "live_results") {
        await supabase
          .from("scans")
          .update({ current_step: "Re-evaluating CVE/EPSS/KEV intelligence", progress: 40 })
          .eq("id", scan.id);

        const { recomputePriorities: rescore } = await import("./scans.functions");
        const res = await rescore();

        await supabase
          .from("scans")
          .update({
            status: "completed",
            progress: 100,
            current_step: "Complete",
            finished_at: new Date().toISOString(),
            stats: { total: res.updated, recomputed: res.updated },
          })
          .eq("id", scan.id);

        return { ok: true as const, findings: res.updated, counts: [0, 0, 0, 0, 0] };
      }

      // 3. Active Scan Execution (Network, Web, Infrastructure, Endpoint, Cloud, Specialized)
      let familiesToRun = [...template.families];
      if (familiesToRun.length === 0) {
        if (template.category === "Endpoint & OS") {
          familiesToRun = [
            "ports",
            "fingerprint",
            "endpoint",
            "exposure",
            "cve_hunt",
            "tls",
            "headers",
          ];
        } else if (template.category === "Infrastructure") {
          familiesToRun = ["ports", "database", "fingerprint", "device", "cve_hunt", "tls"];
        } else if (template.category === "Cloud & Container") {
          familiesToRun = ["ports", "cloud", "container", "api", "fingerprint", "tls", "exposure"];
        } else if (template.category === "Specialized") {
          familiesToRun = ["ports", "cve_hunt", "fingerprint", "exposure", "device", "tls"];
        } else {
          familiesToRun = [
            "ports",
            "fingerprint",
            "tls",
            "headers",
            "exposure",
            "webapp",
            "api",
            "dns",
            "mail",
            "device",
            "cve_hunt",
            "database",
            "cloud",
            "container",
            "endpoint",
          ];
        }
      } else {
        if (!familiesToRun.includes("ports")) familiesToRun.unshift("ports");
        if (!familiesToRun.includes("endpoint")) familiesToRun.push("endpoint");
      }

      const result = await runEngine(scan.target, familiesToRun, async (step, pct) => {
        await supabase
          .from("scans")
          .update({ current_step: step, progress: pct })
          .eq("id", scan.id);
      });

      if (!result.reachable && result.ports.length === 0) {
        await supabase
          .from("scans")
          .update({
            status: "failed",
            progress: 100,
            finished_at: new Date().toISOString(),
            error: "Target did not respond over network ports or HTTP/HTTPS within the timeout.",
          })
          .eq("id", scan.id);
        return { ok: false, reason: "unreachable" as const };
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

      await supabase
        .from("scans")
        .update({ current_step: "Correlating vulnerability intelligence", progress: 88 })
        .eq("id", scan.id);

      // --- CVE correlation against the synced intelligence cache ---
      const cveFindings: typeof result.findings = [];
      for (const tech of result.tech.filter((t) => t.version)) {
        const { data: matches } = await supabase
          .from("cve_cache")
          .select("*")
          .ilike("product", `%${tech.name.toLowerCase()}%`)
          .order("cvss", { ascending: false })
          .limit(5);
        for (const cve of matches ?? []) {
          cveFindings.push({
            plugin_id: `CVE-MATCH-${cve.cve_id}`,
            family: "cve",
            title: `${tech.name} ${tech.version} — ${cve.cve_id}`,
            severity: cve.severity,
            confidence: "medium",
            description:
              `Detected ${tech.name} ${tech.version} via ${tech.source}. ${cve.description ?? ""}`.trim(),
            solution:
              "Upgrade the affected component to a fixed release, or apply the vendor mitigation.",
            evidence: `Version banner: ${tech.name} ${tech.version} (${tech.source})\nMatched advisory: ${cve.cve_id}`,
            cve_ids: [cve.cve_id],
            cwe: cve.cwe,
            attack_tactics: ["Exploitation"],
          });
        }
      }

      const all = [...result.findings, ...cveFindings];

      const { data: asset } = scan.asset_id
        ? await supabase
            .from("assets")
            .select("criticality, internet_facing")
            .eq("id", scan.asset_id)
            .single()
        : { data: null };

      // --- Differential mode: only what changed since the last completed run ---
      let reportable = all;
      let baselineScanId: string | null = null;
      let diffStats: Record<string, number> | null = null;
      if (scan.mode === "differential") {
        const { data: baselineScan } = await supabase
          .from("scans")
          .select("id")
          .eq("user_id", userId)
          .eq("target", scan.target)
          .eq("status", "completed")
          .neq("id", scan.id)
          .order("finished_at", { ascending: false })
          .limit(1)
          .maybeSingle();
        baselineScanId = baselineScan?.id ?? null;
        if (baselineScanId) {
          const { data: baseline } = await supabase
            .from("findings")
            .select("plugin_id, port, service, cve_ids, title, id")
            .eq("scan_id", baselineScanId);
          const diff = diffFindings(all, baseline ?? []);
          reportable = diff.added;
          diffStats = {
            new: diff.added.length,
            unchanged: diff.unchanged.length,
            resolved: diff.resolvedFingerprints.length,
            baseline: diff.baselineCount,
          };
          // Close findings that are no longer observed on this target.
          const stillOpen = new Set(all.map(fingerprint));
          const resolvedIds = (baseline ?? [])
            .filter((b) => !stillOpen.has(fingerprint(b)))
            .map((b) => b.id);
          if (resolvedIds.length) {
            await supabase
              .from("findings")
              .update({ state: "resolved" })
              .in("id", resolvedIds)
              .eq("state", "open");
          }
        }
      }

      // Pre-fetch CVE intelligence for all findings in batch
      const allReportableCves = [...new Set(reportable.flatMap((f) => f.cve_ids ?? []))];
      const cveIntelMap = new Map<
        string,
        { epss: number | null; kev: boolean; cvss: number | null; cwe: string | null }
      >();
      if (allReportableCves.length > 0) {
        for (let i = 0; i < allReportableCves.length; i += 200) {
          const { data: cveRows } = await supabase
            .from("cve_cache")
            .select("cve_id, epss, kev, cvss, cwe")
            .in("cve_id", allReportableCves.slice(i, i + 200));
          for (const r of cveRows ?? []) {
            cveIntelMap.set(r.cve_id, {
              epss: r.epss,
              kev: r.kev,
              cvss: r.cvss,
              cwe: r.cwe,
            });
          }
        }
      }

      const rows: Record<string, unknown>[] = [];
      for (const raw of reportable) {
        const methods = methodsForFamily(raw.family, /\d+\.\d+/.test(String(raw.evidence ?? "")));
        const f = applyVerificationPolicy(raw, methods);
        const bestIntel = (f.cve_ids ?? []).map((c) => cveIntelMap.get(c)).find(Boolean);
        const epss = bestIntel?.epss ?? null;
        const kev = bestIntel?.kev ?? false;
        const cvss = bestIntel?.cvss ?? null;

        const priority = priorityScore({
          cvss,
          severity: f.severity,
          epss,
          kev,
          criticality: asset?.criticality ?? "medium",
          internetFacing: asset?.internet_facing ?? true,
          confidence: f.confidence,
        });
        rows.push({
          user_id: userId,
          scan_id: scan.id,
          asset_id: scan.asset_id,
          plugin_id: f.plugin_id,
          family: f.family,
          title: f.title,
          severity: f.severity,
          cvss,
          epss,
          kev,
          priority,
          confidence: f.confidence,
          verifications: f.verifications,
          is_new: true,
          cve_ids: f.cve_ids ?? [],
          cwe: f.cwe ?? bestIntel?.cwe ?? null,
          attack_tactics: f.attack_tactics ?? [],
          port: f.port ?? null,
          service: f.service ?? null,
          description: f.description,
          solution: f.solution,
          evidence: f.unverified
            ? `${f.evidence}\n\n[verification] Single-source evidence (${f.verifications.join(", ")}). Severity reported one level below the raw plugin claim until a corroborating check runs.`
            : `${f.evidence}\n\n[verification] ${f.verifications.join(" + ")}`,
          refs: f.refs ?? [],
          state: "open",
          due_at: slaDueDate(f.severity).toISOString(),
        });
      }

      if (rows.length) await supabase.from("findings").insert(rows as never);

      const counts = [0, 0, 0, 0, 0];
      for (const f of all) counts[Math.min(4, Math.max(0, f.severity))]!++;
      const riskScore = Math.min(
        100,
        Math.round(counts[4]! * 20 + counts[3]! * 10 + counts[2]! * 4 + counts[1]! * 1.5),
      );

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
            total: all.length,
            response_ms: result.responseMs,
            technologies: result.tech,
            ports: result.ports,
            ports_count: result.ports.length,
            steps: result.steps,
            ...(diffStats ? { diff: diffStats } : {}),
          },
          ...(baselineScanId ? { baseline_scan_id: baselineScanId } : {}),
        } as never)
        .eq("id", scan.id);

      if (scan.asset_id) {
        await supabase
          .from("assets")
          .update({
            last_seen: new Date().toISOString(),
            risk_score: riskScore,
            technologies: result.tech,
          })
          .eq("id", scan.asset_id);

        await supabase.from("risk_history").insert({
          user_id: userId,
          asset_id: scan.asset_id,
          risk_score: riskScore,
          open_critical: counts[4] ?? 0,
          open_high: counts[3] ?? 0,
          open_medium: counts[2] ?? 0,
          open_low: counts[1] ?? 0,
          recorded_at: new Date().toISOString(),
        });
      }

      await supabase.from("audit_log").insert({
        user_id: userId,
        action: "scan.completed",
        entity: "scan",
        entity_id: scan.id,
        detail: { target: scan.target, findings: all.length, ports: result.ports.length },
      });

      return { ok: true as const, findings: rows.length, counts, diff: diffStats };
    } catch (err) {
      const message = err instanceof Error ? err.message : "Scan failed";
      await supabase
        .from("scans")
        .update({
          status: "failed",
          progress: 100,
          error: message,
          finished_at: new Date().toISOString(),
        })
        .eq("id", scan.id);
      return { ok: false as const, reason: message };
    }
  });

/** Re-score every open finding against the latest intelligence (Live Results). */
export const recomputePriorities = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data: findings } = await supabase
      .from("findings")
      .select("id, severity, cvss, cve_ids, confidence, asset_id")
      .eq("user_id", userId)
      .neq("state", "false_positive")
      .limit(2000);
    if (!findings?.length) return { updated: 0 };

    const cveIds = [...new Set(findings.flatMap((f) => f.cve_ids ?? []))];
    const intel = new Map<string, { epss: number | null; kev: boolean; cvss: number | null }>();
    if (cveIds.length) {
      const { data: rows } = await supabase
        .from("cve_cache")
        .select("cve_id, epss, kev, cvss")
        .in("cve_id", cveIds);
      for (const r of rows ?? []) intel.set(r.cve_id, { epss: r.epss, kev: r.kev, cvss: r.cvss });
    }

    let updated = 0;
    const workerPoolLimit = 25;
    let cursor = 0;
    const workers = Array.from(
      { length: Math.min(workerPoolLimit, findings.length) },
      async () => {
        while (cursor < findings.length) {
          const idx = cursor++;
          const f = findings[idx]!;
          const best = (f.cve_ids ?? []).map((c) => intel.get(c)).filter(Boolean)[0];
          const priority = priorityScore({
            cvss: best?.cvss ?? f.cvss,
            severity: f.severity,
            epss: best?.epss ?? null,
            kev: best?.kev ?? false,
            confidence: f.confidence,
          });
          await supabase
            .from("findings")
            .update({ priority, epss: best?.epss ?? null, kev: best?.kev ?? false })
            .eq("id", f.id);
          updated++;
        }
      },
    );
    await Promise.all(workers);
    return { updated };
  });
