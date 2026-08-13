import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { severityFromCvss } from "./severity";

interface CveRow {
  cve_id: string;
  description: string | null;
  severity: number;
  cvss: number | null;
  cvss_vector: string | null;
  epss: number | null;
  kev: boolean;
  kev_due_date: string | null;
  cwe: string | null;
  vendor: string | null;
  product: string | null;
  published: string | null;
  refs: { title: string; url: string }[];
  synced_at: string;
}

/**
 * Syncs live vulnerability intelligence: CISA KEV (known exploited),
 * FIRST EPSS (exploit probability) and NVD (CVE + CVSS + CWE + CPE).
 * Writes into the shared cve_cache so lookups during scans are instant.
 */
export const syncIntel = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    const errors: string[] = [];
    const kevMap = new Map<
      string,
      { due: string | null; vendor: string; product: string; desc: string }
    >();
    const epssMap = new Map<string, number>();

    // --- CISA Known Exploited Vulnerabilities ---
    try {
      const res = await fetch(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        { headers: { accept: "application/json" } },
      );
      if (res.ok) {
        const json = (await res.json()) as {
          vulnerabilities: {
            cveID: string;
            vendorProject: string;
            product: string;
            shortDescription: string;
            dueDate: string;
          }[];
        };
        for (const v of json.vulnerabilities ?? []) {
          kevMap.set(v.cveID, {
            due: v.dueDate ?? null,
            vendor: v.vendorProject,
            product: v.product,
            desc: v.shortDescription,
          });
        }
      } else errors.push(`KEV feed HTTP ${res.status}`);
    } catch (e) {
      errors.push(`KEV feed: ${e instanceof Error ? e.message : "failed"}`);
    }

    // --- NVD: most recently published CVEs ---
    const nvdRows: CveRow[] = [];
    try {
      const res = await fetch(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200&startIndex=0",
        { headers: { accept: "application/json" } },
      );
      if (res.ok) {
        interface NvdCveItem {
          id: string;
          descriptions?: Array<{ lang?: string; value?: string }>;
          metrics?: {
            cvssMetricV31?: Array<{
              cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
            }>;
            cvssMetricV40?: Array<{
              cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
            }>;
            cvssMetricV30?: Array<{
              cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
            }>;
            cvssMetricV2?: Array<{
              cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
            }>;
          };
          configurations?: Array<{ nodes?: Array<{ cpeMatch?: Array<{ criteria?: string }> }> }>;
          weaknesses?: Array<{ description?: Array<{ value?: string }> }>;
          references?: Array<{ url: string; source?: string }>;
          published?: string;
        }

        const json = (await res.json()) as { vulnerabilities?: { cve: NvdCveItem }[] };
        for (const item of json.vulnerabilities ?? []) {
          const cve = item.cve;
          const id = cve.id;
          const metrics = cve.metrics ?? {};
          const primary =
            metrics.cvssMetricV31?.[0] ??
            metrics.cvssMetricV40?.[0] ??
            metrics.cvssMetricV30?.[0] ??
            metrics.cvssMetricV2?.[0];
          const score: number | null = primary?.cvssData?.baseScore ?? null;
          const cpe = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria;
          const cpeParts = cpe?.split(":") ?? [];
          nvdRows.push({
            cve_id: id,
            description:
              (cve.descriptions ?? []).find((d) => d.lang === "en")?.value?.slice(0, 2000) ?? null,
            severity: severityFromCvss(score),
            cvss: score,
            cvss_vector: primary?.cvssData?.vectorString ?? null,
            epss: null,
            kev: kevMap.has(id),
            kev_due_date: kevMap.get(id)?.due ?? null,
            cwe: cve.weaknesses?.[0]?.description?.[0]?.value ?? null,
            vendor: cpeParts[3] ?? kevMap.get(id)?.vendor ?? null,
            product: cpeParts[4] ?? kevMap.get(id)?.product ?? null,
            published: cve.published ?? null,
            refs: (cve.references ?? []).slice(0, 6).map((r) => ({
              title: r.source ?? "Reference",
              url: r.url,
            })),
            synced_at: new Date().toISOString(),
          });
        }
      } else errors.push(`NVD feed HTTP ${res.status}`);
    } catch (e) {
      errors.push(`NVD feed: ${e instanceof Error ? e.message : "failed"}`);
    }

    // --- FIRST EPSS scores for the CVEs we now know about ---
    const wanted = [...new Set([...kevMap.keys(), ...nvdRows.map((r) => r.cve_id)])];
    try {
      for (let i = 0; i < Math.min(wanted.length, 400); i += 100) {
        const batch = wanted.slice(i, i + 100);
        const res = await fetch(`https://api.first.org/data/v1/epss?cve=${batch.join(",")}`, {
          headers: { accept: "application/json" },
        });
        if (!res.ok) break;
        const json = (await res.json()) as { data?: { cve: string; epss: string }[] };
        for (const row of json.data ?? []) epssMap.set(row.cve, Number(row.epss));
      }
    } catch (e) {
      errors.push(`EPSS feed: ${e instanceof Error ? e.message : "failed"}`);
    }

    // KEV entries that NVD did not return still deserve a row
    const byId = new Map<string, CveRow>();
    for (const row of nvdRows) byId.set(row.cve_id, row);
    for (const [id, kev] of kevMap) {
      const existing = byId.get(id);
      if (existing) {
        existing.kev = true;
        existing.kev_due_date = kev.due;
        continue;
      }
      byId.set(id, {
        cve_id: id,
        description: kev.desc,
        severity: 4,
        cvss: null,
        cvss_vector: null,
        epss: null,
        kev: true,
        kev_due_date: kev.due,
        cwe: null,
        vendor: kev.vendor,
        product: kev.product,
        published: null,
        refs: [
          {
            title: "CISA KEV catalog",
            url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
          },
        ],
        synced_at: new Date().toISOString(),
      });
    }
    for (const row of byId.values()) {
      const epss = epssMap.get(row.cve_id);
      if (epss != null) row.epss = epss;
      if (row.kev && row.severity < 3) row.severity = 4;
    }

    const all = [...byId.values()];
    let stored = 0;
    for (let i = 0; i < all.length; i += 200) {
      const chunk = all.slice(i, i + 200);
      const { error } = await supabaseAdmin
        .from("cve_cache")
        .upsert(chunk as never, { onConflict: "cve_id" });
      if (error) errors.push(error.message);
      else stored += chunk.length;
    }

    await context.supabase.from("audit_log").insert({
      user_id: context.userId,
      action: "intel.sync",
      entity: "cve_cache",
      detail: { stored, kev: kevMap.size, epss: epssMap.size, errors },
    });

    return { stored, kev: kevMap.size, epss: epssMap.size, errors };
  });

export const intelStats = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase } = context;
    const [{ count: total }, { count: kev }, latest] = await Promise.all([
      supabase.from("cve_cache").select("cve_id", { count: "exact", head: true }),
      supabase.from("cve_cache").select("cve_id", { count: "exact", head: true }).eq("kev", true),
      supabase
        .from("cve_cache")
        .select("synced_at")
        .order("synced_at", { ascending: false })
        .limit(1)
        .maybeSingle(),
    ]);
    return { total: total ?? 0, kev: kev ?? 0, lastSync: latest.data?.synced_at ?? null };
  });
