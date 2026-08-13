import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { priorityScore, slaDueDate } from "./severity";

const importInput = z.object({
  filename: z.string().min(1).max(200),
  content: z.string().min(1).max(6_000_000),
  assetName: z.string().max(120).optional(),
});

interface ParsedFinding {
  host: string;
  plugin_id: string;
  title: string;
  severity: number;
  cvss: number | null;
  port: number | null;
  service: string | null;
  description: string;
  solution: string;
  evidence: string;
  cve_ids: string[];
}

function decode(s: string) {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function tag(block: string, name: string): string {
  const m = block.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, "i"));
  return m?.[1] ? decode(m[1].trim()) : "";
}

function parseNessus(xml: string): ParsedFinding[] {
  const out: ParsedFinding[] = [];
  const hostBlocks = xml.split(/<ReportHost\b/i).slice(1);
  for (const hostBlock of hostBlocks) {
    const host = hostBlock.match(/name=["']([^"']+)["']/)?.[1] ?? "unknown";
    const items = hostBlock.split(/<ReportItem\b/i).slice(1);
    for (const raw of items) {
      const attrs = raw.slice(0, raw.indexOf(">"));
      const attr = (k: string) => attrs.match(new RegExp(`${k}=["']([^"']*)["']`))?.[1] ?? "";
      const cves = [...raw.matchAll(/<cve>([^<]+)<\/cve>/gi)].map((m) => m[1]!.trim());
      out.push({
        host,
        plugin_id: attr("pluginID") || "NESSUS",
        title: attr("pluginName") || tag(raw, "plugin_name") || "Imported finding",
        severity: Number(attr("severity") || 0),
        cvss: Number(tag(raw, "cvss3_base_score") || tag(raw, "cvss_base_score")) || null,
        port: Number(attr("port")) || null,
        service: attr("svc_name") || attr("protocol") || null,
        description: tag(raw, "description").slice(0, 4000),
        solution: tag(raw, "solution").slice(0, 2000),
        evidence: (tag(raw, "plugin_output") || tag(raw, "synopsis")).slice(0, 4000),
        cve_ids: cves,
      });
    }
  }
  return out;
}

function splitCsvLine(line: string): string[] {
  const cells: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (c === '"') quoted = false;
      else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      cells.push(cur);
      cur = "";
    } else cur += c;
  }
  cells.push(cur);
  return cells;
}

const SEV_WORDS: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  moderate: 2,
  low: 1,
  info: 0,
  informational: 0,
  none: 0,
};

function parseCsv(text: string): ParsedFinding[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length);
  if (lines.length < 2) return [];
  const header = splitCsvLine(lines[0]!).map((h) => h.trim().toLowerCase());
  const idx = (...names: string[]) => {
    for (const n of names) {
      const i = header.indexOf(n);
      if (i >= 0) return i;
    }
    return -1;
  };
  const cols = {
    host: idx("host", "asset", "ip address", "dns name", "target"),
    plugin: idx("plugin id", "plugin_id", "id", "check id"),
    name: idx("name", "plugin name", "title", "vulnerability"),
    sev: idx("risk", "severity"),
    cvss: idx("cvss v3.0 base score", "cvss3 base score", "cvss", "cvss score"),
    port: idx("port"),
    proto: idx("protocol", "service"),
    desc: idx("description", "synopsis"),
    sol: idx("solution", "remediation", "fix"),
    output: idx("plugin output", "evidence", "details"),
    cve: idx("cve", "cves"),
  };
  const out: ParsedFinding[] = [];
  for (const line of lines.slice(1)) {
    const c = splitCsvLine(line);
    const get = (i: number) => (i >= 0 ? (c[i] ?? "").trim() : "");
    const sevRaw = get(cols.sev).toLowerCase();
    const severity =
      SEV_WORDS[sevRaw] ?? (Number(sevRaw) >= 0 && sevRaw !== "" ? Number(sevRaw) : 0);
    const title = get(cols.name);
    if (!title) continue;
    out.push({
      host: get(cols.host) || "imported-host",
      plugin_id: get(cols.plugin) || "IMPORT",
      title,
      severity: Math.max(0, Math.min(4, severity)),
      cvss: Number(get(cols.cvss)) || null,
      port: Number(get(cols.port)) || null,
      service: get(cols.proto) || null,
      description: get(cols.desc).slice(0, 4000),
      solution: get(cols.sol).slice(0, 2000),
      evidence: get(cols.output).slice(0, 4000),
      cve_ids: get(cols.cve)
        .split(/[,;\s]+/)
        .filter((x) => /^CVE-\d{4}-\d+$/i.test(x))
        .map((x) => x.toUpperCase()),
    });
  }
  return out;
}

/** Imports .nessus XML or CSV scan exports, enriching everything with live intelligence. */
export const importScanResults = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => importInput.parse(data))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const isXml =
      /\.nessus$|\.xml$/i.test(data.filename) || data.content.trimStart().startsWith("<");
    const parsed = isXml ? parseNessus(data.content) : parseCsv(data.content);
    if (!parsed.length) throw new Error("No findings could be parsed from this file.");

    const hosts = [...new Set(parsed.map((p) => p.host))];
    const assetIds = new Map<string, string>();
    for (const host of hosts) {
      const { data: existing } = await supabase
        .from("assets")
        .select("id")
        .eq("user_id", userId)
        .eq("target", host)
        .maybeSingle();
      if (existing) {
        assetIds.set(host, existing.id);
        continue;
      }
      const { data: created } = await supabase
        .from("assets")
        .insert({
          user_id: userId,
          name: data.assetName && hosts.length === 1 ? data.assetName : host,
          target: host,
          kind: "host",
          last_seen: new Date().toISOString(),
        })
        .select("id")
        .single();
      if (created) assetIds.set(host, created.id);
    }

    const counts = [0, 0, 0, 0, 0];
    for (const p of parsed) counts[Math.min(4, Math.max(0, p.severity))]!++;

    const { data: scan } = await supabase
      .from("scans")
      .insert({
        user_id: userId,
        asset_id: hosts.length === 1 ? (assetIds.get(hosts[0]!) ?? null) : null,
        name: `Import — ${data.filename}`,
        template: "import",
        target: hosts.join(", ").slice(0, 200),
        status: "completed",
        progress: 100,
        source: "import",
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        stats: {
          critical: counts[4],
          high: counts[3],
          medium: counts[2],
          low: counts[1],
          info: counts[0],
          total: parsed.length,
          hosts: hosts.length,
        },
      })
      .select("id")
      .single();

    const cveIds = [...new Set(parsed.flatMap((p) => p.cve_ids))].slice(0, 800);
    const intel = new Map<
      string,
      { epss: number | null; kev: boolean; cvss: number | null; cwe: string | null }
    >();
    for (let i = 0; i < cveIds.length; i += 200) {
      const { data: rows } = await supabase
        .from("cve_cache")
        .select("cve_id, epss, kev, cvss, cwe")
        .in("cve_id", cveIds.slice(i, i + 200));
      for (const r of rows ?? [])
        intel.set(r.cve_id, { epss: r.epss, kev: r.kev, cvss: r.cvss, cwe: r.cwe });
    }

    const rows: Record<string, unknown>[] = parsed.map((p) => {
      const best = p.cve_ids.map((c) => intel.get(c)).find(Boolean);
      const cvss = p.cvss ?? best?.cvss ?? null;
      return {
        user_id: userId,
        scan_id: scan?.id ?? null,
        asset_id: assetIds.get(p.host) ?? null,
        plugin_id: p.plugin_id,
        family: "imported",
        title: p.title,
        severity: p.severity,
        cvss,
        epss: best?.epss ?? null,
        kev: best?.kev ?? false,
        priority: priorityScore({
          cvss,
          severity: p.severity,
          epss: best?.epss ?? null,
          kev: best?.kev ?? false,
          confidence: "high",
        }),
        confidence: "high",
        cve_ids: p.cve_ids,
        cwe: best?.cwe ?? null,
        port: p.port,
        service: p.service,
        description: p.description,
        solution: p.solution,
        evidence: p.evidence,
        state: "open",
        due_at: slaDueDate(p.severity).toISOString(),
      };
    });

    for (let i = 0; i < rows.length; i += 500) {
      await supabase.from("findings").insert(rows.slice(i, i + 500) as never);
    }

    await supabase.from("audit_log").insert({
      user_id: userId,
      action: "scan.imported",
      entity: "scan",
      entity_id: scan?.id ?? null,
      detail: { filename: data.filename, findings: rows.length, hosts: hosts.length },
    });

    return { scanId: scan?.id ?? null, findings: rows.length, hosts: hosts.length, counts };
  });
