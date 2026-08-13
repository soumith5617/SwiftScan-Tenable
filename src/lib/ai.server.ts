import { generateText, streamText } from "ai";
import { createLovableAiGatewayProvider, AI_MODEL } from "./ai-gateway.server";
import { severityLabel } from "./severity";

type FindingRow = Record<string, unknown> & {
  title: string;
  severity: number;
  family: string;
  plugin_id: string;
};

function gateway() {
  const key = process.env["LOVABLE_API_KEY"];
  if (!key) throw new Error("AI is not configured for this project.");
  return createLovableAiGatewayProvider(key);
}

const SYSTEM = `You are a senior vulnerability analyst inside a scanning platform.
You never speculate about whether a vulnerability exists — the scanner already
produced the evidence. You interpret that evidence only.
Be concrete, terse and technical. No marketing language, no filler preamble.
If the evidence is weak, say so and name the extra verification needed.`;

const PROMPTS = {
  remediation: `Write remediation guidance in markdown with exactly these sections:
**Impact** (2 sentences max) · **Fix** (numbered, concrete steps) · **Verification** (how to confirm the fix took effect) · **Confidence** (what the evidence proves and what it doesn't).`,
  explain: `Explain this finding in plain language a non-technical executive understands: what it is, what an attacker could realistically do with it, and how urgent it is. 150 words max, no bullet lists.`,
  script: `Produce ready-to-run fix scripts in markdown fenced blocks: one bash/shell block for Linux, one PowerShell block for Windows, and one Terraform/config block if the fix is infrastructure-level. Precede each with a one-line comment on what it changes. If a platform does not apply, say so instead of inventing a script.`,
} as const;

export async function generateAnalysis(
  kind: "remediation" | "explain" | "script",
  finding: FindingRow,
): Promise<string> {
  const evidence = [
    `Title: ${finding.title}`,
    `Severity: ${severityLabel(finding.severity)} (${finding.severity}/4)`,
    `Plugin: ${finding.plugin_id} · family: ${finding.family}`,
    finding["cvss"] ? `CVSS: ${finding["cvss"]}` : null,
    finding["epss"] ? `EPSS: ${finding["epss"]}` : null,
    finding["kev"] ? `Listed in CISA KEV: yes` : null,
    Array.isArray(finding["cve_ids"]) && finding["cve_ids"].length
      ? `CVEs: ${(finding["cve_ids"] as string[]).join(", ")}`
      : null,
    finding["cwe"] ? `CWE: ${finding["cwe"]}` : null,
    finding["service"]
      ? `Service: ${finding["service"]}${finding["port"] ? `:${finding["port"]}` : ""}`
      : null,
    `Confidence: ${finding["confidence"]}`,
    finding["description"] ? `\nScanner description:\n${finding["description"]}` : null,
    finding["evidence"] ? `\nRaw evidence:\n${String(finding["evidence"]).slice(0, 2000)}` : null,
    finding["solution"] ? `\nBuilt-in solution hint:\n${finding["solution"]}` : null,
  ]
    .filter(Boolean)
    .join("\n");

  const result = streamText({
    model: gateway()(AI_MODEL),
    system: SYSTEM,
    prompt: `${PROMPTS[kind]}\n\n--- EVIDENCE ---\n${evidence}`,
  });
  return await result.text;
}

export type Cluster = {
  key: string;
  label: string;
  severity: number;
  count: number;
  findingIds: string[];
};

/**
 * Deterministic clustering (plugin/CVE/family identity) — the AI is used to
 * narrate clusters, never to decide membership.
 */
export function clusterFindings(
  findings: {
    id: string;
    title: string;
    severity: number;
    family: string;
    plugin_id: string;
    cve_ids: string[] | null;
  }[],
): Cluster[] {
  const map = new Map<string, Cluster>();
  for (const f of findings) {
    const key = f.cve_ids?.length ? `cve:${[...f.cve_ids].sort()[0]}` : `plugin:${f.plugin_id}`;
    const existing = map.get(key);
    if (existing) {
      existing.count++;
      existing.severity = Math.max(existing.severity, f.severity);
      existing.findingIds.push(f.id);
    } else {
      map.set(key, { key, label: f.title, severity: f.severity, count: 1, findingIds: [f.id] });
    }
  }
  return [...map.values()].sort((a, b) => b.severity - a.severity || b.count - a.count);
}

export async function generateNarrative(
  findings: { title: string; severity: number; priority: number; kev: boolean }[],
  clusters: Cluster[],
): Promise<string> {
  const top = clusters
    .slice(0, 12)
    .map((c) => `- ${c.label} — ${severityLabel(c.severity)} × ${c.count} instances`);
  const kev = findings.filter((f) => f.kev).length;
  const critical = findings.filter((f) => f.severity >= 4).length;

  const { text } = await generateText({
    model: gateway()(AI_MODEL),
    system: SYSTEM,
    prompt: `Write an executive risk narrative in markdown, max 220 words, with three short sections:
**Where we stand**, **What to fix first** (ordered, name the clusters), **Likely attack path** (one plausible chain using only the clusters listed — say "no clear chain from current evidence" if none exists).

Portfolio: ${findings.length} open findings, ${critical} critical, ${kev} on the CISA Known Exploited list, grouped into ${clusters.length} distinct issues.

Top clusters:
${top.join("\n")}`,
  });
  return text;
}
