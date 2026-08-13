import { FRAMEWORKS, evaluateFramework, type ComplianceEvidence } from "./compliance";

type FindingRow = {
  family: string;
  severity: number;
  title: string;
  state: string;
  plugin_id: string;
};
type AssetRow = { id: string; internet_facing: boolean; last_seen: string | null };
type ScanRow = { id: string; asset_id: string | null; source: string; status: string };

export function buildEvidence(findings: FindingRow[], assets: AssetRow[], scans: ScanRow[]) {
  const byFamily: ComplianceEvidence["byFamily"] = {};
  for (const f of findings) {
    const entry = (byFamily[f.family] ??= { total: 0, maxSeverity: 0, titles: [] });
    entry.total++;
    entry.maxSeverity = Math.max(entry.maxSeverity, f.severity);
    if (entry.titles.length < 3) entry.titles.push(f.title);
  }

  const completed = scans.filter((s) => s.status === "completed");
  const scannedAssetIds = new Set(completed.map((s) => s.asset_id).filter(Boolean));

  const evidence: ComplianceEvidence = {
    byFamily,
    pluginIds: [...new Set(findings.map((f) => f.plugin_id))].slice(0, 200),
    totalOpen: findings.length,
    highOrCritical: findings.filter((f) => f.severity >= 3).length,
    assets: assets.length,
    internetFacing: assets.filter((a) => a.internet_facing).length,
    scannedAssets: scannedAssetIds.size,
    agentSourced: scans.filter((s) => s.source === "agent").length,
  };

  const frameworks = FRAMEWORKS.map((fw) => evaluateFramework(fw, evidence));
  return { evidence, frameworks };
}
