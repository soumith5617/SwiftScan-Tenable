import { ReportFormat, ReportKind } from "./types/enterprise";

export interface FindingReportItem {
  id: string;
  severity: number;
  title: string;
  plugin_id?: string;
  cvss?: number | null;
  epss?: number | null;
  kev?: boolean;
  priority?: number;
  solution?: string | null;
  description?: string | null;
  cve_ids?: string[];
  state?: string;
  due_at?: string | null;
  asset?: {
    id?: string;
    name?: string;
    target?: string;
    criticality?: string;
  } | null;
}

export interface AssetReportItem {
  id: string;
  name: string;
  target: string;
  kind?: string;
  criticality?: string;
  internet_facing?: boolean;
  risk_score?: number;
  openFindings?: number;
}

export interface ScanReportItem {
  id: string;
  name?: string;
  target?: string;
  status?: string;
  created_at?: string;
}

export interface ReportGenerationPayload {
  kind: ReportKind;
  format: ReportFormat;
  title: string;
  findings: FindingReportItem[];
  assets: AssetReportItem[];
  scans: ScanReportItem[];
  complianceScorecards?: unknown[];
  userEmail?: string | null;
}

export class ReportGenerator {
  /**
   * Generates formatted report content based on kind and format
   */
  public static generate(payload: ReportGenerationPayload): {
    content: string;
    mimeType: string;
    fileName: string;
  } {
    const { kind, format, title, findings, assets, scans } = payload;
    const dateStr = new Date().toISOString().slice(0, 10);
    const safeTitle = title.toLowerCase().replace(/[^a-z0-9]/g, "-");

    if (format === "csv") {
      return {
        content: this.generateCsv(kind, findings, assets),
        mimeType: "text/csv;charset=utf-8;",
        fileName: `${safeTitle}-${dateStr}.csv`,
      };
    }

    if (format === "json") {
      const data = {
        meta: {
          title,
          generated_at: new Date().toISOString(),
          kind,
          total_findings: findings.length,
          total_assets: assets.length,
        },
        findings,
        assets,
        scans,
      };
      return {
        content: JSON.stringify(data, null, 2),
        mimeType: "application/json",
        fileName: `${safeTitle}-${dateStr}.json`,
      };
    }

    // Default HTML for print / PDF generation
    return {
      content: this.generateHtml(payload),
      mimeType: "text/html;charset=utf-8;",
      fileName: `${safeTitle}-${dateStr}.html`,
    };
  }

  private static generateCsv(
    kind: ReportKind,
    findings: FindingReportItem[],
    assets: AssetReportItem[],
  ): string {
    if (kind === "asset") {
      const headers = [
        "ID",
        "Name",
        "Target",
        "Type",
        "Criticality",
        "Internet Facing",
        "Risk Score",
        "Open Findings",
      ];
      const rows = assets.map((a) => [
        `"${a.id}"`,
        `"${(a.name || "").replace(/"/g, '""')}"`,
        `"${(a.target || "").replace(/"/g, '""')}"`,
        `"${a.kind || ""}"`,
        `"${a.criticality || ""}"`,
        a.internet_facing ? "TRUE" : "FALSE",
        a.risk_score || 0,
        a.openFindings || 0,
      ]);
      return [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    }

    // Findings CSV
    const headers = [
      "ID",
      "Severity",
      "Title",
      "Plugin ID",
      "CVSS",
      "EPSS",
      "KEV",
      "Priority",
      "Target",
      "State",
      "Due Date",
    ];
    const rows = findings.map((f) => [
      `"${f.id}"`,
      f.severity,
      `"${(f.title || "").replace(/"/g, '""')}"`,
      `"${f.plugin_id || ""}"`,
      f.cvss ?? "",
      f.epss != null ? (Number(f.epss) * 100).toFixed(1) + "%" : "",
      f.kev ? "TRUE" : "FALSE",
      Number(f.priority || 0).toFixed(1),
      `"${(f.asset?.target || "").replace(/"/g, '""')}"`,
      `"${f.state || ""}"`,
      `"${f.due_at ? f.due_at.slice(0, 10) : ""}"`,
    ]);
    return [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
  }

  private static generateHtml(payload: ReportGenerationPayload): string {
    const { title, kind, findings, assets } = payload;
    const criticals = findings.filter((f) => f.severity === 4);
    const highs = findings.filter((f) => f.severity === 3);
    const mediums = findings.filter((f) => f.severity === 2);
    const lows = findings.filter((f) => f.severity === 1);
    const kevs = findings.filter((f) => f.kev);

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${title} — AegisScan Security Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; line-height: 1.5; padding: 40px; max-width: 960px; margin: 0 auto; }
    h1, h2, h3 { color: #0f172a; margin-top: 24px; margin-bottom: 8px; }
    .header { border-bottom: 2px solid #0284c7; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }
    .meta { font-size: 12px; color: #64748b; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; text-align: center; }
    .card .val { font-size: 24px; font-weight: bold; margin-top: 4px; }
    .card.crit .val { color: #ef4444; }
    .card.high .val { color: #f97316; }
    .card.med .val { color: #eab308; }
    .card.kev .val { color: #b91c1c; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th { background: #f1f5f9; text-align: left; padding: 8px 12px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #475569; border-bottom: 1px solid #cbd5e1; }
    td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }
    .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .badge-4 { background: #fee2e2; color: #991b1b; }
    .badge-3 { background: #ffedd5; color: #9a3412; }
    .badge-2 { background: #fef9c3; color: #854d0e; }
    .badge-1 { background: #dbeafe; color: #1e40af; }
    .badge-0 { background: #f1f5f9; color: #475569; }
    .evidence { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; font-family: monospace; font-size: 11px; padding: 8px; white-space: pre-wrap; margin-top: 4px; }
    @media print { body { padding: 0; } .card { border: 1px solid #ccc; } }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>AegisScan Vulnerability Assessment</h1>
      <p style="margin: 0; font-weight: 600; color: #0284c7;">${title} (${kind.toUpperCase()} REPORT)</p>
    </div>
    <div class="meta">
      <p style="margin: 0;">Generated: ${new Date().toUTCString()}</p>
      <p style="margin: 0;">Platform: AegisScan Enterprise v2.4</p>
    </div>
  </div>

  <h2>Executive Risk Summary</h2>
  <div class="grid">
    <div class="card crit"><div style="font-size: 11px; text-transform: uppercase; color: #64748b;">Critical Vulnerabilities</div><div class="val">${criticals.length}</div></div>
    <div class="card high"><div style="font-size: 11px; text-transform: uppercase; color: #64748b;">High Vulnerabilities</div><div class="val">${highs.length}</div></div>
    <div class="card med"><div style="font-size: 11px; text-transform: uppercase; color: #64748b;">Medium Vulnerabilities</div><div class="val">${mediums.length}</div></div>
    <div class="card kev"><div style="font-size: 11px; text-transform: uppercase; color: #64748b;">Known Exploited (KEV)</div><div class="val">${kevs.length}</div></div>
  </div>

  <h2>Detailed Finding Breakdown (${findings.length} total)</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 80px;">Severity</th>
        <th>Title &amp; Advisory</th>
        <th>Target Asset</th>
        <th style="text-align: right;">Priority</th>
        <th style="text-align: right;">CVSS</th>
        <th>Remediation Advice</th>
      </tr>
    </thead>
    <tbody>
      ${findings
        .map(
          (f) => `
        <tr>
          <td><span class="badge badge-${f.severity}">${f.severity === 4 ? "CRITICAL" : f.severity === 3 ? "HIGH" : f.severity === 2 ? "MEDIUM" : f.severity === 1 ? "LOW" : "INFO"}</span></td>
          <td>
            <strong>${f.title}</strong>
            <div style="font-size: 11px; color: #64748b; font-family: monospace;">${f.plugin_id} ${f.cve_ids?.length ? `· ${f.cve_ids.join(", ")}` : ""}</div>
          </td>
          <td style="font-family: monospace; font-size: 11px;">${f.asset?.target || "—"}</td>
          <td style="text-align: right; font-weight: bold; font-family: monospace;">${Number(f.priority || 0).toFixed(1)}</td>
          <td style="text-align: right; font-family: monospace;">${f.cvss ?? "—"}</td>
          <td style="font-size: 11px; max-width: 250px;">${f.solution || "Refer to vendor advisory."}</td>
        </tr>
      `,
        )
        .join("")}
    </tbody>
  </table>

  <div style="margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 11px; color: #94a3b8; text-align: center;">
    Confidential Security Assessment Document · Generated by AegisScan Platform
  </div>
</body>
</html>`;
  }
}
