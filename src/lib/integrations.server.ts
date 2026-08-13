import type { SupabaseClient } from "@supabase/supabase-js";

type Client = SupabaseClient;

export type DispatchFinding = {
  id: string;
  title: string;
  severity: number;
  plugin_id: string;
  priority: number;
  kev: boolean;
};

const SEV_LABEL = ["Info", "Low", "Medium", "High", "Critical"];

/** Shapes one finding into the payload each destination system expects. */
export function buildPayload(
  kind: string,
  finding: DispatchFinding,
  meta: { target: string; scanId: string },
  config: Record<string, unknown>,
) {
  const label = SEV_LABEL[Math.min(4, Math.max(0, finding.severity))] ?? "Info";
  const summary = `[${label}] ${finding.title} — ${meta.target}`;

  switch (kind) {
    case "jira":
      return {
        fields: {
          project: { key: String(config["projectKey"] ?? "SEC") },
          issuetype: { name: String(config["issueType"] ?? "Bug") },
          summary,
          description: `Detected on ${meta.target}\nPlugin: ${finding.plugin_id}\nSeverity: ${label}\nVPR priority: ${finding.priority}\nCISA KEV: ${finding.kev ? "yes" : "no"}\nScan: ${meta.scanId}`,
          labels: ["vulnerability", `severity-${label.toLowerCase()}`],
        },
      };
    case "servicenow":
      return {
        short_description: summary,
        description: `Plugin ${finding.plugin_id} on ${meta.target}. VPR ${finding.priority}.`,
        urgency: finding.severity >= 4 ? "1" : finding.severity >= 3 ? "2" : "3",
        impact: finding.kev ? "1" : "3",
        category: "security",
      };
    case "splunk":
      return {
        sourcetype: "aegis:finding",
        event: {
          finding_id: finding.id,
          plugin_id: finding.plugin_id,
          title: finding.title,
          severity: label,
          severity_num: finding.severity,
          priority: finding.priority,
          kev: finding.kev,
          target: meta.target,
          scan_id: meta.scanId,
        },
      };
    case "sentinel":
      return {
        DisplayName: summary,
        Severity: label,
        Description: `Plugin ${finding.plugin_id} on ${meta.target}`,
        ProviderName: "Aegis",
        AlertLink: null,
        ExtendedProperties: { priority: finding.priority, kev: finding.kev, scan_id: meta.scanId },
      };
    case "slack":
      return {
        text: `:rotating_light: *${label}* — ${finding.title}`,
        blocks: [
          { type: "section", text: { type: "mrkdwn", text: `*${label}* — ${finding.title}` } },
          {
            type: "context",
            elements: [
              {
                type: "mrkdwn",
                text: `Target: \`${meta.target}\` · Plugin: \`${finding.plugin_id}\` · VPR ${finding.priority}${finding.kev ? " · CISA KEV" : ""}`,
              },
            ],
          },
        ],
      };
    default:
      return {
        event: "finding.created",
        finding: {
          id: finding.id,
          plugin_id: finding.plugin_id,
          title: finding.title,
          severity: finding.severity,
          severity_label: label,
          priority: finding.priority,
          kev: finding.kev,
        },
        target: meta.target,
        scan_id: meta.scanId,
        sent_at: new Date().toISOString(),
      };
  }
}

function headersFor(kind: string, config: Record<string, unknown>): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = config["token"] ? String(config["token"]) : "";
  if (!token) return headers;
  if (kind === "splunk") headers["Authorization"] = `Splunk ${token}`;
  else if (kind === "jira" || kind === "servicenow") headers["Authorization"] = `Basic ${token}`;
  else headers["Authorization"] = `Bearer ${token}`;
  return headers;
}

export async function deliverOne(
  integration: { id: string; kind: string; endpoint: string; config: Record<string, unknown> },
  finding: DispatchFinding,
  meta: { target: string; scanId: string },
): Promise<{ status: number; detail: string }> {
  const body = buildPayload(integration.kind, finding, meta, integration.config ?? {});
  try {
    const res = await fetch(integration.endpoint, {
      method: "POST",
      headers: headersFor(integration.kind, integration.config ?? {}),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    const text = (await res.text().catch(() => "")).slice(0, 400);
    return { status: res.status, detail: res.ok ? "delivered" : text || res.statusText };
  } catch (err) {
    return { status: 0, detail: err instanceof Error ? err.message : "network error" };
  }
}

/** Fan out newly created findings to every enabled integration above threshold. */
export async function dispatchFindings(
  supabase: Client,
  userId: string,
  findings: DispatchFinding[],
  meta: { target: string; scanId: string },
) {
  const { data: integrations } = await supabase
    .from("integrations")
    .select("id, kind, name, endpoint, config, min_severity")
    .eq("user_id", userId)
    .eq("enabled", true);
  if (!integrations?.length) return { delivered: 0 };

  let delivered = 0;
  const logs: Record<string, unknown>[] = [];
  for (const integration of integrations) {
    const matching = findings.filter((f) => f.severity >= integration.min_severity).slice(0, 25);
    for (const finding of matching) {
      const result = await deliverOne(integration, finding, meta);
      const ok = result.status >= 200 && result.status < 300;
      if (ok) delivered++;
      logs.push({
        user_id: userId,
        integration_id: integration.id,
        finding_id: finding.id,
        status: ok ? "delivered" : "failed",
        http_status: result.status,
        detail: result.detail,
      });
    }
    await supabase
      .from("integrations")
      .update({
        last_delivery_at: new Date().toISOString(),
        last_status: logs.at(-1)?.["status"] ?? "skipped",
      })
      .eq("id", integration.id);
  }
  if (logs.length) await supabase.from("integration_deliveries").insert(logs);
  return { delivered };
}
