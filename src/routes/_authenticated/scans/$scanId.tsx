import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { getScan } from "@/lib/data.functions";
import { PageHeader, SeverityBadge, StatPill } from "@/components/soc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

export const Route = createFileRoute("/_authenticated/scans/$scanId")({
  head: () => ({
    meta: [
      { title: "Scan report — AegisScan" },
      {
        name: "description",
        content:
          "Full scan report with evidence, CVSS, EPSS exploit probability, KEV status and remediation guidance.",
      },
      { property: "og:title", content: "Scan report — AegisScan" },
      {
        property: "og:description",
        content: "Evidence-backed vulnerability report for a single scan.",
      },
      { property: "og:type", content: "article" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ScanDetail,
});

function ScanDetail() {
  const { scanId } = Route.useParams();
  const { data } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScan({ data: { id: scanId } }),
    refetchInterval: (q) => ((q.state.data?.scan?.status ?? "") === "running" ? 2000 : false),
  });

  if (!data?.scan) return <p className="text-sm text-muted-foreground">Loading scan…</p>;
  const scan = data.scan;
  const stats = (scan.stats ?? {}) as Record<string, unknown>;

  return (
    <div>
      <PageHeader
        title={scan.name}
        description={`${scan.target} · template ${scan.template} · ${scan.status}`}
      />

      {scan.status === "running" && (
        <div className="mb-4 flex items-center gap-3">
          <Progress value={scan.progress} className="h-2 max-w-md" />
          <span className="text-sm text-muted-foreground">{scan.current_step}</span>
        </div>
      )}

      {scan.error && (
        <p className="mb-4 rounded-md border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm">
          {scan.error}
        </p>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <StatPill label="Critical" value={Number(stats["critical"] ?? 0)} tone="critical" />
        <StatPill label="High" value={Number(stats["high"] ?? 0)} tone="high" />
        <StatPill label="Medium" value={Number(stats["medium"] ?? 0)} tone="medium" />
        <StatPill label="Low" value={Number(stats["low"] ?? 0)} tone="low" />
        <StatPill label="Info" value={Number(stats["info"] ?? 0)} tone="info" />
      </div>

      {Array.isArray(stats["technologies"]) && stats["technologies"].length > 0 && (
        <Card className="mt-4">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Fingerprinted technologies</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {stats["technologies"].map(
              (t: { name: string; version?: string; source: string }, i: number) => (
                <Badge key={i} variant="secondary">
                  {t.name}
                  {t.version ? ` ${t.version}` : ""}{" "}
                  <span className="ml-1 opacity-60">· {t.source}</span>
                </Badge>
              ),
            )}
          </CardContent>
        </Card>
      )}

      {Array.isArray(stats["ports"]) && stats["ports"].length > 0 && (
        <Card className="mt-4">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center justify-between">
              <span>Discovered Network Ports & Services ({stats["ports"].length})</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
              {stats["ports"].map(
                (p: { port: number; protocol: string; state: string; service: string; banner?: string }, i: number) => (
                  <div
                    key={i}
                    className="flex items-center justify-between rounded-md border border-border/70 bg-card p-2.5 text-xs shadow-xs"
                  >
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono text-xs font-semibold bg-primary/10 text-primary border-primary/20">
                        {p.port}/{p.protocol.toUpperCase()}
                      </Badge>
                      <div>
                        <span className="font-medium text-foreground capitalize block">{p.service}</span>
                        {p.banner && (
                          <span className="text-[11px] text-muted-foreground block truncate max-w-[180px]">
                            {p.banner}
                          </span>
                        )}
                      </div>
                    </div>
                    <Badge variant="outline" className="border-green-500/30 bg-green-500/10 text-green-500 text-[10px]">
                      {p.state}
                    </Badge>
                  </div>
                ),
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <Card className="mt-4">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Findings ({data.findings.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <Accordion type="multiple">
            {data.findings.map((f) => (
              <AccordionItem key={f.id} value={f.id}>
                <AccordionTrigger className="gap-3 text-left">
                  <SeverityBadge severity={f.severity} />
                  <span className="min-w-0 flex-1 truncate text-sm font-medium">{f.title}</span>
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {f.kev && <span className="mr-2 font-semibold text-sev-critical">KEV</span>}P{" "}
                    {f.priority.toFixed(1)}
                  </span>
                </AccordionTrigger>
                <AccordionContent className="space-y-3 text-sm">
                  <Meta f={f} />
                  <Section title="Description" body={f.description} />
                  <Section title="Evidence" body={f.evidence} mono />
                  <Section title="Remediation" body={f.solution} />
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
          {data.findings.length === 0 && (
            <p className="text-sm text-muted-foreground">No findings recorded.</p>
          )}
        </CardContent>
      </Card>

      {Array.isArray(stats["steps"]) && (
        <Card className="mt-4">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Engine execution trace</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-xs text-muted-foreground">
            {stats["steps"].map((s: { step: string; findings: number }, i: number) => (
              <div
                key={i}
                className="flex justify-between border-b border-border/50 py-1 last:border-0"
              >
                <span>{s.step}</span>
                <span className="tabular-nums">{s.findings} findings</span>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function Meta({ f }: { f: Record<string, unknown> }) {
  const cveIds = Array.isArray(f["cve_ids"]) ? (f["cve_ids"] as string[]) : [];
  const epss = typeof f["epss"] === "number" ? `${(f["epss"] * 100).toFixed(1)}%` : "—";
  const items = [
    ["Plugin", f["plugin_id"]],
    ["Family", f["family"]],
    ["CVSS", f["cvss"] ?? "—"],
    ["EPSS", epss],
    ["Confidence", f["confidence"]],
    ["CVEs", cveIds.join(", ") || "—"],
    ["CWE", f["cwe"] ?? "—"],
    ["Port", f["port"] ?? "—"],
  ] as const;
  return (
    <div className="grid grid-cols-2 gap-x-6 gap-y-1 rounded-md bg-muted/40 p-3 text-xs sm:grid-cols-4">
      {items.map(([k, v]) => (
        <div key={k}>
          <span className="text-muted-foreground">{k}: </span>
          <span className="font-medium">{String(v ?? "—")}</span>
        </div>
      ))}
    </div>
  );
}

function Section({ title, body, mono }: { title: string; body: string | null; mono?: boolean }) {
  if (!body) return null;
  return (
    <div>
      <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </p>
      <pre
        className={`whitespace-pre-wrap break-words text-sm ${mono ? "rounded-md bg-muted/60 p-3 font-mono text-xs" : "font-sans"}`}
      >
        {body}
      </pre>
    </div>
  );
}
