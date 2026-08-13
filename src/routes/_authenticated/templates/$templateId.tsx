import { createFileRoute, Link, notFound, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getTemplate,
  MODE_CLASS,
  MODE_LABEL,
  SCAN_WORKFLOW,
  workflowStages,
  agentJobContract,
} from "@/lib/templates";
import { createScan } from "@/lib/data.functions";
import { runScan, recomputePriorities } from "@/lib/scans.functions";
import { PageHeader } from "@/components/soc";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { ArrowLeft, Copy } from "lucide-react";

export const Route = createFileRoute("/_authenticated/templates/$templateId")({
  loader: ({ params }) => {
    const template = getTemplate(params.templateId);
    if (!template) throw notFound();
    return { templateId: template.id };
  },
  head: ({ params }) => {
    const tpl = getTemplate(params.templateId);
    const name = tpl?.name ?? "Scan template";
    const desc = tpl?.description ?? "Scan template specification.";
    return {
      meta: [
        { title: `${name} — AegisScan` },
        { name: "description", content: desc.slice(0, 155) },
        { property: "og:title", content: `${name} — AegisScan` },
        { property: "og:description", content: desc.slice(0, 155) },
        { property: "og:type", content: "article" },
        { name: "twitter:card", content: "summary_large_image" },
      ],
    };
  },
  errorComponent: () => (
    <p className="p-6 text-sm text-muted-foreground">This template could not be loaded.</p>
  ),
  notFoundComponent: () => (
    <p className="p-6 text-sm text-muted-foreground">Unknown scan template.</p>
  ),
  component: TemplateDetail,
});

function TemplateDetail() {
  const { templateId } = Route.useParams();
  const template = getTemplate(templateId)!;
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [target, setTarget] = useState("");
  const stages = workflowStages(template);

  const launch = useMutation({
    mutationFn: async () => {
      const scan = await createScan({
        data: {
          name: `${template.name} — ${target}`,
          target,
          template: template.id,
          createAsset: true,
        },
      });
      await qc.invalidateQueries({ queryKey: ["scans"] });
      return runScan({ data: { scanId: scan.id } });
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      if (res.ok) {
        toast.success(`Scan complete — ${res.findings} findings`);
        navigate({ to: "/scans" });
      } else toast.error(`Scan did not complete: ${res.reason}`);
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Scan failed"),
  });

  const queueAgent = useMutation({
    mutationFn: async () => {
      const scan = await createScan({
        data: {
          name: `${template.name} — ${target}`,
          target,
          template: template.id,
          createAsset: true,
        },
      });
      return runScan({ data: { scanId: scan.id } });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      toast.success("Job queued — awaiting agent results");
      navigate({ to: "/scans" });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Could not queue job"),
  });

  const live = useMutation({
    mutationFn: () => recomputePriorities(),
    onSuccess: (r) => {
      toast.success(`Re-scored ${r.updated} findings against current intelligence`);
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  const contract = JSON.stringify(agentJobContract(template, target || "10.0.0.0/24"), null, 2);

  return (
    <div>
      <Link
        to="/templates"
        className="mb-3 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3" /> All templates
      </Link>
      <PageHeader title={template.name} description={template.purpose}>
        <Badge variant="outline" className={MODE_CLASS[template.mode]}>
          {MODE_LABEL[template.mode]}
        </Badge>
      </PageHeader>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardContent className="space-y-5 py-5">
            <Section title="Techniques" items={template.techniques} />
            <Section title="Detects" items={template.detects} />
            {template.families.length > 0 && (
              <Section title="Engine plugin families" items={template.families} mono />
            )}
            {template.credentials?.length ? (
              <Section title="Credentials required" items={template.credentials} />
            ) : null}

            <div>
              <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Pipeline stages performed
              </p>
              <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                {SCAN_WORKFLOW.map((s) => {
                  const on = stages.includes(s);
                  return (
                    <span
                      key={s}
                      className={
                        on
                          ? "rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-primary"
                          : "rounded border border-border px-1.5 py-0.5 text-muted-foreground/50 line-through"
                      }
                    >
                      {s}
                    </span>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="space-y-3 py-5">
            {template.mode === "native" && (
              <>
                <p className="text-sm font-medium">Run this scan</p>
                <div className="space-y-1.5">
                  <Label htmlFor="target">Target</Label>
                  <Input
                    id="target"
                    placeholder="192.168.1.1 or 10.0.0.1 or https://app.example.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Supports IPv4/IPv6 addresses, local subnets, hostnames, and URLs.
                  </p>
                </div>
                <Button
                  className="w-full"
                  disabled={!target || launch.isPending}
                  onClick={() => launch.mutate()}
                >
                  {launch.isPending ? "Scanning…" : "Start scan"}
                </Button>
              </>
            )}

            {template.mode === "agent" && (
              <>
                <p className="text-sm font-medium">Queue an agent job</p>
                <p className="text-xs text-muted-foreground">
                  This assessment needs raw sockets, credentials or local host access, which the
                  hosted engine cannot perform. Queue the job here and have your agent POST results
                  to the ingest API — they are correlated and scored exactly like native scans.
                </p>
                <div className="space-y-1.5">
                  <Label htmlFor="agent-target">Target</Label>
                  <Input
                    id="agent-target"
                    placeholder="10.0.0.0/24 or host.internal"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                </div>
                <Button
                  className="w-full"
                  disabled={!target || queueAgent.isPending}
                  onClick={() => queueAgent.mutate()}
                >
                  {queueAgent.isPending ? "Queueing…" : "Queue agent job"}
                </Button>
                <Button variant="outline" className="w-full gap-2" onClick={() => copy(contract)}>
                  <Copy className="size-4" /> Copy job contract
                </Button>
                <pre className="max-h-72 overflow-auto rounded-md border border-border bg-muted/40 p-3 font-mono text-[10px] leading-relaxed">
                  {contract}
                </pre>
              </>
            )}

            {template.mode === "analysis" && (
              <>
                <p className="text-sm font-medium">Analysis template</p>
                <p className="text-xs text-muted-foreground">
                  This template evaluates data already in the platform — no network traffic is
                  generated.
                </p>
                {template.framework ? (
                  <Button className="w-full" onClick={() => navigate({ to: "/compliance" })}>
                    Open compliance results
                  </Button>
                ) : (
                  <Button
                    className="w-full"
                    disabled={live.isPending}
                    onClick={() => live.mutate()}
                  >
                    {live.isPending ? "Re-scoring…" : "Run live results analysis"}
                  </Button>
                )}
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Section({ title, items, mono }: { title: string; items: string[]; mono?: boolean }) {
  return (
    <div>
      <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {title}
      </p>
      <ul className="grid gap-1 sm:grid-cols-2">
        {items.map((i) => (
          <li key={i} className={`flex gap-2 text-sm ${mono ? "font-mono text-xs" : ""}`}>
            <span className="text-primary">•</span>
            {i}
          </li>
        ))}
      </ul>
    </div>
  );
}

function copy(text: string) {
  void navigator.clipboard.writeText(text);
  toast.success("Copied to clipboard");
}
