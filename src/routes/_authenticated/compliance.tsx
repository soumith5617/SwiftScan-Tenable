import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { getCompliance } from "@/lib/compliance.functions";
import { PageHeader } from "@/components/soc";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { CheckCircle2, XCircle, MinusCircle } from "lucide-react";

export const Route = createFileRoute("/_authenticated/compliance")({
  head: () => ({
    meta: [
      { title: "Compliance — AegisScan" },
      {
        name: "description",
        content:
          "CIS, DISA STIG, PCI DSS, HIPAA, ISO 27001, GDPR, NIST and custom policy controls with pass/fail evidence.",
      },
      { property: "og:title", content: "Compliance — AegisScan" },
      {
        property: "og:description",
        content: "Framework controls evaluated against live findings and asset posture.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: CompliancePage,
});

function CompliancePage() {
  const { data, isLoading } = useQuery({
    queryKey: ["compliance"],
    queryFn: () => getCompliance(),
  });
  const [active, setActive] = useState<string | null>(null);

  const frameworks = data?.frameworks ?? [];
  const current = frameworks.find((f) => f.key === active) ?? frameworks[0];

  return (
    <div>
      <PageHeader
        title="Compliance"
        description="Benchmark controls evaluated against current findings, asset posture and agent coverage. Controls the platform cannot observe are reported as not assessed rather than passed."
      />

      {isLoading && <p className="text-sm text-muted-foreground">Evaluating controls…</p>}

      {frameworks.length > 0 && (
        <>
          <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {frameworks.map((f) => (
              <button
                key={f.key}
                type="button"
                onClick={() => setActive(f.key)}
                className="text-left"
              >
                <Card
                  className={
                    current?.key === f.key
                      ? "border-primary/60"
                      : "transition-colors hover:border-primary/30"
                  }
                >
                  <CardContent className="space-y-2 py-4">
                    <p className="text-sm font-medium">{f.name}</p>
                    <div className="flex items-center gap-2">
                      <Progress value={f.score} className="h-1.5" />
                      <span className="font-mono text-xs tabular-nums">{f.score}%</span>
                    </div>
                    <p className="font-mono text-[11px] text-muted-foreground">
                      {f.pass} pass · {f.fail} fail · {f.notAssessed} n/a
                    </p>
                  </CardContent>
                </Card>
              </button>
            ))}
          </div>

          {current && (
            <Card>
              <CardContent className="py-5">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h2 className="font-semibold">{current.name}</h2>
                    <p className="text-xs text-muted-foreground">{current.description}</p>
                  </div>
                  <Badge variant="outline">{current.controls.length} controls</Badge>
                </div>
                <div className="divide-y divide-border">
                  {current.controls.map(({ control, status, detail }) => (
                    <div key={control.id} className="flex gap-3 py-3">
                      <StatusIcon status={status} />
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium">
                          <span className="mr-2 font-mono text-xs text-muted-foreground">
                            {control.id}
                          </span>
                          {control.title}
                        </p>
                        <p className="text-xs text-muted-foreground">{control.requirement}</p>
                        <p className="mt-1 text-xs">{detail}</p>
                        {status !== "pass" && (
                          <p className="mt-1 text-xs text-primary">
                            Remediation: {control.remediation}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <div className="mt-4 flex flex-wrap gap-3 text-xs text-muted-foreground">
            <span>Open findings: {data?.evidence.totalOpen ?? 0}</span>
            <span>High/critical: {data?.evidence.highOrCritical ?? 0}</span>
            <span>Assets: {data?.evidence.assets ?? 0}</span>
            <span>Agent-sourced scans: {data?.evidence.agentSourced ?? 0}</span>
            <Button
              variant="link"
              size="sm"
              className="h-auto p-0 text-xs"
              onClick={() => window.print()}
            >
              Print compliance report
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

function StatusIcon({ status }: { status: string }) {
  if (status === "pass") return <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-sev-low" />;
  if (status === "fail") return <XCircle className="mt-0.5 size-4 shrink-0 text-sev-critical" />;
  return <MinusCircle className="mt-0.5 size-4 shrink-0 text-muted-foreground" />;
}
