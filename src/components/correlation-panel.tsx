import { useMutation } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Brain } from "lucide-react";
import { correlateFindings } from "@/lib/ai.functions";
import { severityLabel } from "@/lib/severity";
import { toast } from "sonner";

import { sanitizeHtml } from "@/lib/sanitize";

/** Deterministic clustering of open findings, narrated by the AI layer. */
export function CorrelationPanel() {
  const correlate = useServerFn(correlateFindings);
  const mut = useMutation({
    mutationFn: () => correlate(),
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Brain className="size-4 text-primary" /> Risk correlation
        </CardTitle>
        <Button size="sm" variant="outline" disabled={mut.isPending} onClick={() => mut.mutate()}>
          {mut.isPending ? "Correlating…" : mut.data ? "Re-run" : "Correlate"}
        </Button>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {!mut.data && !mut.isPending && (
          <p className="text-muted-foreground">
            Group duplicate findings by CVE and plugin identity, then generate an executive
            narrative and a likely attack path from the evidence already collected.
          </p>
        )}
        {mut.isPending && (
          <p className="text-muted-foreground">
            Clustering open findings and interpreting the evidence…
          </p>
        )}
        {mut.data && (
          <>
            <div className="whitespace-pre-wrap leading-relaxed">
              {mut.data.narrative
                .split("\n")
                .filter(Boolean)
                .map((line, i) => (
                  <p
                    key={i}
                    className={
                      line.startsWith("**") ? "mt-3 font-semibold" : "text-muted-foreground"
                    }
                    dangerouslySetInnerHTML={{
                      __html: sanitizeHtml(line.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")),
                    }}
                  />
                ))}
            </div>
            {mut.data.clusters.length > 0 && (
              <ul className="divide-y divide-border rounded-md border border-border">
                {mut.data.clusters.slice(0, 8).map((c) => (
                  <li key={c.key} className="flex items-center gap-3 px-3 py-2 text-xs">
                    <Badge variant="outline">{severityLabel(c.severity)}</Badge>
                    <span className="flex-1 truncate">{c.label}</span>
                    <span className="tabular-nums text-muted-foreground">×{c.count}</span>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
