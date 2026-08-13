import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { Link } from "@tanstack/react-router";
import { getAttackGraph } from "@/lib/graph.functions";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { severityBg, severityLabel } from "@/lib/severity";
import { cn } from "@/lib/utils";
import { Network } from "lucide-react";

export function ExposureSummary() {
  const loadGraph = useServerFn(getAttackGraph);
  const { data: graph } = useQuery({ queryKey: ["attack-graph"], queryFn: () => loadGraph() });

  const paths = graph?.paths ?? [];

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Network className="size-4 text-primary" /> Attack paths
        </CardTitle>
        <Button asChild size="sm" variant="ghost">
          <Link to="/attack-graph">Open graph</Link>
        </Button>
      </CardHeader>
      <CardContent className="space-y-1.5">
        {paths.length === 0 && (
          <p className="py-4 text-sm text-muted-foreground">
            No internet-to-crown-jewel path derived yet. Scan an internet-facing asset to populate
            the graph.
          </p>
        )}
        {paths.slice(0, 6).map((p, i) => (
          <div
            key={i}
            className="flex flex-wrap items-center gap-2 rounded-md bg-muted/40 px-3 py-2 text-xs"
          >
            <span className={cn("rounded px-1.5 py-0.5 text-[10px]", severityBg(p.severity))}>
              {severityLabel(p.severity)}
            </span>
            {p.kev && (
              <span className="rounded bg-sev-critical/15 px-1.5 py-0.5 text-[10px] text-sev-critical">
                KEV
              </span>
            )}
            <span className="font-mono">{p.label}</span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
