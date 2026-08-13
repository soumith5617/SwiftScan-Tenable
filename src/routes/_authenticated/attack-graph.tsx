import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { getAttackGraph } from "@/lib/graph.functions";
import { AttackGraphViz } from "@/components/attack-graph-viz";
import { PageHeader, StatPill } from "@/components/soc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const Route = createFileRoute("/_authenticated/attack-graph")({
  head: () => ({
    meta: [
      { title: "Attack Graph — AegisScan" },
      {
        name: "description",
        content:
          "Visualise how an attacker moves from the internet through exposed services and hosts to your crown-jewel assets, derived from real scan evidence.",
      },
      { property: "og:title", content: "Attack Graph — AegisScan" },
      {
        property: "og:description",
        content: "Lateral movement paths derived from your own findings.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AttackGraphPage,
});

function AttackGraphPage() {
  const load = useServerFn(getAttackGraph);
  const { data, isLoading } = useQuery({ queryKey: ["attack-graph"], queryFn: () => load() });

  const graph = data ?? { nodes: [], edges: [], paths: [] };
  const kevPaths = graph.paths.filter((p) => p.kev).length;

  return (
    <div>
      <PageHeader
        title="Attack graph"
        description="Every hop is backed by an open finding on a real asset — no synthetic topology, no assumed reachability."
      />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatPill label="Nodes" value={graph.nodes.length} />
        <StatPill label="Edges" value={graph.edges.length} />
        <StatPill label="Attack paths" value={graph.paths.length} tone="high" />
        <StatPill label="Paths with known exploits" value={kevPaths} tone="critical" />
      </div>

      <Card className="mt-4">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Exposure topology</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="py-10 text-center text-sm text-muted-foreground">Building graph…</p>
          ) : (
            <AttackGraphViz graph={graph} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
