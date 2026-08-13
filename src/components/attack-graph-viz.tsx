import { useMemo, useState } from "react";
import type { AttackGraph, GraphNode } from "@/lib/attack-graph";
import { severityBg, severityLabel } from "@/lib/severity";
import { cn } from "@/lib/utils";

const TIER_LABELS = ["Internet", "Edge", "Exposed service", "Host", "Crown jewels"];

const KIND_FILL: Record<GraphNode["kind"], string> = {
  internet: "var(--muted-foreground)",
  edge: "var(--sev-medium)",
  service: "var(--sev-high)",
  host: "var(--primary)",
  datastore: "var(--sev-critical)",
  identity: "var(--sev-critical)",
  crown: "var(--sev-critical)",
};

const W = 940;
const ROW = 92;
const PAD = 56;

export function AttackGraphViz({ graph }: { graph: AttackGraph }) {
  const [hover, setHover] = useState<string | null>(null);

  const layout = useMemo(() => {
    const tiers = new Map<number, GraphNode[]>();
    for (const n of graph.nodes) {
      const list = tiers.get(n.tier) ?? [];
      list.push(n);
      tiers.set(n.tier, list);
    }
    const pos = new Map<string, { x: number; y: number }>();
    const maxTier = Math.max(0, ...graph.nodes.map((n) => n.tier));
    for (let t = 0; t <= maxTier; t++) {
      const row = (tiers.get(t) ?? []).slice(0, 8);
      row.forEach((n, i) => {
        const step = (W - PAD * 2) / Math.max(row.length, 1);
        pos.set(n.id, { x: PAD + step * i + step / 2, y: PAD + t * ROW });
      });
    }
    return { pos, height: PAD * 2 + maxTier * ROW, maxTier };
  }, [graph]);

  const highlighted = useMemo(() => {
    if (!hover) return null;
    const path = graph.paths.find((p) => p.nodes.includes(hover));
    return path ? new Set(path.nodes) : new Set([hover]);
  }, [hover, graph.paths]);

  if (!graph.nodes.length)
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No exposure graph yet — run a scan against an internet-facing asset to derive attack paths.
      </p>
    );

  return (
    <div className="space-y-4">
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${layout.height}`}
          className="w-full min-w-[720px]"
          role="img"
          aria-label="Attack graph"
        >
          {Array.from({ length: layout.maxTier + 1 }).map((_, t) => (
            <text key={t} x={8} y={PAD + t * ROW + 4} className="fill-muted-foreground text-[9px]">
              {TIER_LABELS[t] ?? `Tier ${t}`}
            </text>
          ))}

          {graph.edges.map((e, i) => {
            const a = layout.pos.get(e.from);
            const b = layout.pos.get(e.to);
            if (!a || !b) return null;
            const on = !highlighted || (highlighted.has(e.from) && highlighted.has(e.to));
            return (
              <g key={i} opacity={on ? 1 : 0.15}>
                <path
                  d={`M ${a.x} ${a.y + 14} C ${a.x} ${a.y + 50}, ${b.x} ${b.y - 50}, ${b.x} ${b.y - 14}`}
                  fill="none"
                  stroke={e.kev ? "var(--sev-critical)" : "var(--border)"}
                  strokeWidth={e.kev ? 2 : 1.25}
                  strokeDasharray={e.kev ? undefined : "4 3"}
                />
              </g>
            );
          })}

          {graph.nodes.map((n) => {
            const p = layout.pos.get(n.id);
            if (!p) return null;
            const on = !highlighted || highlighted.has(n.id);
            return (
              <g
                key={n.id}
                opacity={on ? 1 : 0.2}
                onMouseEnter={() => setHover(n.id)}
                onMouseLeave={() => setHover(null)}
                className="cursor-pointer"
              >
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={n.kind === "internet" ? 12 : 10}
                  fill={KIND_FILL[n.kind]}
                  opacity={0.85}
                />
                {n.findings > 0 && (
                  <text
                    x={p.x}
                    y={p.y + 3}
                    textAnchor="middle"
                    className="fill-background text-[8px] font-bold"
                  >
                    {n.findings}
                  </text>
                )}
                <text
                  x={p.x}
                  y={p.y + 26}
                  textAnchor="middle"
                  className="fill-foreground text-[10px] font-medium"
                >
                  {n.label.length > 22 ? `${n.label.slice(0, 21)}…` : n.label}
                </text>
                {n.sublabel && (
                  <text
                    x={p.x}
                    y={p.y + 37}
                    textAnchor="middle"
                    className="fill-muted-foreground text-[8px]"
                  >
                    {n.sublabel}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      <div>
        <p className="mb-2 text-xs uppercase tracking-wide text-muted-foreground">
          Lateral movement paths ({graph.paths.length})
        </p>
        <ul className="space-y-1.5">
          {graph.paths.slice(0, 8).map((p, i) => (
            <li
              key={i}
              onMouseEnter={() => setHover(p.nodes[0] ?? null)}
              onMouseLeave={() => setHover(null)}
              className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-xs"
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
            </li>
          ))}
          {graph.paths.length === 0 && (
            <li className="text-xs text-muted-foreground">
              No complete internet-to-crown-jewel path — exposure is currently contained.
            </li>
          )}
        </ul>
      </div>
    </div>
  );
}
