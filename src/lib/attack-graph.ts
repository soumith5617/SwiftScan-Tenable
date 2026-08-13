/**
 * Attack graph builder.
 *
 * Deterministically derives an exposure graph from the asset inventory and the
 * open findings: internet edge -> exposed services -> hosts -> internal tiers ->
 * crown jewels. Edges are labelled with the finding that makes the hop possible,
 * so every path in the UI is traceable back to collected evidence.
 */
export type GraphNode = {
  id: string;
  label: string;
  sublabel?: string;
  tier: number;
  kind: "internet" | "edge" | "service" | "host" | "datastore" | "identity" | "crown";
  severity: number;
  findings: number;
};

export type GraphEdge = {
  from: string;
  to: string;
  label: string;
  severity: number;
  kev: boolean;
};

export type AttackPath = {
  nodes: string[];
  label: string;
  severity: number;
  kev: boolean;
  score: number;
};

export type AttackGraph = { nodes: GraphNode[]; edges: GraphEdge[]; paths: AttackPath[] };

type AssetInput = {
  id: string;
  name: string;
  target: string;
  kind: string;
  criticality: string;
  internet_facing: boolean;
  technologies?: unknown;
  os?: string | null;
};

type FindingInput = {
  id: string;
  asset_id: string | null;
  title: string;
  severity: number;
  kev: boolean;
  service?: string | null;
  port?: number | null;
  family: string;
  attack_tactics?: string[] | null;
};

const DATA_KINDS = new Set(["database", "storage", "datastore"]);
const IDENTITY_HINTS = ["ldap", "kerberos", "domain", "ad", "sso", "idp", "auth"];

function tierFor(asset: AssetInput): { tier: number; kind: GraphNode["kind"] } {
  const hay = `${asset.name} ${asset.target} ${asset.kind}`.toLowerCase();
  if (DATA_KINDS.has(asset.kind) || /\b(db|sql|postgres|mysql|mongo|redis)\b/.test(hay))
    return { tier: 3, kind: "datastore" };
  if (IDENTITY_HINTS.some((h) => hay.includes(h))) return { tier: 4, kind: "identity" };
  if (asset.criticality === "critical") return { tier: 5, kind: "crown" };
  if (asset.internet_facing) return { tier: 2, kind: "host" };
  return { tier: 3, kind: "host" };
}

export function buildAttackGraph(assets: AssetInput[], findings: FindingInput[]): AttackGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  nodes.set("internet", {
    id: "internet",
    label: "Internet",
    sublabel: "Untrusted source",
    tier: 0,
    kind: "internet",
    severity: 0,
    findings: 0,
  });

  const byAsset = new Map<string, FindingInput[]>();
  for (const f of findings) {
    if (!f.asset_id) continue;
    const list = byAsset.get(f.asset_id) ?? [];
    list.push(f);
    byAsset.set(f.asset_id, list);
  }

  for (const asset of assets) {
    const { tier, kind } = tierFor(asset);
    const own = byAsset.get(asset.id) ?? [];
    const worst = own.reduce((max, f) => Math.max(max, f.severity), 0);
    nodes.set(asset.id, {
      id: asset.id,
      label: asset.name,
      sublabel: asset.target,
      tier,
      kind,
      severity: worst,
      findings: own.length,
    });

    // Exposed-service nodes sit between the internet and the host.
    if (asset.internet_facing) {
      const services = [
        ...new Set(own.filter((f) => f.service).map((f) => `${f.service}:${f.port ?? "-"}`)),
      ].slice(0, 4);
      if (services.length === 0) services.push("https:443");
      for (const svc of services) {
        const sid = `${asset.id}:${svc}`;
        const svcFindings = own.filter((f) => `${f.service}:${f.port ?? "-"}` === svc);
        const sev = svcFindings.reduce((m, f) => Math.max(m, f.severity), 0);
        nodes.set(sid, {
          id: sid,
          label: svc,
          sublabel: asset.name,
          tier: 1,
          kind: "service",
          severity: sev,
          findings: svcFindings.length,
        });
        edges.push({ from: "internet", to: sid, label: "reachable", severity: sev, kev: false });
        const entry = svcFindings.sort((a, b) => b.severity - a.severity)[0];
        edges.push({
          from: sid,
          to: asset.id,
          label: entry ? entry.title.slice(0, 60) : "service exposure",
          severity: entry?.severity ?? 0,
          kev: entry?.kev ?? false,
        });
      }
    }
  }

  // Lateral movement: a compromised host reaches deeper tiers.
  const assetNodes = assets
    .map((a) => ({ asset: a, node: nodes.get(a.id)! }))
    .filter((x) => Boolean(x.node));
  for (const src of assetNodes) {
    for (const dst of assetNodes) {
      if (src.node.id === dst.node.id) continue;
      if (dst.node.tier <= src.node.tier) continue;
      if (dst.node.tier - src.node.tier > 2) continue;
      const pivot = (byAsset.get(src.asset.id) ?? [])
        .filter(
          (f) =>
            f.severity >= 3 ||
            (f.attack_tactics ?? []).some((t) => /lateral|credential|exec/i.test(t)),
        )
        .sort((a, b) => b.severity - a.severity)[0];
      if (!pivot) continue;
      edges.push({
        from: src.node.id,
        to: dst.node.id,
        label: `pivot via ${pivot.title.slice(0, 44)}`,
        severity: pivot.severity,
        kev: pivot.kev,
      });
    }
  }

  // Highest-value complete paths, ranked by severity along the route.
  const adjacency = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    const list = adjacency.get(e.from) ?? [];
    list.push(e);
    adjacency.set(e.from, list);
  }

  const paths: AttackPath[] = [];
  const walk = (id: string, trail: string[], sev: number, kev: boolean, depth: number) => {
    const next = adjacency.get(id) ?? [];
    const node = nodes.get(id);
    const terminal =
      node && (node.kind === "crown" || node.kind === "datastore" || node.kind === "identity");
    if (terminal || next.length === 0 || depth >= 5) {
      if (trail.length >= 3 && terminal) {
        paths.push({
          nodes: [...trail],
          label: `${nodes.get(trail[trail.length - 1]!)?.label ?? "asset"} reachable from the internet`,
          severity: sev,
          kev,
          score: sev * 10 + trail.length + (kev ? 15 : 0),
        });
      }
      return;
    }
    for (const edge of next.slice(0, 6)) {
      if (trail.includes(edge.to)) continue;
      walk(edge.to, [...trail, edge.to], Math.max(sev, edge.severity), kev || edge.kev, depth + 1);
    }
  };
  walk("internet", ["internet"], 0, false, 0);

  paths.sort((a, b) => b.score - a.score);

  return { nodes: [...nodes.values()], edges, paths: paths.slice(0, 12) };
}

export const TIER_LABELS = [
  "Internet",
  "Exposed service",
  "Perimeter host",
  "Internal / data tier",
  "Identity tier",
  "Crown jewels",
];
