import { createFileRoute, Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/theme-toggle";
import {
  ShieldCheck,
  Zap,
  Radar,
  Database,
  Upload,
  GitBranch,
  Lock,
  Gauge,
  Boxes,
  ScanSearch,
} from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "AegisScan — Fast, Accurate Vulnerability Scanning Platform" },
      {
        name: "description",
        content:
          "AegisScan is a modern Nessus alternative: async scan engine, live NVD/KEV/EPSS intelligence, VPR-style prioritisation, Nessus imports and agent ingest.",
      },
      { property: "og:title", content: "AegisScan — Modern Vulnerability Management" },
      {
        property: "og:description",
        content:
          "Async scanning, live exploit intelligence and evidence-backed findings in one fast workspace.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Landing,
});

const FEATURES = [
  {
    icon: ScanSearch,
    title: "Asset & service discovery",
    body: "Host reachability, redirect chains, technology fingerprinting from headers, cookies, bodies and TLS metadata.",
  },
  {
    icon: Radar,
    title: "Plugin-based detection",
    body: "Independent check families — TLS, headers, exposures, web app probes, API discovery — run concurrently and are versioned like Nessus plugins.",
  },
  {
    icon: Database,
    title: "Live CVE intelligence",
    body: "NVD records, CISA KEV catalog and FIRST EPSS probabilities cached locally for millisecond correlation.",
  },
  {
    icon: Gauge,
    title: "VPR-style prioritisation",
    body: "CVSS blended with exploit probability, known-exploited status, asset criticality and internet exposure into a 0-10 score.",
  },
  {
    icon: Upload,
    title: "Nessus & CSV import",
    body: "Drop a .nessus or CSV export and every finding is parsed, deduplicated into assets and re-enriched.",
  },
  {
    icon: GitBranch,
    title: "Agent ingest API",
    body: "Distributed Rust/Go agents post raw socket, SMB/SSH and OS fingerprint results into the same correlation engine.",
  },
  {
    icon: Lock,
    title: "Compliance & SLA tracking",
    body: "Per-severity SLA clocks, remediation states, false-positive handling and a full audit trail.",
  },
  {
    icon: Boxes,
    title: "Asset inventory",
    body: "Criticality-weighted inventory across web, host, API, cloud and container assets with rolling risk scores.",
  },
];

const WORKFLOW = [
  "Target normalisation & reachability",
  "Service + technology fingerprinting",
  "Plugin selection per template",
  "Concurrent plugin execution",
  "CVE correlation (NVD · KEV · EPSS)",
  "Priority scoring & SLA assignment",
  "Evidence-backed reporting",
];

function Landing() {
  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-30 border-b border-border/60 bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
          <span className="flex items-center gap-2 font-semibold">
            <ShieldCheck className="size-5 text-primary" /> AegisScan
          </span>
          <div className="flex items-center gap-2">
            <ThemeToggle className="mr-1" />
            <Button asChild variant="ghost" size="sm">
              <Link to="/auth">Sign in</Link>
            </Button>
            <Button asChild size="sm">
              <Link to="/auth">Start scanning</Link>
            </Button>
          </div>
        </div>
      </header>

      <section className="mx-auto max-w-6xl px-4 py-20 text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-border px-3 py-1 text-xs text-muted-foreground">
          <Zap className="size-3 text-primary" /> Async engine · live exploit intelligence
        </span>
        <h1 className="mx-auto mt-6 max-w-3xl text-4xl font-semibold tracking-tight sm:text-6xl">
          Vulnerability management without the wait
        </h1>
        <p className="mx-auto mt-5 max-w-2xl text-lg text-muted-foreground">
          Everything teams rely on Nessus for — discovery, plugin-based detection, compliance
          evidence and risk prioritisation — rebuilt on a concurrent engine with live NVD, CISA KEV
          and EPSS intelligence.
        </p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Button asChild size="lg">
            <Link to="/auth">Run your first scan</Link>
          </Button>
          <Button asChild size="lg" variant="outline">
            <Link to="/auth">Import Nessus results</Link>
          </Button>
        </div>
      </section>

      <section className="border-y border-border bg-card/40 py-14">
        <div className="mx-auto max-w-6xl px-4">
          <h2 className="text-center text-sm font-semibold uppercase tracking-widest text-muted-foreground">
            Scan workflow
          </h2>
          <ol className="mt-6 grid gap-3 md:grid-cols-4 lg:grid-cols-7">
            {WORKFLOW.map((step, i) => (
              <li key={step} className="rounded-lg border border-border bg-background p-3 text-xs">
                <span className="font-mono text-primary">{String(i + 1).padStart(2, "0")}</span>
                <p className="mt-1 font-medium leading-snug">{step}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-16">
        <h2 className="text-3xl font-semibold tracking-tight">Feature parity, modern execution</h2>
        <p className="mt-2 max-w-2xl text-muted-foreground">
          Native checks cover everything reachable over HTTP/TLS. Raw socket work — ICMP/ARP sweeps,
          SYN and UDP port scans, OS fingerprinting, credentialed SMB/SSH audits — is delegated to
          distributed agents that post results into the same correlation engine.
        </p>
        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {FEATURES.map((f) => (
            <div key={f.title} className="rounded-lg border border-border bg-card p-5">
              <f.icon className="size-5 text-primary" />
              <h3 className="mt-3 font-medium">{f.title}</h3>
              <p className="mt-1.5 text-sm text-muted-foreground">{f.body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="border-t border-border bg-card/40 py-16">
        <div className="mx-auto max-w-3xl px-4 text-center">
          <h2 className="text-3xl font-semibold tracking-tight">
            Fix what attackers actually exploit
          </h2>
          <p className="mt-3 text-muted-foreground">
            Priority scores are recomputed every time the feeds refresh, so a CVE that becomes
            weaponised tonight is at the top of your queue tomorrow morning.
          </p>
          <Button asChild size="lg" className="mt-7">
            <Link to="/auth">Create your workspace</Link>
          </Button>
        </div>
      </section>

      <footer className="border-t border-border py-8 text-center text-xs text-muted-foreground">
        AegisScan · Only scan systems you are authorised to test.
      </footer>
    </div>
  );
}
