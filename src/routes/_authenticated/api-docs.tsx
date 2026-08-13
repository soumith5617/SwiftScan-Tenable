import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useEffect, useState } from "react";
import { PageHeader } from "@/components/soc";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Copy, ExternalLink } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/api-docs")({
  head: () => ({
    meta: [
      { title: "REST API & Agent Reference — Aegis Scanner" },
      {
        name: "description",
        content:
          "OpenAPI 3.1 reference for the findings, assets and scans endpoints, plus the distributed scan-agent ingest contract.",
      },
      { property: "og:title", content: "REST API & Agent Reference — Aegis Scanner" },
      {
        property: "og:description",
        content:
          "Authenticate with an API key and export findings, assets and scans programmatically.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ApiDocsPage,
});

type Spec = {
  paths: Record<
    string,
    Record<
      string,
      {
        summary?: string;
        description?: string;
        parameters?: { name: string; schema?: { type?: string } }[];
      }
    >
  >;
};

function Snippet({ code }: { code: string }) {
  return (
    <div className="relative">
      <pre className="overflow-auto rounded-md bg-secondary/60 p-3 pr-10 font-mono text-xs">
        {code}
      </pre>
      <Button
        size="sm"
        variant="ghost"
        className="absolute right-1 top-1"
        onClick={() => {
          void navigator.clipboard.writeText(code);
          toast.success("Copied");
        }}
      >
        <Copy className="size-3.5" />
      </Button>
    </div>
  );
}

function ApiDocsPage() {
  const [origin, setOrigin] = useState("");
  useEffect(() => setOrigin(window.location.origin), []);

  const { data: spec } = useQuery<Spec>({
    queryKey: ["openapi"],
    queryFn: async () => (await fetch("/api/public/v1/openapi")).json(),
  });

  const { data: keys } = useQuery({
    queryKey: ["api-keys-preview"],
    queryFn: async () => {
      const { data } = await supabase
        .from("api_keys")
        .select("name, prefix, last_used_at")
        .limit(5);
      return data ?? [];
    },
  });

  const base = origin || "https://your-app.lovable.app";

  return (
    <div>
      <PageHeader
        title="REST API & agent reference"
        description="Everything the UI can do is available over HTTP with an API key."
      >
        <Button variant="outline" asChild>
          <a href="/api/public/v1/openapi" target="_blank" rel="noreferrer">
            <ExternalLink className="mr-2 size-4" /> openapi.json
          </a>
        </Button>
      </PageHeader>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Authentication
          </h2>
          <p className="mb-3 text-sm text-muted-foreground">
            Create a key under Settings → API keys. Send it as{" "}
            <code className="font-mono">X-API-Key</code>. Keys are stored as SHA-256 hashes and can
            only be read once at creation.
          </p>
          <Snippet
            code={`curl -s "${base}/api/public/v1/findings?min_severity=3&state=open" \\
  -H "X-API-Key: $AEGIS_KEY"`}
          />
          {!!keys?.length && (
            <p className="mt-3 text-xs text-muted-foreground">
              Active keys: {keys.map((k) => `${k.name} (${k.prefix}…)`).join(", ")}
            </p>
          )}
        </section>

        <section className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Queue a scan
          </h2>
          <Snippet
            code={`curl -X POST "${base}/api/public/v1/scans" \\
  -H "X-API-Key: $AEGIS_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"target":"example.com","template":"basic_network_scan"}'`}
          />
          <h3 className="mb-2 mt-4 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Agent ingest
          </h3>
          <Snippet
            code={`curl -X POST "${base}/api/public/agent/ingest" \\
  -H "X-Agent-Key: $AEGIS_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"target":"10.0.0.5","os":"Ubuntu 22.04",
       "ports":[{"port":22,"protocol":"tcp","service":"ssh","banner":"OpenSSH_8.9"}],
       "findings":[]}'`}
          />
        </section>

        <section className="rounded-lg border border-border bg-card lg:col-span-2">
          <h2 className="border-b border-border px-4 py-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Endpoints
          </h2>
          <ul className="divide-y divide-border">
            {Object.entries(spec?.paths ?? {}).flatMap(([path, methods]) =>
              Object.entries(methods).map(([method, op]) => (
                <li
                  key={`${method}-${path}`}
                  className="flex flex-wrap items-baseline gap-3 px-4 py-3"
                >
                  <Badge variant="outline" className="font-mono uppercase">
                    {method}
                  </Badge>
                  <code className="font-mono text-sm">/api/public{path}</code>
                  <span className="flex-1 text-sm text-muted-foreground">{op.summary}</span>
                  {!!op.parameters?.length && (
                    <span className="font-mono text-xs text-muted-foreground">
                      ?{op.parameters.map((p) => p.name).join("&")}
                    </span>
                  )}
                </li>
              )),
            )}
          </ul>
        </section>

        <section className="rounded-lg border border-border bg-card p-4 lg:col-span-2">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Distributed scan worker
          </h2>
          <p className="mb-3 text-sm text-muted-foreground">
            The hosted engine performs HTTP/TLS/DNS-reachable analysis. Raw-socket work — ARP/ICMP
            sweeps, SYN and UDP port scans, OS fingerprinting, credentialed SMB/SSH checks — runs in
            an external worker that posts back to the ingest endpoint. A reference Rust worker with
            an async socket pool and adaptive rate limiting is documented below.
          </p>
          <Snippet
            code={`# reference worker (Rust, tokio)
AEGIS_URL=${base} AEGIS_KEY=$AEGIS_KEY \\
  aegis-worker --targets 10.0.0.0/24 --ports top-1000 --concurrency 512 --rate 2000`}
          />
          <p className="mt-3 text-xs text-muted-foreground">
            Worker contract: discover → SYN sweep → service ID → OS fingerprint → local plugin pass
            → POST /api/public/agent/ingest. Results are scored by the same VPR pipeline as native
            scans, so agent and native findings share one risk model.
          </p>
        </section>
      </div>
    </div>
  );
}
