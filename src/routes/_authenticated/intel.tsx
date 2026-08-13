import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { syncIntel, intelStats } from "@/lib/intel.functions";
import { PageHeader, StatPill } from "@/components/soc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useState } from "react";
import { listApiKeys, createApiKey, deleteApiKey } from "@/lib/data.functions";
import { Trash2 } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/intel")({
  head: () => ({
    meta: [
      { title: "Vulnerability intelligence — AegisScan" },
      {
        name: "description",
        content:
          "Sync live NVD CVE records, CISA Known Exploited Vulnerabilities and FIRST EPSS exploit probabilities into your scoring engine.",
      },
      { property: "og:title", content: "Vulnerability intelligence — AegisScan" },
      {
        property: "og:description",
        content: "Live NVD, CISA KEV and EPSS feeds powering priority scores.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: IntelPage,
});

function IntelPage() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["intel"], queryFn: () => intelStats() });

  const sync = useMutation({
    mutationFn: () => syncIntel(),
    onSuccess: (r) => {
      toast.success(`Synced ${r.stored} CVEs · ${r.kev} KEV · ${r.epss} EPSS scores`);
      if (r.errors.length) toast.warning(r.errors.join(" · "));
      qc.invalidateQueries({ queryKey: ["intel"] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Sync failed"),
  });

  return (
    <div>
      <PageHeader
        title="Vulnerability intelligence"
        description="NVD CVE records, CISA KEV catalog and FIRST EPSS probabilities, cached for instant correlation."
      >
        <Button size="sm" onClick={() => sync.mutate()} disabled={sync.isPending}>
          {sync.isPending ? "Syncing feeds…" : "Sync feeds now"}
        </Button>
      </PageHeader>

      <div className="grid gap-3 sm:grid-cols-3">
        <StatPill label="CVEs cached" value={data?.total ?? 0} />
        <StatPill label="Known exploited (KEV)" value={data?.kev ?? 0} tone="critical" />
        <StatPill
          label="Last sync"
          value={data?.lastSync ? new Date(data.lastSync).toLocaleString() : "never"}
        />
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <Feed
          title="NVD"
          body="Authoritative CVE records with CVSS v3.1/v4 vectors, CWE weaknesses and CPE product mappings used to match fingerprinted software versions."
        />
        <Feed
          title="CISA KEV"
          body="Vulnerabilities confirmed exploited in the wild. Any matching finding is escalated to Critical and inherits the federal remediation due date."
        />
        <Feed
          title="FIRST EPSS"
          body="Daily probability that a CVE will be exploited within 30 days. Feeds directly into the priority score so you fix what attackers actually use."
        />
      </div>

      <Card className="mt-4">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">How priority is calculated</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          <code className="block rounded-md bg-muted/60 p-3 font-mono text-xs text-foreground">
            priority = (cvss × 0.62) + (epss × 2.6) + (kev ? 2.2 : 0) × criticality_multiplier ×
            exposure_multiplier × confidence_multiplier
          </code>
          <p className="mt-2">
            Scores are clamped to 0–10 and recomputed whenever intelligence feeds refresh, so the
            queue always reflects today's exploit landscape rather than the day the scan ran.
          </p>
        </CardContent>
      </Card>

      <AgentKeys />
    </div>
  );
}

function AgentKeys() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["api-keys"], queryFn: () => listApiKeys() });
  const [name, setName] = useState("");
  const [fresh, setFresh] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => createApiKey({ data: { name } }),
    onSuccess: (r) => {
      setFresh(r.key);
      setName("");
      qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Could not create key"),
  });
  const remove = useMutation({
    mutationFn: (id: string) => deleteApiKey({ data: { id } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });

  return (
    <Card className="mt-4">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Agent ingest keys</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Distributed agents performing raw socket, SYN/UDP, OS fingerprint and credentialed checks
          post results to{" "}
          <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
            POST /api/public/agent/ingest
          </code>{" "}
          with an{" "}
          <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">x-agent-key</code>{" "}
          header.
        </p>
        <div className="flex gap-2">
          <Input
            placeholder="Agent name (e.g. dmz-collector)"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <Button disabled={!name || create.isPending} onClick={() => create.mutate()}>
            Generate
          </Button>
        </div>
        {fresh && (
          <p className="break-all rounded-md border border-primary/40 bg-primary/10 p-3 font-mono text-xs">
            {fresh}
            <span className="mt-1 block font-sans text-muted-foreground">
              Copy it now — it will not be shown again.
            </span>
          </p>
        )}
        <div className="space-y-1">
          {(data ?? []).map((k) => (
            <div
              key={k.id}
              className="flex items-center gap-3 rounded-md border border-border/60 px-3 py-2 text-xs"
            >
              <span className="font-medium">{k.name}</span>
              <span className="font-mono text-muted-foreground">{k.prefix}…</span>
              <span className="flex-1 text-muted-foreground">
                {k.last_used_at
                  ? `last used ${new Date(k.last_used_at).toLocaleString()}`
                  : "never used"}
              </span>
              <Button size="icon" variant="ghost" onClick={() => remove.mutate(k.id)}>
                <Trash2 className="size-4" />
              </Button>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function Feed({ title, body }: { title: string; body: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">{body}</CardContent>
    </Card>
  );
}
