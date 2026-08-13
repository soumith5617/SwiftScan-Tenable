import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { toast } from "sonner";
import { PageHeader } from "@/components/soc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Send, Trash2, Plug } from "lucide-react";
import {
  INTEGRATION_KINDS,
  deleteIntegration,
  listIntegrations,
  saveIntegration,
  testIntegration,
  toggleIntegration,
} from "@/lib/integrations.functions";
import { severityLabel } from "@/lib/severity";

export const Route = createFileRoute("/_authenticated/integrations")({
  head: () => ({
    meta: [
      { title: "Integrations — Aegis Scanner" },
      {
        name: "description",
        content:
          "Push findings to Jira, ServiceNow, Splunk, Microsoft Sentinel, Slack or any webhook the moment they are detected.",
      },
      { property: "og:title", content: "Integrations — Aegis Scanner" },
      {
        property: "og:description",
        content: "Ticketing and SIEM delivery for every new vulnerability finding.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: IntegrationsPage,
});

function IntegrationsPage() {
  const qc = useQueryClient();
  const load = useServerFn(listIntegrations);
  const save = useServerFn(saveIntegration);
  const toggle = useServerFn(toggleIntegration);
  const remove = useServerFn(deleteIntegration);
  const test = useServerFn(testIntegration);

  const { data } = useQuery({ queryKey: ["integrations"], queryFn: () => load() });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["integrations"] });

  const [kind, setKind] = useState<(typeof INTEGRATION_KINDS)[number]["id"]>("webhook");
  const [name, setName] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [token, setToken] = useState("");
  const [projectKey, setProjectKey] = useState("");
  const [minSeverity, setMinSeverity] = useState(3);

  const saveMut = useMutation({
    mutationFn: () => save({ data: { kind, name, endpoint, token, projectKey, minSeverity } }),
    onSuccess: () => {
      toast.success("Integration saved");
      setName("");
      setEndpoint("");
      setToken("");
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const testMut = useMutation({
    mutationFn: (id: string) => test({ data: { id } }),
    onSuccess: (r) => {
      if (r.ok) toast.success(`Delivered (HTTP ${r.status})`);
      else toast.error(`Failed (HTTP ${r.status}) — ${r.detail}`);
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const hint = INTEGRATION_KINDS.find((k) => k.id === kind)?.hint ?? "";

  return (
    <div>
      <PageHeader
        title="Integrations"
        description="Every new finding above your threshold is pushed to these destinations as it is written, with a full delivery log."
      />

      <div className="grid gap-6 lg:grid-cols-[400px_1fr]">
        <section className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Add destination
          </h2>
          <div className="space-y-3">
            <div>
              <Label>Type</Label>
              <Select value={kind} onValueChange={(v) => setKind(v as typeof kind)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INTEGRATION_KINDS.map((k) => (
                    <SelectItem key={k.id} value={k.id}>
                      {k.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
            </div>
            <div>
              <Label htmlFor="int-name">Name</Label>
              <Input
                id="int-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="SecOps Jira"
              />
            </div>
            <div>
              <Label htmlFor="int-endpoint">Endpoint (HTTPS)</Label>
              <Input
                id="int-endpoint"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="https://…"
              />
            </div>
            <div>
              <Label htmlFor="int-token">Token / credential</Label>
              <Input
                id="int-token"
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Stored encrypted, never returned"
              />
            </div>
            {kind === "jira" && (
              <div>
                <Label htmlFor="int-project">Jira project key</Label>
                <Input
                  id="int-project"
                  value={projectKey}
                  onChange={(e) => setProjectKey(e.target.value)}
                  placeholder="SEC"
                />
              </div>
            )}
            <div>
              <Label>Minimum severity</Label>
              <Select value={String(minSeverity)} onValueChange={(v) => setMinSeverity(Number(v))}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {[0, 1, 2, 3, 4].map((s) => (
                    <SelectItem key={s} value={String(s)}>
                      {severityLabel(s)} and above
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              className="w-full"
              disabled={!name || !endpoint || saveMut.isPending}
              onClick={() => saveMut.mutate()}
            >
              <Plug className="mr-2 size-4" /> Save integration
            </Button>
          </div>
        </section>

        <div className="space-y-6">
          <section className="rounded-lg border border-border bg-card">
            <h2 className="border-b border-border px-4 py-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Connected destinations
            </h2>
            {!data?.integrations.length ? (
              <p className="p-4 text-sm text-muted-foreground">Nothing connected yet.</p>
            ) : (
              <ul className="divide-y divide-border">
                {data.integrations.map((i) => (
                  <li key={i.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                    <div className="min-w-48 flex-1">
                      <p className="font-medium">{i.name}</p>
                      <p className="truncate font-mono text-xs text-muted-foreground">
                        {i.endpoint}
                      </p>
                    </div>
                    <Badge variant="outline">
                      {INTEGRATION_KINDS.find((k) => k.id === i.kind)?.label ?? i.kind}
                    </Badge>
                    <Badge variant="outline">{severityLabel(i.min_severity)}+</Badge>
                    {i.last_status && (
                      <span
                        className={
                          i.last_status === "delivered"
                            ? "text-xs text-sev-low"
                            : "text-xs text-sev-high"
                        }
                      >
                        {i.last_status}
                      </span>
                    )}
                    <Switch
                      checked={i.enabled}
                      onCheckedChange={(v) =>
                        toggle({ data: { id: i.id, enabled: v } }).then(invalidate)
                      }
                      aria-label="Enable integration"
                    />
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={testMut.isPending}
                      onClick={() => testMut.mutate(i.id)}
                    >
                      <Send className="size-3.5" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => remove({ data: { id: i.id } }).then(invalidate)}
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="rounded-lg border border-border bg-card">
            <h2 className="border-b border-border px-4 py-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Delivery log
            </h2>
            {!data?.deliveries.length ? (
              <p className="p-4 text-sm text-muted-foreground">No deliveries yet.</p>
            ) : (
              <ul className="divide-y divide-border font-mono text-xs">
                {data.deliveries.map((d) => (
                  <li key={d.id} className="flex items-center gap-3 px-4 py-2">
                    <span className={d.status === "delivered" ? "text-sev-low" : "text-sev-high"}>
                      {d.status}
                    </span>
                    <span className="text-muted-foreground">HTTP {d.http_status ?? "—"}</span>
                    <span className="flex-1 truncate text-muted-foreground">{d.detail}</span>
                    <span className="text-muted-foreground">
                      {new Date(d.created_at).toLocaleTimeString()}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
