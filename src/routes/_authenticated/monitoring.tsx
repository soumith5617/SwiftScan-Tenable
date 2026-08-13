import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { toast } from "sonner";
import { PageHeader, StatPill } from "@/components/soc";
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
import { Play, Trash2, Clock, Activity, AlertTriangle, CheckCircle2 } from "lucide-react";
import {
  CADENCES,
  createSchedule,
  deleteSchedule,
  listMonitoring,
  runScheduleNow,
  toggleSchedule,
} from "@/lib/monitoring.functions";
import { NATIVE_TEMPLATES } from "@/lib/templates";

export const Route = createFileRoute("/_authenticated/monitoring")({
  head: () => ({
    meta: [
      { title: "Continuous Monitoring — Aegis Scanner" },
      {
        name: "description",
        content:
          "Schedule recurring vulnerability scans and track configuration drift across your attack surface in real time.",
      },
      { property: "og:title", content: "Continuous Monitoring — Aegis Scanner" },
      {
        property: "og:description",
        content: "Recurring scans, drift detection and change history for every monitored asset.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: MonitoringPage,
});

function MonitoringPage() {
  const qc = useQueryClient();
  const load = useServerFn(listMonitoring);
  const create = useServerFn(createSchedule);
  const toggle = useServerFn(toggleSchedule);
  const remove = useServerFn(deleteSchedule);
  const runNow = useServerFn(runScheduleNow);

  const { data, isLoading } = useQuery({ queryKey: ["monitoring"], queryFn: () => load() });

  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [template, setTemplate] = useState("basic_network_scan");
  const [cadence, setCadence] = useState<(typeof CADENCES)[number]["id"]>("daily");

  const invalidate = () => qc.invalidateQueries({ queryKey: ["monitoring"] });

  const createMut = useMutation({
    mutationFn: () => create({ data: { name, target, template, cadence, assetId: null } }),
    onSuccess: () => {
      toast.success("Schedule armed");
      setName("");
      setTarget("");
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const runMut = useMutation({
    mutationFn: (id: string) => runNow({ data: { id } }),
    onSuccess: (r) => {
      toast.success(r.ok ? `Run complete — ${r.findings} findings` : `Run stopped: ${r.reason}`);
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const schedules = data?.schedules ?? [];
  const changes = data?.changes ?? [];

  return (
    <div>
      <PageHeader
        title="Continuous monitoring"
        description="Recurring scans with drift detection — new exposures, resolved issues and technology changes are recorded between runs."
      />

      <div className="mb-6 grid gap-3 sm:grid-cols-4">
        <StatPill label="Schedules" value={schedules.length} />
        <StatPill label="Active" value={schedules.filter((s) => s.enabled).length} tone="info" />
        <StatPill label="Drift events (60)" value={changes.length} tone="medium" />
        <StatPill
          label="New exposures"
          value={changes.filter((c) => c.kind === "new_finding").length}
          tone="high"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-[380px_1fr]">
        <section className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            New schedule
          </h2>
          <div className="space-y-3">
            <div>
              <Label htmlFor="sched-name">Name</Label>
              <Input
                id="sched-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Perimeter sweep"
              />
            </div>
            <div>
              <Label htmlFor="sched-target">Target</Label>
              <Input
                id="sched-target"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com"
              />
            </div>
            <div>
              <Label>Template</Label>
              <Select value={template} onValueChange={setTemplate}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  {NATIVE_TEMPLATES.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Cadence</Label>
              <Select value={cadence} onValueChange={(v) => setCadence(v as typeof cadence)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CADENCES.map((c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              className="w-full"
              disabled={!name || !target || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              <Clock className="mr-2 size-4" /> Arm schedule
            </Button>
          </div>
        </section>

        <div className="space-y-6">
          <section className="rounded-lg border border-border bg-card">
            <h2 className="border-b border-border px-4 py-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Schedules
            </h2>
            {isLoading ? (
              <p className="p-4 text-sm text-muted-foreground">Loading…</p>
            ) : schedules.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground">
                No schedules yet. Arm one to start continuous coverage.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {schedules.map((s) => (
                  <li key={s.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                    <div className="min-w-48 flex-1">
                      <p className="font-medium">{s.name}</p>
                      <p className="font-mono text-xs text-muted-foreground">{s.target}</p>
                    </div>
                    <Badge variant="outline">
                      {CADENCES.find((c) => c.id === s.cadence)?.label ?? s.cadence}
                    </Badge>
                    <div className="text-xs text-muted-foreground">
                      <p>Next: {new Date(s.next_run_at).toLocaleString()}</p>
                      <p>
                        {s.runs} runs
                        {s.last_run_at ? ` · last ${new Date(s.last_run_at).toLocaleString()}` : ""}
                      </p>
                    </div>
                    <Switch
                      checked={s.enabled}
                      onCheckedChange={(v) =>
                        toggle({ data: { id: s.id, enabled: v } }).then(invalidate)
                      }
                      aria-label="Enable schedule"
                    />
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={runMut.isPending}
                      onClick={() => runMut.mutate(s.id)}
                    >
                      <Play className="size-3.5" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => remove({ data: { id: s.id } }).then(invalidate)}
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
              Drift &amp; change history
            </h2>
            {changes.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground">
                No drift recorded yet. Differences between consecutive scans of the same asset
                appear here.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {changes.map((c) => (
                  <li key={c.id} className="flex items-start gap-3 px-4 py-2.5 text-sm">
                    {c.kind === "new_finding" ? (
                      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-sev-high" />
                    ) : c.kind === "resolved" ? (
                      <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-sev-low" />
                    ) : (
                      <Activity className="mt-0.5 size-4 shrink-0 text-sev-info" />
                    )}
                    <span className="flex-1">{c.summary}</span>
                    <span className="whitespace-nowrap text-xs text-muted-foreground">
                      {new Date(c.created_at).toLocaleString()}
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
