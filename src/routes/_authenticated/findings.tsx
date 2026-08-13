import { AiInsight } from "@/components/ai-insight";
import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listFindings, updateFinding } from "@/lib/data.functions";
import { recomputePriorities } from "@/lib/scans.functions";
import {
  listSavedFilters,
  createSavedFilter,
  deleteSavedFilter,
  applyRiskOverride,
} from "@/lib/enterprise.functions";
import { PageHeader, SeverityBadge } from "@/components/soc";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Search,
  SlidersHorizontal,
  Bookmark,
  BookmarkPlus,
  ArrowUpDown,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Flame,
  CheckCircle2,
} from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/findings")({
  head: () => ({
    meta: [
      { title: "Vulnerability Triage & Risk Overrides — AegisScan" },
      {
        name: "description",
        content:
          "Enterprise vulnerability triage table with multi-factor risk scoring, EPSS probability, CISA KEV status, custom risk overrides and saved filters.",
      },
      { property: "og:title", content: "Findings Triage — AegisScan" },
      {
        property: "og:description",
        content: "Prioritize and resolve vulnerabilities with evidence.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: FindingsPage,
});

const STATES = ["open", "fixed", "accepted", "false_positive"] as const;

function FindingsPage() {
  const qc = useQueryClient();
  const { data: findings = [], isLoading } = useQuery({
    queryKey: ["findings"],
    queryFn: () => listFindings(),
  });
  const { data: savedFilters = [] } = useQuery({
    queryKey: ["saved-filters-findings"],
    queryFn: () => listSavedFilters({ data: { entity_type: "findings" } }),
  });

  // Filter & Sort State
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("all");
  const [state, setState] = useState("open");
  const [kevOnly, setKevOnly] = useState(false);
  const [sortBy, setSortBy] = useState<"priority" | "cvss" | "epss" | "severity" | "due_at">(
    "priority",
  );
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  // Pagination State
  const [page, setPage] = useState(1);
  const pageSize = 25;

  // Selection & Modal States
  const [selected, setSelected] = useState<string | null>(null);
  const [filterModalOpen, setFilterModalOpen] = useState(false);
  const [filterName, setFilterName] = useState("");

  // Risk Override State
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [overrideSeverity, setOverrideSeverity] = useState<number>(1);
  const [overrideReason, setOverrideReason] = useState("");

  // Mutations
  const updateStatus = useMutation({
    mutationFn: (input: { id: string; state: (typeof STATES)[number] }) =>
      updateFinding({ data: input }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      toast.success("Finding status updated");
    },
  });

  const rescore = useMutation({
    mutationFn: () => recomputePriorities(),
    onSuccess: (r) => {
      toast.success(`Re-scored ${r.updated} findings against current intelligence feeds`);
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  const saveFilterMut = useMutation({
    mutationFn: () =>
      createSavedFilter({
        data: {
          name: filterName,
          entity_type: "findings",
          query_params: { sev, state, kevOnly, sortBy, sortOrder },
          is_default: false,
          is_shared: false,
        },
      }),
    onSuccess: () => {
      setFilterModalOpen(false);
      setFilterName("");
      qc.invalidateQueries({ queryKey: ["saved-filters-findings"] });
      toast.success("Filter preset saved");
    },
  });

  const deleteFilterMut = useMutation({
    mutationFn: (id: string) => deleteSavedFilter({ data: { id } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["saved-filters-findings"] });
      toast.success("Saved filter removed");
    },
  });

  const overrideMut = useMutation({
    mutationFn: (findingId: string) =>
      applyRiskOverride({
        data: {
          finding_id: findingId,
          overridden_severity: overrideSeverity as 0 | 1 | 2 | 3 | 4,
          reason: overrideReason,
        },
      }),
    onSuccess: () => {
      setOverrideOpen(false);
      setOverrideReason("");
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      toast.success("Risk override applied and priority rescored");
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Override failed"),
  });

  // Filter and Sort Processing
  const filteredRows = useMemo(() => {
    const list = findings.filter((f) => {
      if (state !== "all" && f.state !== state) return false;
      if (sev !== "all" && String(f.severity) !== sev) return false;
      if (kevOnly && !f.kev) return false;
      if (q) {
        const needle = q.toLowerCase();
        const text =
          `${f.title} ${f.cve_ids?.join(" ") || ""} ${f.asset?.target ?? ""} ${f.plugin_id}`.toLowerCase();
        if (!text.includes(needle)) return false;
      }
      return true;
    });

    list.sort((a, b) => {
      let diff = 0;
      if (sortBy === "priority") diff = (a.priority ?? 0) - (b.priority ?? 0);
      else if (sortBy === "cvss") diff = (a.cvss ?? 0) - (b.cvss ?? 0);
      else if (sortBy === "epss") diff = (a.epss ?? 0) - (b.epss ?? 0);
      else if (sortBy === "severity") diff = a.severity - b.severity;
      else if (sortBy === "due_at") {
        const dateA = a.due_at ? new Date(a.due_at).getTime() : 0;
        const dateB = b.due_at ? new Date(b.due_at).getTime() : 0;
        diff = dateA - dateB;
      }
      return sortOrder === "desc" ? -diff : diff;
    });

    return list;
  }, [findings, q, sev, state, kevOnly, sortBy, sortOrder]);

  // Paginated Slices
  const totalPages = Math.ceil(filteredRows.length / pageSize) || 1;
  const paginatedRows = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredRows.slice(start, start + pageSize);
  }, [filteredRows, page, pageSize]);

  const active = findings.find((f) => f.id === selected) ?? null;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Vulnerability Findings"
        description="Unified triage console. Priority combines CVSS score, EPSS probability, CISA KEV exploitation data and asset criticality."
      >
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => rescore.mutate()}
            disabled={rescore.isPending}
            className="gap-1.5"
          >
            <Flame className="size-3.5 text-orange-500" />
            {rescore.isPending ? "Re-scoring..." : "Rescore with Latest Intel"}
          </Button>

          <Dialog open={filterModalOpen} onOpenChange={setFilterModalOpen}>
            <DialogTrigger asChild>
              <Button size="sm" variant="outline" className="gap-1.5">
                <BookmarkPlus className="size-3.5" /> Save Filter
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Save Current Filter Preset</DialogTitle>
              </DialogHeader>
              <div className="space-y-3 pt-2">
                <div className="space-y-1.5">
                  <Label>Filter Name</Label>
                  <Input
                    value={filterName}
                    onChange={(e) => setFilterName(e.target.value)}
                    placeholder="e.g. Critical KEV Exploitable"
                  />
                </div>
                <div className="rounded-md bg-muted/40 p-3 text-xs space-y-1">
                  <p className="font-semibold text-muted-foreground">Parameters captured:</p>
                  <p>
                    Severity: <span className="font-mono">{sev}</span> · State:{" "}
                    <span className="font-mono">{state}</span> · KEV Only:{" "}
                    <span className="font-mono">{String(kevOnly)}</span>
                  </p>
                </div>
                <Button
                  className="w-full"
                  disabled={!filterName || saveFilterMut.isPending}
                  onClick={() => saveFilterMut.mutate()}
                >
                  {saveFilterMut.isPending ? "Saving..." : "Save View Preset"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </PageHeader>

      {/* FILTER BAR */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-72">
            <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
            <Input
              placeholder="Search title, CVE, plugin or target..."
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setPage(1);
              }}
              className="pl-8"
            />
          </div>

          <Select
            value={sev}
            onValueChange={(v) => {
              setSev(v);
              setPage(1);
            }}
          >
            <SelectTrigger className="w-36">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              <SelectItem value="4">Critical (4)</SelectItem>
              <SelectItem value="3">High (3)</SelectItem>
              <SelectItem value="2">Medium (2)</SelectItem>
              <SelectItem value="1">Low (1)</SelectItem>
              <SelectItem value="0">Info (0)</SelectItem>
            </SelectContent>
          </Select>

          <Select
            value={state}
            onValueChange={(v) => {
              setState(v);
              setPage(1);
            }}
          >
            <SelectTrigger className="w-36">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All States</SelectItem>
              {STATES.map((s) => (
                <SelectItem key={s} value={s} className="capitalize">
                  {s.replace("_", " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Button
            size="sm"
            variant={kevOnly ? "default" : "outline"}
            onClick={() => {
              setKevOnly(!kevOnly);
              setPage(1);
            }}
            className="gap-1.5"
          >
            <Flame className="size-3.5 text-sev-critical" /> KEV Only
          </Button>

          {savedFilters.length > 0 && (
            <Select
              onValueChange={(val) => {
                const target = savedFilters.find((f) => f.id === val);
                if (target?.query_params) {
                  const p = target.query_params as Record<string, unknown>;
                  const sevVal = p["sev"];
                  const stateVal = p["state"];
                  const kevVal = p["kevOnly"];
                  if (typeof sevVal === "string") setSev(sevVal);
                  if (typeof stateVal === "string") setState(stateVal);
                  if (typeof kevVal === "boolean") setKevOnly(kevVal);
                  setPage(1);
                  toast.info(`Applied filter: ${target.name}`);
                }
              }}
            >
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Saved Views" />
              </SelectTrigger>
              <SelectContent>
                {savedFilters.map((f) => (
                  <SelectItem key={f.id} value={f.id}>
                    {f.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>

        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="font-semibold text-foreground">{filteredRows.length}</span> total
          findings
        </div>
      </div>

      {/* FINDINGS TABLE */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-muted/30 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="w-24 px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Finding Title &amp; Advisory</th>
                  <th className="px-4 py-3">Asset Target</th>
                  <th
                    className="cursor-pointer px-4 py-3 text-right hover:text-foreground"
                    onClick={() => {
                      setSortBy("cvss");
                      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
                    }}
                  >
                    <div className="flex items-center justify-end gap-1">
                      CVSS <ArrowUpDown className="size-3" />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer px-4 py-3 text-right hover:text-foreground"
                    onClick={() => {
                      setSortBy("epss");
                      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
                    }}
                  >
                    <div className="flex items-center justify-end gap-1">
                      EPSS <ArrowUpDown className="size-3" />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer px-4 py-3 text-right hover:text-foreground"
                    onClick={() => {
                      setSortBy("priority");
                      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
                    }}
                  >
                    <div className="flex items-center justify-end gap-1">
                      Priority <ArrowUpDown className="size-3" />
                    </div>
                  </th>
                  <th className="px-4 py-3">Remediation SLA</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {paginatedRows.map((f) => {
                  const overdue = f.due_at && new Date(f.due_at) < new Date() && f.state === "open";
                  return (
                    <tr
                      key={f.id}
                      onClick={() => setSelected(f.id)}
                      className="cursor-pointer transition-colors hover:bg-muted/40"
                    >
                      <td className="px-4 py-3">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="max-w-md px-4 py-3">
                        <p className="line-clamp-1 font-semibold text-foreground">{f.title}</p>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <span className="font-mono">{f.plugin_id}</span>
                          {f.kev && (
                            <Badge
                              variant="outline"
                              className="border-red-500/30 bg-red-500/15 px-1 py-0 text-[10px] font-bold text-red-500"
                            >
                              CISA KEV
                            </Badge>
                          )}
                          {Array.isArray(f.cve_ids) && f.cve_ids.length > 0 && (
                            <span className="truncate font-mono">
                              {f.cve_ids.slice(0, 2).join(", ")}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                        {f.asset?.target || "—"}
                      </td>
                      <td className="px-4 py-3 text-right font-mono font-semibold tabular-nums text-foreground">
                        {f.cvss !== null ? Number(f.cvss).toFixed(1) : "—"}
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums text-muted-foreground">
                        {f.epss != null ? `${(Number(f.epss) * 100).toFixed(1)}%` : "—"}
                      </td>
                      <td className="px-4 py-3 text-right font-mono font-bold tabular-nums text-foreground">
                        {Number(f.priority ?? 0).toFixed(1)}
                      </td>
                      <td className="px-4 py-3 text-xs">
                        {f.due_at ? (
                          <span
                            className={
                              overdue
                                ? "font-bold text-red-500"
                                : f.state === "fixed"
                                  ? "text-green-500"
                                  : "text-muted-foreground"
                            }
                          >
                            {overdue && "🚨 Overdue: "}
                            {new Date(f.due_at).toLocaleDateString()}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {paginatedRows.length === 0 && !isLoading && (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-sm text-muted-foreground">
                      No findings match the selected criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* PAGINATION CONTROLS */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between border-t border-border px-4 py-3">
              <p className="text-xs text-muted-foreground">
                Page {page} of {totalPages} ({filteredRows.length} findings)
              </p>
              <div className="flex items-center gap-1.5">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={page <= 1}
                  onClick={() => setPage(page - 1)}
                  className="size-8 p-0"
                >
                  <ChevronLeft className="size-4" />
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={page >= totalPages}
                  onClick={() => setPage(page + 1)}
                  className="size-8 p-0"
                >
                  <ChevronRight className="size-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* FINDING DETAILS SHEET */}
      <Sheet open={!!active} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
          {active && (
            <div className="space-y-6">
              <SheetHeader className="text-left">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={active.severity} />
                  {active.kev && (
                    <Badge className="border-red-500/30 bg-red-500/15 text-red-500 font-bold">
                      CISA KEV Exploited
                    </Badge>
                  )}
                  <Badge variant="outline" className="font-mono">
                    Priority Score: {Number(active.priority ?? 0).toFixed(1)}
                  </Badge>
                  <Badge variant="outline" className="capitalize">
                    Status: {active.state.replace("_", " ")}
                  </Badge>
                </div>
                <SheetTitle className="text-base font-bold leading-snug">{active.title}</SheetTitle>
              </SheetHeader>

              {/* TECHNICAL METADATA */}
              <div className="grid grid-cols-2 gap-2.5 rounded-lg bg-muted/40 p-3.5 text-xs sm:grid-cols-4">
                <div>
                  <span className="text-muted-foreground">Plugin ID:</span>
                  <p className="font-mono font-medium">{active.plugin_id}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Family:</span>
                  <p className="font-medium capitalize">{active.family || "General"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Base CVSS:</span>
                  <p className="font-mono font-medium">{active.cvss ?? "—"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">EPSS Score:</span>
                  <p className="font-mono font-medium">
                    {active.epss != null ? `${(Number(active.epss) * 100).toFixed(1)}%` : "—"}
                  </p>
                </div>
                <div>
                  <span className="text-muted-foreground">Asset Target:</span>
                  <p className="font-mono font-medium truncate">{active.asset?.target || "—"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Port / Service:</span>
                  <p className="font-mono font-medium">
                    {active.port ?? "443"} / {active.service ?? "tcp"}
                  </p>
                </div>
                <div>
                  <span className="text-muted-foreground">CWE:</span>
                  <p className="font-mono font-medium">{active.cwe ?? "—"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Remediation Due:</span>
                  <p className="font-medium">
                    {active.due_at ? new Date(active.due_at).toLocaleDateString() : "—"}
                  </p>
                </div>
              </div>

              {/* DESCRIPTION */}
              {active.description && (
                <div className="space-y-1.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                    Vulnerability Description
                  </h4>
                  <p className="rounded-md border border-border/60 bg-card p-3 text-xs leading-relaxed text-foreground">
                    {active.description}
                  </p>
                </div>
              )}

              {/* EVIDENCE */}
              {active.evidence && (
                <div className="space-y-1.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                    Observed Evidence &amp; Proof
                  </h4>
                  <pre className="overflow-x-auto rounded-md bg-muted/60 p-3 font-mono text-[11px] leading-relaxed text-foreground">
                    {active.evidence}
                  </pre>
                </div>
              )}

              {/* REMEDIATION */}
              {active.solution && (
                <div className="space-y-1.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                    Remediation Steps
                  </h4>
                  <p className="rounded-md border border-primary/20 bg-primary/5 p-3 text-xs leading-relaxed text-foreground">
                    {active.solution}
                  </p>
                </div>
              )}

              {/* AI INSIGHT */}
              <AiInsight key={active.id} findingId={active.id} />

              {/* TRIAGE ACTIONS & RISK OVERRIDE */}
              <div className="space-y-3 border-t border-border pt-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  Triage Actions
                </h4>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap gap-1.5">
                    {STATES.map((s) => (
                      <Button
                        key={s}
                        size="sm"
                        variant={active.state === s ? "default" : "outline"}
                        onClick={() => updateStatus.mutate({ id: active.id, state: s })}
                        className="capitalize"
                      >
                        {s.replace("_", " ")}
                      </Button>
                    ))}
                  </div>

                  <Dialog open={overrideOpen} onOpenChange={setOverrideOpen}>
                    <DialogTrigger asChild>
                      <Button size="sm" variant="outline" className="gap-1.5">
                        <SlidersHorizontal className="size-3.5" /> Risk Override
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Apply Custom Risk Override</DialogTitle>
                      </DialogHeader>
                      <div className="space-y-3 pt-2">
                        <div className="space-y-1.5">
                          <Label>Effective Severity Override</Label>
                          <Select
                            value={String(overrideSeverity)}
                            onValueChange={(v) => setOverrideSeverity(Number(v))}
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="4">Critical (4)</SelectItem>
                              <SelectItem value="3">High (3)</SelectItem>
                              <SelectItem value="2">Medium (2)</SelectItem>
                              <SelectItem value="1">Low (1)</SelectItem>
                              <SelectItem value="0">Info (0)</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-1.5">
                          <Label>Business Justification / Reason</Label>
                          <Textarea
                            value={overrideReason}
                            onChange={(e) => setOverrideReason(e.target.value)}
                            placeholder="e.g. Compensating firewall control applied; asset isolated on air-gapped VLAN."
                            rows={3}
                          />
                        </div>
                        <Button
                          className="w-full"
                          disabled={!overrideReason || overrideMut.isPending}
                          onClick={() => overrideMut.mutate(active.id)}
                        >
                          {overrideMut.isPending ? "Applying..." : "Save Override & Recalculate"}
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
