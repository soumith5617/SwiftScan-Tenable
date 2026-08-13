import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useMemo } from "react";
import { listScans, createScan, deleteScan } from "@/lib/data.functions";
import { runScan } from "@/lib/scans.functions";
import { SCAN_CATALOG, SCAN_CATEGORIES, getTemplate, ScanCategory } from "@/lib/templates";
import { PageHeader } from "@/components/soc";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { Trash2, Play, Search } from "lucide-react";

export const Route = createFileRoute("/_authenticated/scans/")({
  head: () => ({
    meta: [
      { title: "Scans — AegisScan" },
      {
        name: "description",
        content:
          "Launch async vulnerability scans with tuned templates and follow live progress per plugin family.",
      },
      { property: "og:title", content: "Scans — AegisScan" },
      {
        property: "og:description",
        content: "Launch and monitor vulnerability scans in real time.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ScansPage,
});

function ScansPage() {
  const qc = useQueryClient();
  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => listScans(),
    refetchInterval: 4000,
  });
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState("");
  const [name, setName] = useState("");
  const [template, setTemplate] = useState<string>("basic_network_scan");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  const filteredTemplates = useMemo(() => {
    return SCAN_CATALOG.filter((t) => {
      const matchCat = categoryFilter === "all" || t.category === categoryFilter;
      const matchQuery =
        !searchQuery ||
        t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.category.toLowerCase().includes(searchQuery.toLowerCase());
      return matchCat && matchQuery;
    });
  }, [categoryFilter, searchQuery]);

  const selectedTemplate = useMemo(() => getTemplate(template), [template]);

  const launch = useMutation({
    mutationFn: async () => {
      const scan = await createScan({
        data: { name: name || `Scan of ${target}`, target, template, createAsset: true },
      });
      setOpen(false);
      setTarget("");
      setName("");
      await qc.invalidateQueries({ queryKey: ["scans"] });
      const res = await runScan({ data: { scanId: scan.id } });
      return res;
    },
    onSuccess: (res) => {
      if (res.ok) toast.success(`Scan complete — ${res.findings} findings`);
      else toast.error(`Scan failed: ${res.reason}`);
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Scan failed"),
  });

  const remove = useMutation({
    mutationFn: (id: string) => deleteScan({ data: { id } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Async engine with pooled concurrency, adaptive timeouts and plugin families."
      >
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="sm">New scan</Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[90vh] flex flex-col">
            <DialogHeader>
              <DialogTitle>Launch a scan</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 overflow-y-auto pr-1 flex-1">
              <div className="space-y-1.5">
                <Label htmlFor="target">Target</Label>
                <Input
                  id="target"
                  placeholder="example.com or https://app.example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Only scan systems you are authorised to test. Private and loopback ranges are
                  blocked.
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="name">Scan name (optional)</Label>
                <Input id="name" value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Template ({SCAN_CATALOG.length} available)</Label>
                  <Link to="/templates" className="text-xs text-primary hover:underline">
                    Catalog details
                  </Link>
                </div>

                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
                    <Input
                      placeholder="Search templates (e.g. log4shell, pci, database, web)..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-8 text-xs h-9"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap gap-1 py-1">
                  <button
                    type="button"
                    onClick={() => setCategoryFilter("all")}
                    className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors ${
                      categoryFilter === "all"
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted hover:bg-muted/80 text-muted-foreground"
                    }`}
                  >
                    All (50)
                  </button>
                  {SCAN_CATEGORIES.map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setCategoryFilter(cat)}
                      className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors ${
                        categoryFilter === cat
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted hover:bg-muted/80 text-muted-foreground"
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>

                <div className="grid max-h-56 gap-1.5 overflow-y-auto pr-1">
                  {filteredTemplates.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => setTemplate(t.id)}
                      className={`rounded-md border p-2.5 text-left text-sm transition-colors ${
                        template === t.id
                          ? "border-primary bg-primary/10"
                          : "border-border hover:bg-muted/50"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <p className="font-medium text-xs sm:text-sm">{t.name}</p>
                        <Badge variant="outline" className="text-[10px] py-0 shrink-0">
                          {t.category}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                        {t.description}
                      </p>
                    </button>
                  ))}
                  {filteredTemplates.length === 0 && (
                    <p className="text-xs text-muted-foreground py-4 text-center">
                      No scan templates match &quot;{searchQuery}&quot;
                    </p>
                  )}
                </div>

                {selectedTemplate && (
                  <div className="rounded-md border border-primary/20 bg-primary/5 p-2.5 text-xs">
                    <p className="font-semibold text-primary">Selected: {selectedTemplate.name}</p>
                    <p className="text-muted-foreground mt-0.5">{selectedTemplate.purpose}</p>
                  </div>
                )}
              </div>
              <Button
                className="w-full mt-2"
                disabled={!target || launch.isPending}
                onClick={() => launch.mutate()}
              >
                {launch.isPending ? "Scanning…" : `Start ${selectedTemplate?.name ?? "Scan"}`}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </PageHeader>

      <div className="space-y-2">
        {(scans ?? []).length === 0 && (
          <Card>
            <CardContent className="py-10 text-center text-sm text-muted-foreground">
              No scans yet. Launch your first scan to populate findings.
            </CardContent>
          </Card>
        )}
        {(scans ?? []).map((s) => {
          const stats = (s.stats ?? {}) as Record<string, number>;
          return (
            <Card key={s.id}>
              <CardContent className="flex flex-wrap items-center gap-3 py-3">
                <div className="min-w-0 flex-1">
                  <Link
                    to="/scans/$scanId"
                    params={{ scanId: s.id }}
                    className="truncate font-medium hover:underline"
                  >
                    {s.name}
                  </Link>
                  <p className="truncate text-xs text-muted-foreground">
                    {s.target} · {getTemplate(s.template)?.name ?? s.template} ·{" "}
                    {new Date(s.created_at).toLocaleString()}
                  </p>
                  {s.status === "running" && (
                    <div className="mt-2 flex items-center gap-2">
                      <Progress value={s.progress} className="h-1.5 w-48" />
                      <span className="text-xs text-muted-foreground">{s.current_step}</span>
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-1.5 text-xs">
                  <Sev n={stats["critical"] ?? 0} c="bg-sev-critical/15 text-sev-critical" />
                  <Sev n={stats["high"] ?? 0} c="bg-sev-high/15 text-sev-high" />
                  <Sev n={stats["medium"] ?? 0} c="bg-sev-medium/15 text-sev-medium" />
                  <Sev n={stats["low"] ?? 0} c="bg-sev-low/15 text-sev-low" />
                </div>
                <Badge variant="outline" className="capitalize">
                  {s.status}
                </Badge>
                {(s.status === "queued" || s.status === "failed") && (
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={async () => {
                      const res = await runScan({ data: { scanId: s.id } });
                      qc.invalidateQueries({ queryKey: ["scans"] });
                      if (res.ok) toast.success(`Scan complete — ${res.findings} findings`);
                      else toast.error(`Scan failed: ${res.reason}`);
                    }}
                  >
                    <Play className="size-4" />
                  </Button>
                )}
                <Button size="icon" variant="ghost" onClick={() => remove.mutate(s.id)}>
                  <Trash2 className="size-4" />
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function Sev({ n, c }: { n: number; c: string }) {
  return <span className={`rounded px-1.5 py-0.5 font-semibold tabular-nums ${c}`}>{n}</span>;
}
