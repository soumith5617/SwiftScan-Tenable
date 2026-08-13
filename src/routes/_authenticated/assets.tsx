import { createFileRoute } from "@tanstack/react-router";
import { useState, useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listAssets, createAsset, deleteAsset } from "@/lib/data.functions";
import {
  listAssetGroups,
  createAssetGroup,
  deleteAssetGroup,
  listHostPorts,
} from "@/lib/enterprise.functions";
import { PageHeader, SeverityBadge } from "@/components/soc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Server,
  FolderKanban,
  Network,
  Cpu,
  Trash2,
  Plus,
  Search,
  ExternalLink,
  ShieldAlert,
  Globe,
  Lock,
  Radio,
} from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/assets")({
  head: () => ({
    meta: [
      { title: "Asset Inventory & Port Discovery — AegisScan" },
      {
        name: "description",
        content:
          "Comprehensive asset inventory, dynamic asset groups, host discovery, open port mappings and OS fingerprinting.",
      },
      { property: "og:title", content: "Asset Inventory — AegisScan" },
      {
        property: "og:description",
        content: "Criticality-weighted asset inventory and risk scores.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AssetsPage,
});

function AssetsPage() {
  const qc = useQueryClient();
  const { data: assets = [], isLoading: loadingAssets } = useQuery({
    queryKey: ["assets"],
    queryFn: () => listAssets(),
  });
  const { data: groups = [], isLoading: loadingGroups } = useQuery({
    queryKey: ["asset-groups"],
    queryFn: () => listAssetGroups(),
  });
  const { data: ports = [], isLoading: loadingPorts } = useQuery({
    queryKey: ["host-ports"],
    queryFn: () => listHostPorts(),
  });

  // State
  const [activeTab, setActiveTab] = useState("inventory");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [critFilter, setCritFilter] = useState("all");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  // Asset creation modal state
  const [assetOpen, setAssetOpen] = useState(false);
  const [assetForm, setAssetForm] = useState({
    name: "",
    target: "",
    kind: "web" as "web" | "host" | "api" | "cloud" | "container",
    criticality: "medium" as "low" | "medium" | "high" | "critical",
    internet_facing: true,
  });

  // Group creation modal state
  const [groupOpen, setGroupOpen] = useState(false);
  const [groupForm, setGroupForm] = useState({
    name: "",
    description: "",
    color: "#3b82f6",
  });

  // Mutations
  const addAsset = useMutation({
    mutationFn: () => createAsset({ data: { ...assetForm, tags: [] } }),
    onSuccess: () => {
      setAssetOpen(false);
      setAssetForm({
        name: "",
        target: "",
        kind: "web",
        criticality: "medium",
        internet_facing: true,
      });
      qc.invalidateQueries({ queryKey: ["assets"] });
      toast.success("Asset registered successfully");
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Could not add asset"),
  });

  const removeAsset = useMutation({
    mutationFn: (id: string) => deleteAsset({ data: { id } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      setSelectedAssetId(null);
      toast.success("Asset deleted");
    },
  });

  const addGroup = useMutation({
    mutationFn: () => createAssetGroup({ data: groupForm }),
    onSuccess: () => {
      setGroupOpen(false);
      setGroupForm({ name: "", description: "", color: "#3b82f6" });
      qc.invalidateQueries({ queryKey: ["asset-groups"] });
      toast.success("Asset group created");
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Could not create group"),
  });

  const removeGroup = useMutation({
    mutationFn: (id: string) => deleteAssetGroup({ data: { id } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asset-groups"] });
      toast.success("Asset group removed");
    },
  });

  // Filtered Assets
  const filteredAssets = useMemo(() => {
    return assets.filter((a) => {
      if (typeFilter !== "all" && a.kind !== typeFilter) return false;
      if (critFilter !== "all" && a.criticality !== critFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return a.name.toLowerCase().includes(q) || a.target.toLowerCase().includes(q);
      }
      return true;
    });
  }, [assets, search, typeFilter, critFilter]);

  const selectedAsset = assets.find((a) => a.id === selectedAssetId) ?? null;
  const assetPorts = ports.filter((p) => p.asset_id === selectedAssetId);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Asset Inventory"
        description="Comprehensive attack surface inventory with automated port mapping, group segmentation and continuous risk scoring."
      >
        <div className="flex gap-2">
          <Dialog open={groupOpen} onOpenChange={setGroupOpen}>
            <DialogTrigger asChild>
              <Button size="sm" variant="outline" className="gap-1.5">
                <FolderKanban className="size-4" /> New Group
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create Asset Group</DialogTitle>
              </DialogHeader>
              <div className="space-y-3 pt-2">
                <div className="space-y-1.5">
                  <Label>Group Name</Label>
                  <Input
                    value={groupForm.name}
                    onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })}
                    placeholder="e.g. Production Web Tier"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Description</Label>
                  <Input
                    value={groupForm.description}
                    onChange={(e) => setGroupForm({ ...groupForm, description: e.target.value })}
                    placeholder="Assets critical to customer-facing commerce"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Badge Color</Label>
                  <div className="flex items-center gap-2">
                    <input
                      type="color"
                      value={groupForm.color}
                      onChange={(e) => setGroupForm({ ...groupForm, color: e.target.value })}
                      className="size-9 cursor-pointer rounded border border-border bg-transparent p-0.5"
                    />
                    <span className="font-mono text-xs text-muted-foreground">
                      {groupForm.color}
                    </span>
                  </div>
                </div>
                <Button
                  className="w-full"
                  disabled={!groupForm.name || addGroup.isPending}
                  onClick={() => addGroup.mutate()}
                >
                  {addGroup.isPending ? "Creating..." : "Create Group"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>

          <Dialog open={assetOpen} onOpenChange={setAssetOpen}>
            <DialogTrigger asChild>
              <Button size="sm" className="gap-1.5">
                <Plus className="size-4" /> Add Asset
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Register New Asset</DialogTitle>
              </DialogHeader>
              <div className="space-y-3 pt-2">
                <div className="space-y-1.5">
                  <Label>Asset Name</Label>
                  <Input
                    value={assetForm.name}
                    onChange={(e) => setAssetForm({ ...assetForm, name: e.target.value })}
                    placeholder="e.g. Primary Payment Gateway"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Target (FQDN / IP / URL)</Label>
                  <Input
                    value={assetForm.target}
                    onChange={(e) => setAssetForm({ ...assetForm, target: e.target.value })}
                    placeholder="api.company.com or 198.51.100.42"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label>Asset Type</Label>
                    <Select
                      value={assetForm.kind}
                      onValueChange={(v) =>
                        setAssetForm({ ...assetForm, kind: v as typeof assetForm.kind })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {["web", "host", "api", "cloud", "container"].map((k) => (
                          <SelectItem key={k} value={k} className="capitalize">
                            {k}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label>Business Criticality</Label>
                    <Select
                      value={assetForm.criticality}
                      onValueChange={(v) =>
                        setAssetForm({
                          ...assetForm,
                          criticality: v as typeof assetForm.criticality,
                        })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {["low", "medium", "high", "critical"].map((k) => (
                          <SelectItem key={k} value={k} className="capitalize">
                            {k}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="flex items-center justify-between rounded-md border border-border p-3">
                  <div className="space-y-0.5">
                    <Label htmlFor="asset-if">Internet Facing</Label>
                    <p className="text-xs text-muted-foreground">
                      Exposed to public inbound connections
                    </p>
                  </div>
                  <Switch
                    id="asset-if"
                    checked={assetForm.internet_facing}
                    onCheckedChange={(v) => setAssetForm({ ...assetForm, internet_facing: v })}
                  />
                </div>
                <Button
                  className="w-full"
                  disabled={!assetForm.name || !assetForm.target || addAsset.isPending}
                  onClick={() => addAsset.mutate()}
                >
                  {addAsset.isPending ? "Adding..." : "Register Asset"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </PageHeader>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-4 sm:w-auto">
          <TabsTrigger value="inventory" className="gap-2">
            <Server className="size-4" /> All Assets ({assets.length})
          </TabsTrigger>
          <TabsTrigger value="groups" className="gap-2">
            <FolderKanban className="size-4" /> Groups ({groups.length})
          </TabsTrigger>
          <TabsTrigger value="ports" className="gap-2">
            <Network className="size-4" /> Ports & Services ({ports.length})
          </TabsTrigger>
          <TabsTrigger value="technologies" className="gap-2">
            <Cpu className="size-4" /> Fingerprinted Tech
          </TabsTrigger>
        </TabsList>

        {/* 1. ALL ASSETS TAB */}
        <TabsContent value="inventory" className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative w-64">
                <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
                <Input
                  placeholder="Filter assets..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8"
                />
              </div>
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="Type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  {["web", "host", "api", "cloud", "container"].map((t) => (
                    <SelectItem key={t} value={t} className="capitalize">
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={critFilter} onValueChange={setCritFilter}>
                <SelectTrigger className="w-36">
                  <SelectValue placeholder="Criticality" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Criticality</SelectItem>
                  {["critical", "high", "medium", "low"].map((c) => (
                    <SelectItem key={c} value={c} className="capitalize">
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <p className="text-xs text-muted-foreground">{filteredAssets.length} assets matched</p>
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {filteredAssets.map((a) => (
              <Card
                key={a.id}
                className="cursor-pointer transition-all hover:border-primary/50 hover:shadow-sm"
                onClick={() => setSelectedAssetId(a.id)}
              >
                <CardContent className="space-y-3 p-4">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <p className="truncate font-semibold text-foreground">{a.name}</p>
                        {a.internet_facing ? (
                          <span title="Internet Facing" className="inline-flex items-center">
                            <Globe
                              className="size-3.5 shrink-0 text-amber-500"
                              aria-hidden="true"
                            />
                          </span>
                        ) : (
                          <span title="Internal" className="inline-flex items-center">
                            <Lock
                              className="size-3.5 shrink-0 text-muted-foreground"
                              aria-hidden="true"
                            />
                          </span>
                        )}
                      </div>
                      <p className="truncate font-mono text-xs text-muted-foreground">{a.target}</p>
                    </div>
                    <Badge
                      variant="outline"
                      className={
                        a.criticality === "critical"
                          ? "border-red-500/30 bg-red-500/10 text-red-500 font-semibold"
                          : a.criticality === "high"
                            ? "border-orange-500/30 bg-orange-500/10 text-orange-500"
                            : "border-border text-muted-foreground"
                      }
                    >
                      {a.criticality}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-3 gap-2 rounded-md bg-muted/40 p-2.5 text-center text-xs">
                    <div>
                      <p className="text-[10px] uppercase text-muted-foreground">Risk Score</p>
                      <p className="mt-0.5 text-base font-bold tabular-nums text-foreground">
                        {a.risk_score}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase text-muted-foreground">Open Issues</p>
                      <p className="mt-0.5 text-base font-bold tabular-nums text-foreground">
                        {a.openFindings}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase text-muted-foreground">Crit / High</p>
                      <p className="mt-0.5 text-base font-bold tabular-nums">
                        <span className="text-sev-critical">{a.critical}</span> /{" "}
                        <span className="text-sev-high">{a.high}</span>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span className="capitalize">{a.kind} Asset</span>
                    <span>
                      Last active:{" "}
                      {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : "Never"}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {filteredAssets.length === 0 && !loadingAssets && (
            <Card>
              <CardContent className="py-12 text-center text-sm text-muted-foreground">
                No assets matched your search filters. Click &quot;Add Asset&quot; to register a
                target.
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* 2. ASSET GROUPS TAB */}
        <TabsContent value="groups" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {groups.map((g) => (
              <Card key={g.id}>
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div className="size-3 rounded-full" style={{ backgroundColor: g.color }} />
                      <CardTitle className="text-base font-semibold">{g.name}</CardTitle>
                    </div>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-7 text-muted-foreground hover:text-destructive"
                      onClick={() => removeGroup.mutate(g.id)}
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>
                  <CardDescription className="text-xs">
                    {g.description || "No description provided."}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <div className="flex items-center justify-between rounded-md bg-muted/40 p-2.5 text-xs">
                    <span className="text-muted-foreground">Assigned Assets:</span>
                    <span className="font-semibold tabular-nums">{g.asset_count}</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    Created on {new Date(g.created_at).toLocaleDateString()}
                  </p>
                </CardContent>
              </Card>
            ))}
            {groups.length === 0 && !loadingGroups && (
              <Card className="col-span-full">
                <CardContent className="py-10 text-center text-sm text-muted-foreground">
                  No asset groups configured. Create groups to organize assets by business unit or
                  environment tier.
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        {/* 3. HOST PORTS TAB */}
        <TabsContent value="ports" className="space-y-4">
          <Card>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-border bg-muted/30 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    <tr>
                      <th className="px-4 py-3">Asset</th>
                      <th className="px-4 py-3">Port</th>
                      <th className="px-4 py-3">Protocol</th>
                      <th className="px-4 py-3">State</th>
                      <th className="px-4 py-3">Service</th>
                      <th className="px-4 py-3">Banner / Product</th>
                      <th className="px-4 py-3 text-right">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {ports.map((p) => (
                      <tr key={p.id} className="hover:bg-muted/30">
                        <td className="px-4 py-3 font-medium text-foreground">
                          {p.assets?.name || "Asset"}
                          <span className="block font-mono text-xs text-muted-foreground">
                            {p.assets?.target}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono font-semibold">{p.port}</td>
                        <td className="px-4 py-3 font-mono uppercase text-xs">{p.protocol}</td>
                        <td className="px-4 py-3">
                          <Badge
                            variant="outline"
                            className="border-green-500/30 bg-green-500/10 text-green-500 font-mono text-xs"
                          >
                            {p.state}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 capitalize font-medium">
                          {p.service_name || "Unknown"}
                        </td>
                        <td className="max-w-xs truncate px-4 py-3 text-xs text-muted-foreground">
                          {p.banner || p.product || "—"}
                        </td>
                        <td className="px-4 py-3 text-right text-xs text-muted-foreground">
                          {new Date(p.last_seen).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                    {ports.length === 0 && !loadingPorts && (
                      <tr>
                        <td colSpan={7} className="py-8 text-center text-sm text-muted-foreground">
                          No open ports discovered yet. Launch a scan to initiate host port
                          discovery.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 4. TECHNOLOGIES TAB */}
        <TabsContent value="technologies" className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {assets
              .flatMap((a) =>
                Array.isArray(a.technologies)
                  ? (a.technologies as unknown as Array<{
                      name: string;
                      version?: string;
                      source?: string;
                    }>)
                  : [],
              )
              .map((t, idx) => (
                <Card key={idx}>
                  <CardContent className="space-y-1.5 p-4">
                    <div className="flex items-center justify-between">
                      <p className="font-semibold text-foreground">{t.name}</p>
                      {t.version && <Badge variant="secondary">{t.version}</Badge>}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Source: {t.source || "Header fingerprint"}
                    </p>
                  </CardContent>
                </Card>
              ))}
            {assets.every(
              (a) =>
                !Array.isArray(a.technologies) ||
                (
                  a.technologies as unknown as Array<{
                    name: string;
                    version?: string;
                    source?: string;
                  }>
                ).length === 0,
            ) && (
              <Card className="col-span-full">
                <CardContent className="py-10 text-center text-sm text-muted-foreground">
                  No technology fingerprints recorded yet. Technologies are discovered automatically
                  during active scans.
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>
      </Tabs>

      {/* ASSET DETAIL DRAWER */}
      <Sheet open={!!selectedAsset} onOpenChange={(o) => !o && setSelectedAssetId(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
          {selectedAsset && (
            <div className="space-y-6">
              <SheetHeader>
                <div className="flex items-center gap-2">
                  <SheetTitle className="text-lg font-bold">{selectedAsset.name}</SheetTitle>
                  <Badge variant="outline" className="capitalize">
                    {selectedAsset.kind}
                  </Badge>
                </div>
                <p className="font-mono text-xs text-muted-foreground">{selectedAsset.target}</p>
              </SheetHeader>

              <div className="grid grid-cols-2 gap-3 rounded-lg bg-muted/40 p-4 text-xs">
                <div>
                  <span className="text-muted-foreground">Criticality: </span>
                  <span className="font-semibold capitalize text-foreground">
                    {selectedAsset.criticality}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Exposure: </span>
                  <span className="font-semibold text-foreground">
                    {selectedAsset.internet_facing ? "Public Internet Facing" : "Internal Network"}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Risk Score: </span>
                  <span className="font-bold text-foreground">
                    {selectedAsset.risk_score} / 100
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Open Findings: </span>
                  <span className="font-semibold text-foreground">
                    {selectedAsset.openFindings}
                  </span>
                </div>
              </div>

              <div>
                <h4 className="mb-2 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  Discovered Ports ({assetPorts.length})
                </h4>
                {assetPorts.length === 0 ? (
                  <p className="rounded-md border border-border/50 p-3 text-xs text-muted-foreground">
                    No ports recorded for this asset yet.
                  </p>
                ) : (
                  <div className="divide-y divide-border rounded-md border border-border">
                    {assetPorts.map((p) => (
                      <div key={p.id} className="flex items-center justify-between p-2.5 text-xs">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold">
                            {p.port}/{p.protocol}
                          </span>
                          <span className="text-muted-foreground">
                            {p.service_name || "unknown"}
                          </span>
                        </div>
                        <span className="font-mono text-muted-foreground">
                          {p.banner || "Open"}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="pt-4">
                <Button
                  variant="destructive"
                  size="sm"
                  className="w-full gap-2"
                  onClick={() => removeAsset.mutate(selectedAsset.id)}
                  disabled={removeAsset.isPending}
                >
                  <Trash2 className="size-4" /> Delete Asset &amp; History
                </Button>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
