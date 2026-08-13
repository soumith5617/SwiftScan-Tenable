import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { importScanResults } from "@/lib/import.functions";
import { PageHeader } from "@/components/soc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { UploadCloud } from "lucide-react";

export const Route = createFileRoute("/_authenticated/import")({
  head: () => ({
    meta: [
      { title: "Import scan results — AegisScan" },
      {
        name: "description",
        content:
          "Import .nessus XML or CSV vulnerability exports, auto-create assets and enrich every finding with KEV and EPSS intelligence.",
      },
      { property: "og:title", content: "Import scan results — AegisScan" },
      {
        property: "og:description",
        content: "Bring Nessus and CSV exports into AegisScan in seconds.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ImportPage,
});

function ImportPage() {
  const qc = useQueryClient();
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [assetName, setAssetName] = useState("");

  const run = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Choose a file first");
      const content = await file.text();
      return importScanResults({
        data: { filename: file.name, content, assetName: assetName || undefined },
      });
    },
    onSuccess: (r) => {
      toast.success(`Imported ${r.findings} findings across ${r.hosts} host(s)`);
      qc.invalidateQueries();
      if (r.scanId) router.navigate({ to: "/scans/$scanId", params: { scanId: r.scanId } });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Import failed"),
  });

  return (
    <div className="max-w-3xl">
      <PageHeader
        title="Import scan results"
        description="Nessus .nessus XML and generic CSV exports are parsed, deduplicated into assets and re-scored."
      />

      <Card>
        <CardContent className="space-y-4 py-6">
          <label className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border p-10 text-center hover:bg-muted/40">
            <UploadCloud className="size-8 text-muted-foreground" />
            <span className="text-sm font-medium">
              {file ? file.name : "Choose a .nessus, .xml or .csv export"}
            </span>
            <span className="text-xs text-muted-foreground">Up to ~6 MB per file</span>
            <input
              type="file"
              accept=".nessus,.xml,.csv,text/csv,text/xml"
              className="hidden"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </label>

          <div className="space-y-1.5">
            <Label htmlFor="asset">Asset name override (single-host files)</Label>
            <Input
              id="asset"
              value={assetName}
              onChange={(e) => setAssetName(e.target.value)}
              placeholder="Optional"
            />
          </div>

          <Button className="w-full" disabled={!file || run.isPending} onClick={() => run.mutate()}>
            {run.isPending ? "Parsing and enriching…" : "Import results"}
          </Button>
        </CardContent>
      </Card>

      <Card className="mt-4">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">What happens on import</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            1. Every ReportHost / CSV row becomes a finding with plugin ID, output evidence and
            remediation text.
          </p>
          <p>2. Hosts are matched against existing assets, or created automatically.</p>
          <p>3. CVE references are correlated against the cached KEV and EPSS intelligence.</p>
          <p>
            4. Priority scores and SLA due dates are calculated so imported data behaves exactly
            like native scans.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
