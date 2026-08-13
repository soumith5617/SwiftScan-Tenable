import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listReports, generateReport, deleteReport } from "@/lib/reports.functions";
import { PageHeader } from "@/components/soc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  FileText,
  Download,
  Trash2,
  Plus,
  Printer,
  ShieldCheck,
  Table,
  Code,
  FileSpreadsheet,
} from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/reports")({
  head: () => ({
    meta: [
      { title: "Executive & Technical Security Reports — AegisScan" },
      {
        name: "description",
        content:
          "Generate executive summaries, technical vulnerability sheets, asset inventories and compliance scorecards in PDF, CSV and JSON formats.",
      },
      { property: "og:title", content: "Reports — AegisScan" },
      {
        property: "og:description",
        content: "Generate and export vulnerability management reports.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ReportsPage,
});

interface ReportSummary {
  findings_count?: number;
  critical_count?: number;
  high_count?: number;
  assets_count?: number;
  generated_by?: string;
}

function ReportsPage() {
  const qc = useQueryClient();
  const { data: reports = [], isLoading } = useQuery({
    queryKey: ["reports"],
    queryFn: () => listReports(),
  });

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    title: "",
    kind: "executive" as "executive" | "technical" | "asset" | "compliance",
    format: "pdf" as "pdf" | "csv" | "json",
  });

  // Client-side file download helper
  const triggerDownload = (content: string, mimeType: string, fileName: string) => {
    if (mimeType.includes("html")) {
      const win = window.open("", "_blank");
      if (win) {
        win.document.write(content);
        win.document.close();
        win.focus();
        return;
      }
    }
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const create = useMutation({
    mutationFn: () => generateReport({ data: form }),
    onSuccess: (res) => {
      setOpen(false);
      setForm({ title: "", kind: "executive", format: "pdf" });
      qc.invalidateQueries({ queryKey: ["reports"] });
      toast.success("Report generated successfully");
      triggerDownload(res.content, res.mimeType, res.fileName);
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Could not generate report"),
  });

  const remove = useMutation({
    mutationFn: (id: string) => deleteReport({ data: { id } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["reports"] });
      toast.success("Report removed from history");
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Reports"
        description="Generate publication-ready Executive Summaries, Technical Assessments, Asset Breakdown sheets, and raw data exports."
      >
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-1.5">
              <Plus className="size-4" /> New Report
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Generate Security Report</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <Label>Report Title</Label>
                <Input
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                  placeholder="e.g. Q3 Executive Vulnerability Assessment"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label>Report Type</Label>
                  <Select
                    value={form.kind}
                    onValueChange={(v) => setForm({ ...form, kind: v as typeof form.kind })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="executive">Executive Summary</SelectItem>
                      <SelectItem value="technical">Technical Assessment</SelectItem>
                      <SelectItem value="asset">Asset Inventory</SelectItem>
                      <SelectItem value="compliance">Compliance Scorecard</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label>Export Format</Label>
                  <Select
                    value={form.format}
                    onValueChange={(v) => setForm({ ...form, format: v as typeof form.format })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="pdf">PDF (Printable Document)</SelectItem>
                      <SelectItem value="csv">CSV Spreadsheet</SelectItem>
                      <SelectItem value="json">JSON Structured Data</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="rounded-md border border-border/60 bg-muted/40 p-3 text-xs text-muted-foreground space-y-1">
                <p className="font-semibold text-foreground">Included data sections:</p>
                <p>• Executive risk score &amp; posture summary</p>
                <p>• Severity distribution and active KEV exposures</p>
                <p>• Evidence-backed finding breakdown &amp; remediation</p>
              </div>

              <Button
                className="w-full gap-2"
                disabled={!form.title || create.isPending}
                onClick={() => create.mutate()}
              >
                <FileText className="size-4" />
                {create.isPending ? "Compiling Report..." : "Generate & Download Report"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </PageHeader>

      {/* QUICK TEMPLATES GRID */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card
          className="cursor-pointer transition-all hover:border-primary/50"
          onClick={() => {
            setForm({ title: "Executive Security Summary", kind: "executive", format: "pdf" });
            setOpen(true);
          }}
        >
          <CardHeader className="p-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-5 text-primary" />
              <CardTitle className="text-sm font-semibold">Executive Summary</CardTitle>
            </div>
            <CardDescription className="text-xs">
              High-level risk gauges, SLA rates &amp; posture
            </CardDescription>
          </CardHeader>
        </Card>

        <Card
          className="cursor-pointer transition-all hover:border-primary/50"
          onClick={() => {
            setForm({ title: "Technical Vulnerability Report", kind: "technical", format: "pdf" });
            setOpen(true);
          }}
        >
          <CardHeader className="p-4">
            <div className="flex items-center gap-2">
              <FileText className="size-5 text-orange-500" />
              <CardTitle className="text-sm font-semibold">Technical Findings</CardTitle>
            </div>
            <CardDescription className="text-xs">
              Detailed findings with proof &amp; remediation
            </CardDescription>
          </CardHeader>
        </Card>

        <Card
          className="cursor-pointer transition-all hover:border-primary/50"
          onClick={() => {
            setForm({ title: "Asset Inventory Export", kind: "asset", format: "csv" });
            setOpen(true);
          }}
        >
          <CardHeader className="p-4">
            <div className="flex items-center gap-2">
              <FileSpreadsheet className="size-5 text-green-500" />
              <CardTitle className="text-sm font-semibold">Asset Inventory</CardTitle>
            </div>
            <CardDescription className="text-xs">
              Export all targets, criticality &amp; risk scores
            </CardDescription>
          </CardHeader>
        </Card>

        <Card
          className="cursor-pointer transition-all hover:border-primary/50"
          onClick={() => {
            setForm({ title: "Compliance Scorecard", kind: "compliance", format: "pdf" });
            setOpen(true);
          }}
        >
          <CardHeader className="p-4">
            <div className="flex items-center gap-2">
              <Table className="size-5 text-blue-500" />
              <CardTitle className="text-sm font-semibold">Compliance Audit</CardTitle>
            </div>
            <CardDescription className="text-xs">
              CIS, NIST, PCI &amp; HIPAA pass/fail controls
            </CardDescription>
          </CardHeader>
        </Card>
      </div>

      {/* GENERATED REPORTS HISTORY */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Report Generation Archive</CardTitle>
          <CardDescription className="text-xs">
            History of all generated reports and exports
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-muted/30 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-4 py-3">Report Title</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Format</th>
                  <th className="px-4 py-3">Findings / Assets</th>
                  <th className="px-4 py-3">Generated Date</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {reports.map((r) => {
                  const summary = (r.summary ?? {}) as ReportSummary;
                  return (
                    <tr key={r.id} className="hover:bg-muted/30">
                      <td className="px-4 py-3 font-semibold text-foreground">
                        {r.title}
                        <span className="block text-xs font-normal text-muted-foreground">
                          {r.status === "completed" ? "Completed" : "Generating"}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className="capitalize">
                          {r.kind}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 font-mono uppercase text-xs">
                        <Badge variant="secondary">{r.format}</Badge>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {summary.findings_count !== undefined
                          ? `${summary.findings_count} findings · ${summary.assets_count ?? 0} assets`
                          : "—"}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {new Date(r.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-8 text-muted-foreground hover:text-destructive"
                          onClick={() => remove.mutate(r.id)}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </td>
                    </tr>
                  );
                })}
                {reports.length === 0 && !isLoading && (
                  <tr>
                    <td colSpan={6} className="py-10 text-center text-sm text-muted-foreground">
                      No reports generated yet. Click &quot;New Report&quot; to export an
                      assessment.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
