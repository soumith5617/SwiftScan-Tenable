import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getDashboard } from "@/lib/data.functions";
import { PageHeader, StatPill, SeverityBadge } from "@/components/soc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CorrelationPanel } from "@/components/correlation-panel";
import { ExposureSummary } from "@/components/exposure-summary";
import {
  ShieldAlert,
  Flame,
  Clock,
  Server,
  Activity,
  Radar,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  Globe,
  Lock,
  Play,
  Layers,
  BarChart3,
  ShieldCheck,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from "recharts";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({
    meta: [
      { title: "Security Dashboard — AegisScan" },
      {
        name: "description",
        content:
          "Enterprise view of global risk posture, SLA compliance, KEV exploit exposure, asset risk and operational scanning telemetry.",
      },
      { property: "og:title", content: "Security Dashboard — AegisScan" },
      {
        property: "og:description",
        content: "Open vulnerabilities, KEV exposure and asset risk at a glance.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Dashboard,
});

function Dashboard() {
  const [activeTab, setActiveTab] = useState("executive");
  const { data, isLoading } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => getDashboard(),
    refetchInterval: 15000,
  });

  if (isLoading || !data) {
    return (
      <div className="flex h-96 items-center justify-center">
        <p className="text-sm text-muted-foreground animate-pulse">
          Loading enterprise security telemetry...
        </p>
      </div>
    );
  }

  // Derived metrics
  const totalOpen = data.totals.open || 0;
  const criticalCount = data.severity.critical || 0;
  const highCount = data.severity.high || 0;
  const overdueCount = data.totals.overdue || 0;
  const slaCompliance =
    totalOpen > 0
      ? Math.max(0, Number((((totalOpen - overdueCount) / totalOpen) * 100).toFixed(1)))
      : 100;

  // Global Risk Score (0-100)
  const globalRiskScore = Math.min(
    100,
    Math.round(
      (criticalCount * 25 + highCount * 12 + (data.totals.kev || 0) * 15) /
        Math.max(1, data.totals.assets || 1),
    ),
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Posture & Telemetry"
        description="Unified enterprise risk intelligence, SLA tracking, active scans and asset posture across your organization."
      >
        <div className="flex items-center gap-2">
          <Button asChild size="sm" className="gap-1.5">
            <Link to="/scans">
              <Radar className="size-4" /> Launch Scan
            </Link>
          </Button>
        </div>
      </PageHeader>

      {/* TOP LEVEL POSTURE PILLS */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatPill label="Active Findings" value={data.totals.open} />
        <StatPill label="Critical Severity" value={criticalCount} tone="critical" />
        <StatPill label="Known Exploited (KEV)" value={data.totals.kev} tone="high" />
        <StatPill
          label="SLA Compliance"
          value={`${slaCompliance}%`}
          tone={slaCompliance < 90 ? "medium" : "default"}
        />
      </div>

      {/* DASHBOARD PERSPECTIVE TABS */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-4 sm:w-auto">
          <TabsTrigger value="executive" className="gap-2">
            <ShieldCheck className="size-4" /> Executive Posture
          </TabsTrigger>
          <TabsTrigger value="operations" className="gap-2">
            <Activity className="size-4" /> Operations &amp; Scans
          </TabsTrigger>
          <TabsTrigger value="threats" className="gap-2">
            <Flame className="size-4" /> Threat &amp; Exploit Intel
          </TabsTrigger>
          <TabsTrigger value="assets" className="gap-2">
            <Server className="size-4" /> Asset Posture
          </TabsTrigger>
        </TabsList>

        {/* 1. EXECUTIVE POSTURE VIEW */}
        <TabsContent value="executive" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-3">
            {/* Global Risk Index Gauge Card */}
            <Card className="lg:col-span-1">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold">
                  Global Threat Exposure Index
                </CardTitle>
                <CardDescription className="text-xs">
                  Weighted across asset criticality &amp; KEV exploitability
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 pt-2 text-center">
                <div className="mx-auto flex size-28 flex-col items-center justify-center rounded-full border-4 border-primary/20 bg-muted/30">
                  <span className="text-3xl font-extrabold tabular-nums text-foreground">
                    {globalRiskScore}
                  </span>
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    / 100 Score
                  </span>
                </div>
                <div className="flex items-center justify-center gap-2">
                  <Badge
                    variant="outline"
                    className={
                      globalRiskScore >= 70
                        ? "border-red-500/30 bg-red-500/10 text-red-500 font-bold"
                        : globalRiskScore >= 40
                          ? "border-orange-500/30 bg-orange-500/10 text-orange-500 font-semibold"
                          : "border-green-500/30 bg-green-500/10 text-green-500 font-semibold"
                    }
                  >
                    {globalRiskScore >= 70
                      ? "Elevated Threat Level"
                      : globalRiskScore >= 40
                        ? "Moderate Exposure"
                        : "Hardened Posture"}
                  </Badge>
                </div>
                <div className="grid grid-cols-2 gap-2 border-t border-border pt-3 text-left text-xs">
                  <div>
                    <span className="text-muted-foreground">Monitored Targets:</span>
                    <p className="font-semibold text-foreground">{data.totals.assets} Assets</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Remediated Issues:</span>
                    <p className="font-semibold text-green-500">{data.totals.fixed} Fixed</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Severity Distribution Progress Card */}
            <Card className="lg:col-span-2">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold">
                    Severity Distribution &amp; SLA Breakdown
                  </CardTitle>
                  <span className="text-xs text-muted-foreground">
                    {totalOpen} Open Vulnerabilities
                  </span>
                </div>
              </CardHeader>
              <CardContent className="space-y-3 pt-2">
                {([4, 3, 2, 1, 0] as const).map((sev) => {
                  const key = (["info", "low", "medium", "high", "critical"] as const)[sev]!;
                  const value = data.severity[key];
                  const pct = totalOpen ? Math.round((value / totalOpen) * 100) : 0;
                  return (
                    <div key={sev} className="flex items-center gap-3">
                      <div className="w-20">
                        <SeverityBadge severity={sev} />
                      </div>
                      <Progress value={pct} className="h-2 flex-1" />
                      <span className="w-12 text-right text-xs font-semibold tabular-nums text-foreground">
                        {value} ({pct}%)
                      </span>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          </div>

          {/* Correlation & Exposure Panels */}
          <div className="grid gap-4 lg:grid-cols-2">
            <CorrelationPanel />
            <ExposureSummary />
          </div>

          {/* Top Priority Risks Table */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold">
                  Top Critical Vulnerabilities by Priority
                </CardTitle>
                <Link to="/findings" className="text-xs text-primary hover:underline">
                  View all findings &rarr;
                </Link>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {data.topRisks.length === 0 && (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  No open findings detected in your environment.
                </p>
              )}
              {data.topRisks.map((f) => (
                <Link
                  key={f.id}
                  to="/findings"
                  className="flex items-center gap-3 rounded-md border border-border/60 p-2.5 transition-colors hover:bg-muted/40"
                >
                  <SeverityBadge severity={f.severity} />
                  <span className="min-w-0 flex-1 truncate text-xs font-semibold text-foreground">
                    {f.title}
                  </span>
                  {f.kev && (
                    <Badge
                      variant="outline"
                      className="border-red-500/30 bg-red-500/10 text-red-500 font-bold text-[10px]"
                    >
                      CISA KEV
                    </Badge>
                  )}
                  <span className="font-mono text-xs font-bold text-foreground">
                    P {Number(f.priority ?? 0).toFixed(1)}
                  </span>
                </Link>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 2. OPERATIONS & SCANNING VIEW */}
        <TabsContent value="operations" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold">
                    Recent Scan Activity &amp; Engine Queue
                  </CardTitle>
                  <Link to="/scans" className="text-xs text-primary hover:underline">
                    Scan History &rarr;
                  </Link>
                </div>
              </CardHeader>
              <CardContent className="space-y-2.5">
                {data.scans.length === 0 && (
                  <p className="py-8 text-center text-sm text-muted-foreground">
                    No recent scan jobs found.
                  </p>
                )}
                {data.scans.map((s) => (
                  <Link
                    key={s.id}
                    to="/scans/$scanId"
                    params={{ scanId: s.id }}
                    className="flex items-center justify-between gap-3 rounded-md border border-border/60 p-3 text-sm transition-colors hover:bg-muted/50"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-semibold text-foreground">{s.name}</p>
                      <p className="font-mono text-xs text-muted-foreground">{s.target}</p>
                    </div>
                    <Badge
                      variant="outline"
                      className={
                        s.status === "completed"
                          ? "border-green-500/30 text-green-500 capitalize"
                          : s.status === "running"
                            ? "border-blue-500/30 text-blue-500 capitalize animate-pulse"
                            : "border-border text-muted-foreground capitalize"
                      }
                    >
                      {s.status}
                    </Badge>
                  </Link>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold">Scanning Engine Health</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-xs">
                <div className="flex items-center justify-between border-b border-border/50 pb-2">
                  <span className="text-muted-foreground">Built-in Async Engine:</span>
                  <Badge variant="outline" className="border-green-500/30 text-green-500 font-mono">
                    ONLINE
                  </Badge>
                </div>
                <div className="flex items-center justify-between border-b border-border/50 pb-2">
                  <span className="text-muted-foreground">Active Concurrency Limit:</span>
                  <span className="font-mono font-semibold">16 Workers</span>
                </div>
                <div className="flex items-center justify-between border-b border-border/50 pb-2">
                  <span className="text-muted-foreground">NVD/KEV Feed Sync:</span>
                  <span className="font-mono text-green-500 font-semibold">Healthy</span>
                </div>
                <div className="flex items-center justify-between pb-1">
                  <span className="text-muted-foreground">Distributed Agent Ingest:</span>
                  <span className="font-mono text-primary font-semibold">Ready (/api/public)</span>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 3. THREAT & EXPLOIT INTEL VIEW */}
        <TabsContent value="threats" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-3">
            {/* Trend Chart */}
            <Card className="lg:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold">
                  14-Day Vulnerability Discovery &amp; Exposure Trend
                </CardTitle>
                <CardDescription className="text-xs">
                  New findings discovered per day across environment
                </CardDescription>
              </CardHeader>
              <CardContent className="h-64 pt-4">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={data.trend}>
                    <defs>
                      <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
                    <XAxis dataKey="day" fontSize={11} stroke="#888888" />
                    <YAxis fontSize={11} stroke="#888888" />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#0f172a",
                        borderRadius: "6px",
                        border: "1px solid #334155",
                        fontSize: "12px",
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="total"
                      stroke="#3b82f6"
                      fillOpacity={1}
                      fill="url(#colorTotal)"
                      name="Total Findings"
                    />
                    <Area
                      type="monotone"
                      dataKey="critical"
                      stroke="#ef4444"
                      fillOpacity={1}
                      fill="url(#colorCrit)"
                      name="Critical Severity"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold">Intelligence Feed Coverage</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-xs">
                <div className="rounded-md border border-border/60 p-2.5">
                  <p className="font-semibold text-foreground">CISA KEV Catalog</p>
                  <p className="mt-0.5 text-muted-foreground">
                    {data.totals.kev} open findings match active exploit catalog
                  </p>
                </div>
                <div className="rounded-md border border-border/60 p-2.5">
                  <p className="font-semibold text-foreground">Cached CVE Definitions</p>
                  <p className="mt-0.5 text-muted-foreground">
                    {data.totals.cves} CVEs indexed in correlation memory
                  </p>
                </div>
                <div className="rounded-md border border-border/60 p-2.5">
                  <p className="font-semibold text-foreground">FIRST EPSS Probability</p>
                  <p className="mt-0.5 text-muted-foreground">
                    Scored dynamically against daily 30-day exploit probability
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 4. ASSET POSTURE VIEW */}
        <TabsContent value="assets" className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold">
                  Highest Risk Monitored Assets
                </CardTitle>
                <Link to="/assets" className="text-xs text-primary hover:underline">
                  Full Asset Inventory &rarr;
                </Link>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-border bg-muted/30 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    <tr>
                      <th className="px-4 py-3">Asset</th>
                      <th className="px-4 py-3">Criticality</th>
                      <th className="px-4 py-3 text-right">Risk Score</th>
                      <th className="px-4 py-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {data.assets.map((a) => (
                      <tr key={a.id} className="hover:bg-muted/30">
                        <td className="px-4 py-3 font-medium text-foreground">
                          {a.name}
                          <span className="block font-mono text-xs text-muted-foreground">
                            {a.target}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant="outline" className="capitalize">
                            {a.criticality}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-right font-mono font-bold tabular-nums text-foreground">
                          {a.risk_score}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <Button asChild size="sm" variant="ghost">
                            <Link to="/assets">Inspect</Link>
                          </Button>
                        </td>
                      </tr>
                    ))}
                    {data.assets.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-8 text-center text-sm text-muted-foreground">
                          No assets monitored yet. Launch a scan or import Nessus files to populate
                          assets.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
