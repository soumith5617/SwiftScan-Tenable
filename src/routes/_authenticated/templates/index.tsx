import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  SCAN_CATALOG,
  SCAN_CATEGORIES,
  MODE_LABEL,
  MODE_CLASS,
  SCAN_WORKFLOW,
  type ScanMode,
} from "@/lib/templates";
import { PageHeader } from "@/components/soc";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowRight } from "lucide-react";

export const Route = createFileRoute("/_authenticated/templates/")({
  head: () => ({
    meta: [
      { title: "Scan Templates — AegisScan" },
      {
        name: "description",
        content:
          "Every Nessus-class scan template: discovery, network, web, API, endpoint, cloud, compliance and specialized CVE hunts.",
      },
      { property: "og:title", content: "Scan Templates — AegisScan" },
      {
        property: "og:description",
        content: "The full scan-template catalog with honest execution modes.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: TemplatesPage,
});

const MODES: (ScanMode | "all")[] = ["all", "native", "agent", "analysis"];

function TemplatesPage() {
  const [q, setQ] = useState("");
  const [mode, setMode] = useState<ScanMode | "all">("all");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return SCAN_CATALOG.filter((t) => {
      if (mode !== "all" && t.mode !== mode) return false;
      if (!needle) return true;
      return (
        t.name.toLowerCase().includes(needle) ||
        t.description.toLowerCase().includes(needle) ||
        t.detects.join(" ").toLowerCase().includes(needle) ||
        t.techniques.join(" ").toLowerCase().includes(needle)
      );
    });
  }, [q, mode]);

  const counts = {
    native: SCAN_CATALOG.filter((t) => t.mode === "native").length,
    agent: SCAN_CATALOG.filter((t) => t.mode === "agent").length,
    analysis: SCAN_CATALOG.filter((t) => t.mode === "analysis").length,
  };

  return (
    <div>
      <PageHeader
        title="Scan templates"
        description={`${SCAN_CATALOG.length} templates — ${counts.native} run natively here, ${counts.agent} delegate to a scan agent, ${counts.analysis} evaluate platform data.`}
      />

      <Card className="mb-4">
        <CardContent className="py-4">
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Scan workflow
          </p>
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
            {SCAN_WORKFLOW.map((s, i) => (
              <span key={s} className="flex items-center gap-1.5">
                <span className="rounded border border-border bg-muted/40 px-1.5 py-0.5">{s}</span>
                {i < SCAN_WORKFLOW.length - 1 && <span className="text-muted-foreground">→</span>}
              </span>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search templates, techniques or detections…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="max-w-sm"
        />
        {MODES.map((m) => (
          <Button
            key={m}
            size="sm"
            variant={mode === m ? "default" : "outline"}
            onClick={() => setMode(m)}
          >
            {m === "all" ? "All modes" : MODE_LABEL[m]}
          </Button>
        ))}
      </div>

      <div className="space-y-8">
        {SCAN_CATEGORIES.map((cat) => {
          const items = filtered.filter((t) => t.category === cat);
          if (!items.length) return null;
          return (
            <section key={cat}>
              <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                {cat}
              </h2>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {items.map((t) => (
                  <Link
                    key={t.id}
                    to="/templates/$templateId"
                    params={{ templateId: t.id }}
                    className="group"
                  >
                    <Card className="h-full transition-colors group-hover:border-primary/50">
                      <CardContent className="flex h-full flex-col gap-2 py-4">
                        <div className="flex items-start justify-between gap-2">
                          <p className="font-medium leading-tight">{t.name}</p>
                          <Badge variant="outline" className={MODE_CLASS[t.mode]}>
                            {MODE_LABEL[t.mode]}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground">{t.description}</p>
                        <div className="mt-auto flex flex-wrap gap-1 pt-2">
                          {t.detects.slice(0, 3).map((d) => (
                            <span
                              key={d}
                              className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]"
                            >
                              {d}
                            </span>
                          ))}
                        </div>
                        <span className="flex items-center gap-1 text-xs text-primary opacity-0 transition-opacity group-hover:opacity-100">
                          Open template <ArrowRight className="size-3" />
                        </span>
                      </CardContent>
                    </Card>
                  </Link>
                ))}
              </div>
            </section>
          );
        })}
        {filtered.length === 0 && (
          <Card>
            <CardContent className="py-10 text-center text-sm text-muted-foreground">
              No templates match that filter.
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
