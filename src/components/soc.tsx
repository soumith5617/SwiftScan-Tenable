import { Badge } from "@/components/ui/badge";
import { severityBg, severityLabel } from "@/lib/severity";
import { cn } from "@/lib/utils";

export function SeverityBadge({ severity, className }: { severity: number; className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn("font-medium tabular-nums", severityBg(severity), className)}
    >
      {severityLabel(severity)}
    </Badge>
  );
}

export function StatPill({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "critical" | "high" | "medium" | "low" | "info" | "default";
}) {
  const toneClass =
    tone === "critical"
      ? "text-sev-critical"
      : tone === "high"
        ? "text-sev-high"
        : tone === "medium"
          ? "text-sev-medium"
          : tone === "low"
            ? "text-sev-low"
            : tone === "info"
              ? "text-sev-info"
              : "text-foreground";
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={cn("mt-1 text-2xl font-semibold tabular-nums", toneClass)}>{value}</p>
    </div>
  );
}

export function PageHeader({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      <div className="flex flex-wrap gap-2">{children}</div>
    </div>
  );
}
