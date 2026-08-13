export const SEVERITY_LABELS = ["Info", "Low", "Medium", "High", "Critical"] as const;

export type SeverityLevel = 0 | 1 | 2 | 3 | 4;

export function severityLabel(sev: number): string {
  return SEVERITY_LABELS[Math.max(0, Math.min(4, Math.round(sev)))] ?? "Info";
}

export function severityColor(sev: number): string {
  switch (Math.max(0, Math.min(4, Math.round(sev)))) {
    case 4:
      return "text-sev-critical";
    case 3:
      return "text-sev-high";
    case 2:
      return "text-sev-medium";
    case 1:
      return "text-sev-low";
    default:
      return "text-sev-info";
  }
}

export function severityBg(sev: number): string {
  switch (Math.max(0, Math.min(4, Math.round(sev)))) {
    case 4:
      return "bg-sev-critical/15 text-sev-critical border-sev-critical/30";
    case 3:
      return "bg-sev-high/15 text-sev-high border-sev-high/30";
    case 2:
      return "bg-sev-medium/15 text-sev-medium border-sev-medium/30";
    case 1:
      return "bg-sev-low/15 text-sev-low border-sev-low/30";
    default:
      return "bg-sev-info/15 text-sev-info border-sev-info/30";
  }
}

export function severityFromCvss(cvss: number | null | undefined): number {
  if (cvss == null) return 0;
  if (cvss >= 9) return 4;
  if (cvss >= 7) return 3;
  if (cvss >= 4) return 2;
  if (cvss > 0) return 1;
  return 0;
}

/**
 * VPR-style priority score (0-10): CVSS weighted by real-world exploit signals,
 * asset criticality and exposure. Recomputed whenever intelligence feeds update.
 */
export function priorityScore(input: {
  cvss?: number | null;
  severity: number;
  epss?: number | null;
  kev?: boolean;
  criticality?: string | null;
  internetFacing?: boolean;
  confidence?: string;
}): number {
  const base = input.cvss ?? input.severity * 2.4;
  const epss = input.epss ?? 0;
  let score = base * 0.62;
  score += epss * 2.6;
  if (input.kev) score += 2.2;
  const critMultiplier =
    input.criticality === "critical"
      ? 1.18
      : input.criticality === "high"
        ? 1.1
        : input.criticality === "low"
          ? 0.9
          : 1;
  score *= critMultiplier;
  if (input.internetFacing) score *= 1.06;
  if (input.confidence === "low") score *= 0.85;
  return Math.max(0, Math.min(10, Math.round(score * 10) / 10));
}

export const SLA_DAYS: Record<number, number> = { 4: 7, 3: 15, 2: 30, 1: 90, 0: 180 };

export function slaDueDate(severity: number, from: Date = new Date()): Date {
  const days = SLA_DAYS[Math.max(0, Math.min(4, Math.round(severity)))] ?? 90;
  return new Date(from.getTime() + days * 86400000);
}

export { SCAN_CATALOG as SCAN_TEMPLATES, NATIVE_TEMPLATES, getTemplate } from "./templates";
export type { ScanTemplate, ScanMode, ScanCategory } from "./templates";

export const FINDING_STATES = [
  "open",
  "in_progress",
  "resolved",
  "accepted",
  "false_positive",
] as const;

export function stateLabel(state: string) {
  return (
    {
      open: "Open",
      in_progress: "In progress",
      resolved: "Resolved",
      accepted: "Risk accepted",
      false_positive: "False positive",
    }[state] ?? state
  );
}
