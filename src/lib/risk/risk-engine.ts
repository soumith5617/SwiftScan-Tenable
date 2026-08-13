/**
 * AegisScan Enterprise Risk Calculation Engine
 *
 * Implements standard CVSS v3.1/v4.0 scoring adjustments, EPSS probability multiplier,
 * CISA KEV (Known Exploited Vulnerability) urgency boost, Asset Criticality weighting,
 * Business Exposure multipliers, and Custom Risk Overrides.
 */

import {
  AssetCriticality,
  RiskCalculationInput,
  RiskCalculationResult,
  SeverityLevel,
} from "../types/enterprise";

export const CRITICALITY_WEIGHTS: Record<AssetCriticality, number> = {
  low: 0.8,
  medium: 1.0,
  high: 1.3,
  critical: 1.6,
};

export class RiskEngine {
  /**
   * Calculates adjusted priority score (0.0 to 100.0) and effective severity level.
   */
  public static calculateFindingRisk(input: RiskCalculationInput): RiskCalculationResult {
    const {
      cvssScore,
      epssScore,
      isKev,
      assetCriticality,
      isInternetFacing,
      customSeverityOverride,
    } = input;
    const safeEpss = epssScore ?? 0.01;

    // 1. Base score derived from CVSS (0 - 10)
    const baseCvss = Math.min(10.0, Math.max(0.0, cvssScore));

    // 2. Criticality Weight
    const criticalityWeight = CRITICALITY_WEIGHTS[assetCriticality] ?? 1.0;

    // 3. Exposure Weight (Internet-facing assets carry higher inherent risk)
    const exposureWeight = isInternetFacing ? 1.25 : 1.0;

    // 4. KEV Boost (Active exploit in wild boosts priority significantly)
    const kevBoost = isKev ? 2.5 : 1.0;

    // 5. EPSS Multiplier (Probability of exploitation in next 30 days: 0.0 to 1.0)
    const epssMultiplier = 1.0 + Math.min(1.0, Math.max(0, safeEpss)) * 1.5;

    // Calculate raw adjusted priority score (scaled to 0 - 100)
    let adjustedPriority =
      baseCvss * 7.5 * criticalityWeight * exposureWeight * epssMultiplier * (isKev ? 1.3 : 1.0);

    // Cap adjusted priority to range [0, 100]
    adjustedPriority = Math.min(100.0, Math.max(0.0, Number(adjustedPriority.toFixed(2))));

    // 6. Calculate Effective Severity
    let calculatedSeverity: SeverityLevel = 0;
    if (adjustedPriority >= 85 || baseCvss >= 9.0) {
      calculatedSeverity = 4; // Critical
    } else if (adjustedPriority >= 65 || baseCvss >= 7.0) {
      calculatedSeverity = 3; // High
    } else if (adjustedPriority >= 40 || baseCvss >= 4.0) {
      calculatedSeverity = 2; // Medium
    } else if (adjustedPriority >= 15 || baseCvss >= 0.1) {
      calculatedSeverity = 1; // Low
    } else {
      calculatedSeverity = 0; // Info
    }

    // Apply custom severity override if present
    const effectiveSeverity =
      customSeverityOverride != null ? customSeverityOverride : calculatedSeverity;

    return {
      baseCvss,
      effectiveSeverity,
      adjustedPriority,
      riskFactors: {
        epssMultiplier,
        kevBoost,
        criticalityWeight,
        exposureWeight,
      },
    };
  }

  /**
   * Calculates overall risk score for an asset (0 - 100) based on open findings.
   */
  public static calculateAssetRiskScore(
    criticality: AssetCriticality,
    isInternetFacing: boolean,
    findings: Array<{ severity: SeverityLevel; priority: number; kev: boolean }>,
  ): number {
    if (findings.length === 0) return 0;

    const criticalityWeight = CRITICALITY_WEIGHTS[criticality];
    const exposureWeight = isInternetFacing ? 1.2 : 1.0;

    // Sum weighted findings
    let totalRisk = 0;
    for (const f of findings) {
      const severityMultiplier =
        f.severity === 4
          ? 25
          : f.severity === 3
            ? 15
            : f.severity === 2
              ? 8
              : f.severity === 1
                ? 2
                : 0;
      const kevFactor = f.kev ? 1.4 : 1.0;
      totalRisk += severityMultiplier * kevFactor;
    }

    // Apply diminishing returns formula so score stays normalized between 0 - 100
    const rawScore = (1 - Math.exp(-totalRisk / 60)) * 100;
    const finalScore = Math.min(100, Math.max(0, rawScore * criticalityWeight * exposureWeight));

    return Number(finalScore.toFixed(1));
  }

  /**
   * SLA days by severity level
   */
  public static readonly SLA_DAYS: Record<SeverityLevel, number> = {
    4: 14, // Critical: 14 days
    3: 30, // High: 30 days
    2: 60, // Medium: 60 days
    1: 90, // Low: 90 days
    0: 180, // Info: 180 days
  };

  /**
   * Calculate due date for a finding based on severity and KEV presence
   */
  public static calculateDueDate(
    severity: SeverityLevel,
    isKev = false,
    createdDate = new Date(),
  ): string {
    const days = isKev
      ? Math.min(14, this.SLA_DAYS[severity] ?? 30)
      : (this.SLA_DAYS[severity] ?? 30);
    const due = new Date(createdDate.getTime() + days * 86_400_000);
    return due.toISOString();
  }

  /**
   * Evaluate SLA compliance rate across findings
   */
  public static calculateSlaCompliance(
    findings: Array<{ severity: number; state: string; due_at: string | null; created_at: string }>,
  ): {
    complianceRate: number;
    overdueCount: number;
    onTrackCount: number;
    resolvedWithinSlaCount: number;
  } {
    const now = Date.now();
    let overdueCount = 0;
    let onTrackCount = 0;
    let resolvedWithinSlaCount = 0;
    let totalEvaluated = 0;

    for (const f of findings) {
      if (!f.due_at) continue;
      totalEvaluated++;
      const dueTime = new Date(f.due_at).getTime();

      if (f.state === "open") {
        if (now > dueTime) {
          overdueCount++;
        } else {
          onTrackCount++;
        }
      } else if (f.state === "fixed") {
        resolvedWithinSlaCount++;
      }
    }

    const complianceRate =
      totalEvaluated > 0
        ? Number((((totalEvaluated - overdueCount) / totalEvaluated) * 100).toFixed(1))
        : 100;

    return {
      complianceRate,
      overdueCount,
      onTrackCount,
      resolvedWithinSlaCount,
    };
  }

  /**
   * Utility to map numerical severity to label
   */
  public static severityToLabel(
    severity: SeverityLevel,
  ): "Critical" | "High" | "Medium" | "Low" | "Info" {
    switch (severity) {
      case 4:
        return "Critical";
      case 3:
        return "High";
      case 2:
        return "Medium";
      case 1:
        return "Low";
      default:
        return "Info";
    }
  }

  /**
   * Severity color badge styling utility
   */
  public static severityToBadgeStyle(severity: SeverityLevel): {
    bg: string;
    text: string;
    border: string;
  } {
    switch (severity) {
      case 4:
        return {
          bg: "bg-red-500/15",
          text: "text-red-500 font-semibold",
          border: "border-red-500/30",
        };
      case 3:
        return {
          bg: "bg-orange-500/15",
          text: "text-orange-500 font-semibold",
          border: "border-orange-500/30",
        };
      case 2:
        return {
          bg: "bg-amber-500/15",
          text: "text-amber-500 font-semibold",
          border: "border-amber-500/30",
        };
      case 1:
        return {
          bg: "bg-blue-500/15",
          text: "text-blue-500 font-medium",
          border: "border-blue-500/30",
        };
      default:
        return {
          bg: "bg-slate-500/15",
          text: "text-slate-400 font-medium",
          border: "border-slate-500/30",
        };
    }
  }
}
