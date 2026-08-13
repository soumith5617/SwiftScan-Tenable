/**
 * Evidence-based verification model ("zero false positive" gating).
 *
 * A finding is only reported at full confidence when independent methods agree.
 * Each detection carries the list of methods that produced it; the confidence
 * label is derived from that list rather than asserted by the plugin.
 */
export const VERIFICATION_METHODS = [
  {
    id: "banner",
    label: "Service banner",
    weight: 1,
    note: "Server/product banner or response header",
  },
  {
    id: "version",
    label: "Version fingerprint",
    weight: 2,
    note: "Parsed product version matched to an advisory range",
  },
  {
    id: "behavior",
    label: "Behavioural probe",
    weight: 3,
    note: "Non-destructive request whose response only a vulnerable build returns",
  },
  {
    id: "config",
    label: "Configuration read",
    weight: 2,
    note: "Observed configuration (headers, TLS parameters, DNS records)",
  },
  {
    id: "package",
    label: "Package manager",
    weight: 3,
    note: "Installed package list from a credentialed check",
  },
  {
    id: "patch",
    label: "Patch level",
    weight: 3,
    note: "OS/product patch level from a credentialed check",
  },
  {
    id: "registry",
    label: "Registry key",
    weight: 3,
    note: "Windows registry value from a credentialed check",
  },
  {
    id: "authenticated",
    label: "Authenticated check",
    weight: 4,
    note: "Verified with supplied credentials on the host",
  },
] as const;

export type VerificationMethod = (typeof VERIFICATION_METHODS)[number]["id"];

const WEIGHTS = new Map(VERIFICATION_METHODS.map((m) => [m.id, m.weight] as const));

export function verificationLabel(id: string): string {
  return VERIFICATION_METHODS.find((m) => m.id === id)?.label ?? id;
}

/** Total evidence weight across the distinct methods that produced a finding. */
export function evidenceWeight(methods: readonly string[]): number {
  return [...new Set(methods)].reduce(
    (sum, m) => sum + (WEIGHTS.get(m as VerificationMethod) ?? 0),
    0,
  );
}

/**
 * Derive the reported confidence from the evidence actually collected.
 * High severity claims demand more corroboration than informational ones.
 */
export function deriveConfidence(
  methods: readonly string[],
  severity: number,
): "high" | "medium" | "low" {
  const weight = evidenceWeight(methods);
  const distinct = new Set(methods).size;
  const bar = severity >= 3 ? 5 : severity >= 2 ? 3 : 2;
  if (weight >= bar && distinct >= 2) return "high";
  if (weight >= Math.max(2, bar - 2)) return "medium";
  return "low";
}

/**
 * Findings that clear the reporting bar. Low-confidence high-severity claims are
 * kept but downgraded, so nothing is silently dropped while the headline numbers
 * stay defensible.
 */
export function applyVerificationPolicy<T extends { severity: number; confidence?: string }>(
  finding: T,
  methods: readonly string[],
): T & { verifications: string[]; confidence: string; unverified: boolean } {
  const list = [...new Set(methods)];
  const confidence = deriveConfidence(list, finding.severity);
  const unverified = confidence === "low" && finding.severity >= 3;
  return {
    ...finding,
    verifications: list,
    confidence,
    // A critical claim backed by a single weak signal is reported one level down
    // with the gap made explicit in the evidence trail.
    severity: unverified ? Math.max(2, finding.severity - 1) : finding.severity,
    unverified,
  };
}

/** Map a plugin family to the verification methods its checks can produce. */
export function methodsForFamily(family: string, hasVersion: boolean): VerificationMethod[] {
  const base: VerificationMethod[] = [];
  switch (family) {
    case "tls":
    case "headers":
    case "cookies":
    case "cors":
      base.push("config");
      break;
    case "dns":
    case "mail":
      base.push("config");
      break;
    case "cve_hunt":
      base.push("behavior");
      break;
    case "device":
    case "fingerprint":
      base.push("banner");
      break;
    case "cve":
      base.push("version");
      break;
    default:
      base.push("banner");
  }
  if (hasVersion && !base.includes("version")) base.push("version");
  return base;
}
