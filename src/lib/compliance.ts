/**
 * Compliance framework model.
 *
 * Controls are data, not code paths. Each control maps to observable evidence
 * already in the platform (findings + asset posture) and evaluates to
 * pass / fail / not_assessed. No control claims a check the platform cannot see.
 */

export type ControlStatus = "pass" | "fail" | "not_assessed";

export interface ComplianceEvidence {
  /** Open findings grouped by plugin family. */
  byFamily: Record<string, { total: number; maxSeverity: number; titles: string[] }>;
  /** Open findings grouped by plugin id prefix. */
  pluginIds: string[];
  totalOpen: number;
  highOrCritical: number;
  assets: number;
  internetFacing: number;
  scannedAssets: number;
  agentSourced: number;
}

export interface Control {
  id: string;
  title: string;
  requirement: string;
  remediation: string;
  /** Families whose findings cause this control to fail. */
  failsOn: string[];
  /** Minimum severity of a finding in those families needed to fail. */
  minSeverity?: number;
  /** When true the control needs agent data we may not have. */
  needsAgent?: boolean;
}

export interface Framework {
  key: string;
  name: string;
  description: string;
  controls: Control[];
}

const c = (
  id: string,
  title: string,
  requirement: string,
  remediation: string,
  failsOn: string[],
  opts: { minSeverity?: number; needsAgent?: boolean } = {},
): Control => ({ id, title, requirement, remediation, failsOn, ...opts });

export const FRAMEWORKS: Framework[] = [
  {
    key: "CIS",
    name: "CIS Benchmarks",
    description: "Center for Internet Security hardening controls mapped to observable evidence.",
    controls: [
      c(
        "CIS-1.1",
        "Inventory of authorised assets",
        "Maintain an accurate inventory of all assets in scope.",
        "Add every in-scope host to the asset inventory and keep last-seen current.",
        [],
      ),
      c(
        "CIS-4.1",
        "Secure configuration of network services",
        "Services must not expose default or debug interfaces.",
        "Remove debug endpoints and restrict admin panels.",
        ["exposure"],
        { minSeverity: 2 },
      ),
      c(
        "CIS-3.10",
        "Encrypt data in transit",
        "All sensitive data must be transmitted over strong TLS.",
        "Enforce HTTPS with HSTS and a valid certificate chain.",
        ["tls"],
        { minSeverity: 2 },
      ),
      c(
        "CIS-9.2",
        "Secure web browser and server settings",
        "Web servers must send hardening headers.",
        "Add CSP, X-Content-Type-Options, Referrer-Policy and frame protections.",
        ["headers"],
        { minSeverity: 1 },
      ),
      c(
        "CIS-7.1",
        "Continuous vulnerability management",
        "Run authenticated vulnerability scans regularly.",
        "Deploy a scan agent for credentialed coverage.",
        [],
        { needsAgent: true },
      ),
      c(
        "CIS-16.11",
        "Leverage vetted application security",
        "Web applications must be free of injection and XSS defects.",
        "Remediate reflected XSS and redirect defects.",
        ["webapp"],
        { minSeverity: 2 },
      ),
    ],
  },
  {
    key: "STIG",
    name: "DISA STIG",
    description: "U.S. Department of Defense Security Technical Implementation Guides.",
    controls: [
      c(
        "STIG-CAT-I-TLS",
        "Deprecated transport must be disabled",
        "Only TLS 1.2+ with approved ciphers is permitted.",
        "Disable legacy protocols and weak cipher suites.",
        ["tls"],
        { minSeverity: 3 },
      ),
      c(
        "STIG-CAT-I-EXP",
        "No unauthorised information disclosure",
        "Configuration and source files must not be reachable.",
        "Block /.git, /.env and backup artefacts at the edge.",
        ["exposure"],
        { minSeverity: 3 },
      ),
      c(
        "STIG-CAT-II-HDR",
        "Application must set protective headers",
        "Responses must include DoD-required security headers.",
        "Configure the full header set at the reverse proxy.",
        ["headers"],
        { minSeverity: 1 },
      ),
      c(
        "STIG-CAT-II-API",
        "APIs must authenticate every request",
        "No API endpoint may serve data unauthenticated.",
        "Require authentication on all documented endpoints.",
        ["api"],
        { minSeverity: 2 },
      ),
      c(
        "STIG-CAT-I-OS",
        "Operating systems must be STIG-hardened",
        "Host configuration must match the OS STIG.",
        "Run a credentialed OS audit through the scan agent.",
        [],
        { needsAgent: true },
      ),
    ],
  },
  {
    key: "PCI",
    name: "PCI DSS",
    description: "Payment card industry data security standard technical requirements.",
    controls: [
      c(
        "PCI-2.2",
        "Vendor defaults must be changed",
        "No default credentials or default pages may remain.",
        "Change every vendor default and remove default content.",
        ["device", "exposure"],
        { minSeverity: 2 },
      ),
      c(
        "PCI-4.1",
        "Strong cryptography in transit",
        "Cardholder data must traverse strong TLS only.",
        "Enforce HTTPS everywhere with valid certificates and HSTS.",
        ["tls"],
        { minSeverity: 2 },
      ),
      c(
        "PCI-6.5",
        "Address common coding vulnerabilities",
        "Applications must resist injection, XSS and redirect abuse.",
        "Fix all web application findings before release.",
        ["webapp"],
        { minSeverity: 2 },
      ),
      c(
        "PCI-6.2",
        "Install applicable security patches",
        "Known-vulnerable components must be patched.",
        "Upgrade components with matched CVEs.",
        ["cve", "cve_hunt"],
        { minSeverity: 3 },
      ),
      c(
        "PCI-11.2",
        "Run internal and external vulnerability scans",
        "Quarterly internal and external scans are required.",
        "Schedule recurring scans; add an agent for internal coverage.",
        [],
        { needsAgent: true },
      ),
      c(
        "PCI-1.3",
        "Restrict inbound traffic to what is required",
        "Only required services may be internet-facing.",
        "Remove or firewall unnecessary internet-facing services.",
        ["exposure"],
        { minSeverity: 3 },
      ),
    ],
  },
  {
    key: "HIPAA",
    name: "HIPAA Security Rule",
    description: "Technical safeguards for electronic protected health information.",
    controls: [
      c(
        "HIPAA-164.312(e)",
        "Transmission security",
        "ePHI must be encrypted in transit.",
        "Enforce TLS on every endpoint handling ePHI.",
        ["tls"],
        { minSeverity: 2 },
      ),
      c(
        "HIPAA-164.312(a)",
        "Access control",
        "Only authorised users may reach ePHI.",
        "Require authentication on every data endpoint.",
        ["api", "webapp"],
        { minSeverity: 3 },
      ),
      c(
        "HIPAA-164.312(b)",
        "Audit controls",
        "Systems must record access to ePHI.",
        "Enable and retain application and infrastructure audit logs.",
        [],
      ),
      c(
        "HIPAA-164.308(a)(1)",
        "Risk analysis",
        "Conduct ongoing technical risk assessment.",
        "Maintain recurring scans and review findings monthly.",
        [],
      ),
      c(
        "HIPAA-164.310(d)",
        "Device and media controls",
        "Endpoint devices must be inventoried and hardened.",
        "Collect endpoint posture with the scan agent.",
        [],
        { needsAgent: true },
      ),
    ],
  },
  {
    key: "ISO27001",
    name: "ISO/IEC 27001 Annex A",
    description:
      "Technical controls supporting an ISO 27001 information security management system.",
    controls: [
      c(
        "A.8.8",
        "Management of technical vulnerabilities",
        "Vulnerabilities must be identified and remediated on schedule.",
        "Close overdue findings and track SLA compliance.",
        ["cve", "cve_hunt"],
        { minSeverity: 3 },
      ),
      c(
        "A.8.9",
        "Configuration management",
        "Systems must run approved, hardened configuration.",
        "Remediate misconfiguration findings.",
        ["headers", "exposure"],
        { minSeverity: 2 },
      ),
      c(
        "A.8.24",
        "Use of cryptography",
        "Cryptographic controls must follow policy.",
        "Enforce modern TLS and valid certificates.",
        ["tls"],
        { minSeverity: 2 },
      ),
      c(
        "A.5.7",
        "Threat intelligence",
        "Threat intelligence must inform risk decisions.",
        "Keep KEV/EPSS feeds synced and priorities recomputed.",
        [],
      ),
      c(
        "A.8.16",
        "Monitoring activities",
        "Networks and systems must be monitored.",
        "Enable continuous scanning of critical assets.",
        [],
      ),
    ],
  },
  {
    key: "GDPR",
    name: "GDPR Article 32",
    description: "Security of processing for personal data.",
    controls: [
      c(
        "GDPR-32.1(a)",
        "Pseudonymisation and encryption",
        "Personal data must be encrypted in transit and at rest.",
        "Enforce HTTPS and encrypt stored personal data.",
        ["tls"],
        { minSeverity: 2 },
      ),
      c(
        "GDPR-32.1(b)",
        "Confidentiality of processing systems",
        "No unauthorised exposure of personal data.",
        "Remove publicly reachable data files and directory listings.",
        ["exposure"],
        { minSeverity: 2 },
      ),
      c(
        "GDPR-32.1(d)",
        "Regular testing of security measures",
        "Security measures must be regularly tested.",
        "Maintain a recurring scan schedule with recorded results.",
        [],
      ),
      c(
        "GDPR-25",
        "Data protection by design",
        "Applications must limit data exposure by default.",
        "Fix verbose errors and over-sharing API responses.",
        ["api", "webapp"],
        { minSeverity: 2 },
      ),
    ],
  },
  {
    key: "NIST",
    name: "NIST CSF / 800-53",
    description: "Identify, Protect, Detect, Respond and Recover technical controls.",
    controls: [
      c(
        "ID.AM-1",
        "Physical and software assets inventoried",
        "Maintain a complete asset inventory.",
        "Register every asset and keep last-seen current.",
        [],
      ),
      c(
        "PR.DS-2",
        "Data in transit is protected",
        "Protect data during transmission.",
        "Enforce TLS with valid certificates.",
        ["tls"],
        { minSeverity: 2 },
      ),
      c(
        "PR.IP-1",
        "Baseline configuration maintained",
        "Systems must match a hardened baseline.",
        "Remediate configuration and header findings.",
        ["headers", "exposure"],
        { minSeverity: 2 },
      ),
      c(
        "DE.CM-8",
        "Vulnerability scans performed",
        "Vulnerability scans must run regularly.",
        "Schedule recurring scans across all assets.",
        [],
      ),
      c(
        "RS.MI-3",
        "Newly identified vulnerabilities mitigated",
        "Newly identified vulnerabilities are mitigated or documented.",
        "Triage every open critical/high finding within SLA.",
        ["cve", "cve_hunt"],
        { minSeverity: 4 },
      ),
      c(
        "PR.AC-4",
        "Access permissions managed",
        "Least privilege must be enforced.",
        "Audit identity and access configuration via the agent.",
        [],
        { needsAgent: true },
      ),
    ],
  },
  {
    key: "CUSTOM",
    name: "Custom Policy",
    description: "Organisation-specific rules encoded as pass/fail controls.",
    controls: [
      c(
        "ORG-1",
        "No open critical findings",
        "The environment must carry zero open critical vulnerabilities.",
        "Remediate or formally accept every critical finding.",
        ["*"],
        { minSeverity: 4 },
      ),
      c(
        "ORG-2",
        "All internet-facing assets scanned",
        "Every internet-facing asset must have a completed scan.",
        "Launch a scan for each unscanned internet-facing asset.",
        [],
      ),
      c(
        "ORG-3",
        "Agent coverage established",
        "At least one asset must report through a scan agent.",
        "Deploy the AegisScan agent and register an ingest key.",
        [],
        { needsAgent: true },
      ),
    ],
  },
];

export function evaluateControl(
  control: Control,
  ev: ComplianceEvidence,
): { status: ControlStatus; detail: string } {
  if (control.needsAgent && ev.agentSourced === 0) {
    return {
      status: "not_assessed",
      detail: "Requires scan-agent data; no agent results ingested yet.",
    };
  }

  if (control.id === "ORG-2") {
    if (ev.internetFacing === 0)
      return { status: "not_assessed", detail: "No internet-facing assets registered." };
    return ev.scannedAssets >= ev.internetFacing
      ? {
          status: "pass",
          detail: `${ev.scannedAssets}/${ev.internetFacing} internet-facing assets scanned.`,
        }
      : {
          status: "fail",
          detail: `${ev.internetFacing - ev.scannedAssets} internet-facing assets never scanned.`,
        };
  }

  if (control.failsOn.length === 0) {
    if (ev.scannedAssets === 0)
      return { status: "not_assessed", detail: "No completed scans yet." };
    return { status: "pass", detail: "Evidence collected from completed scans." };
  }

  const min = control.minSeverity ?? 1;
  const families = control.failsOn.includes("*") ? Object.keys(ev.byFamily) : control.failsOn;
  const hits = families
    .map((f) => ev.byFamily[f])
    .filter((x): x is NonNullable<typeof x> => Boolean(x) && x!.maxSeverity >= min);

  if (ev.scannedAssets === 0) return { status: "not_assessed", detail: "No completed scans yet." };
  if (hits.length === 0)
    return { status: "pass", detail: "No qualifying open findings in the mapped families." };

  const count = hits.reduce((n, h) => n + h.total, 0);
  const example = hits[0]!.titles[0] ?? "";
  return {
    status: "fail",
    detail: `${count} open finding(s)${example ? ` — e.g. ${example}` : ""}.`,
  };
}

export function evaluateFramework(framework: Framework, ev: ComplianceEvidence) {
  const controls = framework.controls.map((control) => ({
    control,
    ...evaluateControl(control, ev),
  }));
  const pass = controls.filter((x) => x.status === "pass").length;
  const fail = controls.filter((x) => x.status === "fail").length;
  const assessed = pass + fail;
  return {
    key: framework.key,
    name: framework.name,
    description: framework.description,
    controls,
    pass,
    fail,
    notAssessed: controls.length - assessed,
    score: assessed ? Math.round((pass / assessed) * 100) : 0,
  };
}
