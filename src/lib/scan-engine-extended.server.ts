/**
 * Extended native plugin families — server only.
 *
 * dns       DNSSEC, CAA, dangling CNAME, nameserver hygiene (DNS-over-HTTPS)
 * mail      SPF / DMARC / MX anti-spoofing posture
 * cve_hunt  Targeted, non-exploitative CVE hunts (Log4Shell, Shellshock, Bash)
 * device    Embedded device, IoT and hypervisor console fingerprinting
 */

import {
  probe,
  normalizeTarget,
  type Plugin,
  type RawFinding,
  type ScanContext,
  type ProbeResult,
} from "./scan-engine.server";

interface DohAnswer {
  name: string;
  type: number;
  data: string;
}

async function dnsQuery(name: string, type: string): Promise<DohAnswer[]> {
  const res = await probe(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { headers: { accept: "application/dns-json" } },
    7000,
  );
  if (!res?.body) return [];
  try {
    return (JSON.parse(res.body) as { Answer?: DohAnswer[] }).Answer ?? [];
  } catch {
    return [];
  }
}

async function dnssecAuthenticated(name: string): Promise<boolean> {
  const res = await probe(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A&do=true`,
    { headers: { accept: "application/dns-json" } },
    7000,
  );
  if (!res?.body) return false;
  try {
    return Boolean((JSON.parse(res.body) as { AD?: boolean }).AD);
  } catch {
    return false;
  }
}

async function pooled<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  let cursor = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (cursor < items.length) {
        const idx = cursor++;
        out[idx] = await fn(items[idx]!);
      }
    }),
  );
  return out;
}

export const EXTENDED_PLUGINS: Plugin[] = [
  {
    id: "AEG-70000",
    family: "dns",
    name: "DNS security audit",
    run: async (ctx) => {
      const findings: RawFinding[] = [];
      const host = ctx.baseUrl.hostname;
      const apex = host.split(".").slice(-2).join(".");

      const [dnssec, caa, cname, ns] = await Promise.all([
        dnssecAuthenticated(apex),
        dnsQuery(apex, "CAA"),
        dnsQuery(host, "CNAME"),
        dnsQuery(apex, "NS"),
      ]);

      if (!dnssec) {
        findings.push({
          plugin_id: "AEG-70001",
          family: "dns",
          title: "DNSSEC validation not available for the zone",
          severity: 1,
          confidence: "high",
          cwe: "CWE-350",
          description:
            "The resolver could not authenticate answers for this zone (no AD flag). Without DNSSEC, DNS responses can be spoofed or cache-poisoned in transit.",
          solution: "Sign the zone with DNSSEC and publish DS records at the registrar.",
          evidence: `Authenticated Data flag absent for ${apex}`,
          attack_tactics: ["Collection"],
        });
      }

      if (caa.length === 0) {
        findings.push({
          plugin_id: "AEG-70002",
          family: "dns",
          title: "No CAA record published",
          severity: 1,
          confidence: "high",
          description:
            "Any certificate authority may issue certificates for this domain because no CAA record restricts issuance.",
          solution: "Publish a CAA record naming only approved certificate authorities.",
          evidence: `CAA lookup for ${apex} returned no records`,
        });
      }

      if (cname.length) {
        const targetName = cname[0]!.data.replace(/\.$/, "");
        const resolved = await dnsQuery(targetName, "A");
        if (!resolved.length) {
          findings.push({
            plugin_id: "AEG-70003",
            family: "dns",
            title: "Dangling CNAME — subdomain takeover risk",
            severity: 4,
            confidence: "medium",
            cwe: "CWE-350",
            description: `${host} is a CNAME to ${targetName}, which no longer resolves. An attacker who claims that name on the hosting provider can serve content on your hostname.`,
            solution: "Remove the CNAME record or reclaim the target resource.",
            evidence: `${host} CNAME ${targetName} -> no A record`,
            attack_tactics: ["Initial Access"],
          });
        }
      }

      if (ns.length === 1) {
        findings.push({
          plugin_id: "AEG-70004",
          family: "dns",
          title: "Single authoritative nameserver",
          severity: 1,
          confidence: "high",
          description:
            "Only one NS record is published, making DNS resolution a single point of failure.",
          solution: "Publish at least two authoritative nameservers on independent infrastructure.",
          evidence: ns.map((n) => n.data).join(", "),
        });
      }

      return findings;
    },
  },

  {
    id: "AEG-71000",
    family: "mail",
    name: "Email transport and anti-spoofing posture",
    run: async (ctx) => {
      const findings: RawFinding[] = [];
      const apex = ctx.baseUrl.hostname.split(".").slice(-2).join(".");
      const [txt, dmarc, mx] = await Promise.all([
        dnsQuery(apex, "TXT"),
        dnsQuery(`_dmarc.${apex}`, "TXT"),
        dnsQuery(apex, "MX"),
      ]);

      const spf = txt
        .map((r) => r.data.replace(/"/g, ""))
        .find((v) => v.toLowerCase().startsWith("v=spf1"));
      if (!spf) {
        findings.push({
          plugin_id: "AEG-71001",
          family: "mail",
          title: "No SPF record published",
          severity: 2,
          confidence: "high",
          cwe: "CWE-290",
          description:
            "Without SPF, any host on the internet can send mail claiming to come from this domain.",
          solution: "Publish an SPF record ending in -all that lists only authorised senders.",
          evidence: `TXT lookup for ${apex} contained no v=spf1 record`,
          attack_tactics: ["Initial Access"],
        });
      } else if (/[~+]all\s*$/.test(spf)) {
        findings.push({
          plugin_id: "AEG-71002",
          family: "mail",
          title: "Permissive SPF policy",
          severity: 1,
          confidence: "high",
          description:
            "The SPF record ends in ~all or +all, so spoofed mail is soft-failed or accepted outright.",
          solution: "Tighten the record to -all once every legitimate sender is enumerated.",
          evidence: spf,
        });
      }

      const dmarcRecord = dmarc
        .map((r) => r.data.replace(/"/g, ""))
        .find((v) => v.toLowerCase().startsWith("v=dmarc1"));
      if (!dmarcRecord) {
        findings.push({
          plugin_id: "AEG-71003",
          family: "mail",
          title: "No DMARC record published",
          severity: 2,
          confidence: "high",
          cwe: "CWE-290",
          description:
            "DMARC is absent, so receivers have no instruction for handling mail that fails SPF or DKIM.",
          solution:
            "Publish _dmarc TXT with p=quarantine and reporting, then progress to p=reject.",
          evidence: `_dmarc.${apex} returned no TXT record`,
        });
      } else if (/p=none/i.test(dmarcRecord)) {
        findings.push({
          plugin_id: "AEG-71004",
          family: "mail",
          title: "DMARC policy is monitor-only (p=none)",
          severity: 1,
          confidence: "high",
          description:
            "Failing messages are still delivered because the DMARC policy does not enforce.",
          solution: "Move to p=quarantine and then p=reject.",
          evidence: dmarcRecord,
        });
      }

      if (mx.length) {
        findings.push({
          plugin_id: "AEG-71005",
          family: "mail",
          title: "Mail exchangers inventoried",
          severity: 0,
          confidence: "high",
          description:
            "Mail servers accepting mail for this domain, recorded for attack-surface tracking.",
          solution:
            "Confirm each MX enforces STARTTLS and is not an open relay (agent-mode check).",
          evidence: mx.map((r) => r.data).join("\n"),
        });
      }

      return findings;
    },
  },

  {
    id: "AEG-72000",
    family: "cve_hunt",
    name: "Targeted CVE hunts (Log4Shell, Shellshock, Bash)",
    run: async (ctx) => {
      const findings: RawFinding[] = [];
      const base = ctx.baseUrl.origin;

      const java = ctx.tech.find((x) =>
        /tomcat|jetty|jboss|wildfly|spring|struts|java|coldfusion/i.test(x.name),
      );
      const marker = "${jndi:ldap://aegisscan.invalid/x}";
      const probed = await probe(base, { headers: { "x-api-version": marker, referer: marker } });
      const errorLeak = Boolean(
        probed?.body && /log4j|JndiLookup|LoggerContext|org\.apache\.logging/i.test(probed.body),
      );

      if (java || errorLeak) {
        findings.push({
          plugin_id: "AEG-72001",
          family: "cve_hunt",
          title: "Java logging stack reachable — Log4Shell exposure candidate",
          severity: errorLeak ? 4 : 2,
          confidence: errorLeak ? "medium" : "low",
          cwe: "CWE-917",
          cve_ids: ["CVE-2021-44228", "CVE-2021-45046"],
          description:
            "A Java application stack answers unauthenticated requests. Log4j 2.x before 2.17.1 evaluates JNDI lookups inside logged strings, allowing remote code execution. This check is non-exploitative — no external JNDI endpoint is ever contacted.",
          solution:
            "Upgrade Log4j to 2.17.1 or later, or set log4j2.formatMsgNoLookups=true and remove JndiLookup.class from the classpath.",
          evidence: [
            java ? `Java stack fingerprint: ${java.name} ${java.version ?? ""}`.trim() : null,
            errorLeak
              ? "Response referenced Log4j internals after a JNDI-shaped header was logged."
              : null,
          ]
            .filter(Boolean)
            .join("\n"),
          attack_tactics: ["Initial Access", "Execution"],
          refs: [
            { title: "CVE-2021-44228", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" },
          ],
        });
      }

      const cgiPaths = [
        "/cgi-bin/test.cgi",
        "/cgi-bin/status",
        "/cgi-bin/",
        "/cgi-sys/defaultwebpage.cgi",
      ];
      const payload = "() { :;}; echo aegis-shellshock";
      const results = await pooled(cgiPaths, 4, (p) =>
        probe(`${base}${p}`, { headers: { "user-agent": payload, cookie: payload } }, 7000),
      );
      results.forEach((res, i) => {
        if (!res) return;
        if (/aegis-shellshock/.test(res.body)) {
          findings.push({
            plugin_id: "AEG-72002",
            family: "cve_hunt",
            title: "Shellshock — Bash remote command execution through CGI",
            severity: 4,
            confidence: "high",
            cwe: "CWE-78",
            cve_ids: ["CVE-2014-6271", "CVE-2014-7169"],
            description:
              "The CGI handler executed a shell function definition supplied in an HTTP header, proving the underlying Bash is vulnerable to Shellshock and its variants.",
            solution: "Patch Bash to a fixed release and disable unused CGI handlers.",
            evidence: `${cgiPaths[i]} reflected the injected command output.`,
            attack_tactics: ["Execution"],
          });
        } else if (res.status < 400) {
          findings.push({
            plugin_id: "AEG-72003",
            family: "cve_hunt",
            title: "Legacy CGI handler reachable",
            severity: 1,
            confidence: "medium",
            description:
              "A cgi-bin style handler responded. CGI surfaces are the delivery path for the Bash CVE family and should not be exposed publicly.",
            solution: "Remove unused CGI scripts or restrict them behind authentication.",
            evidence: `${cgiPaths[i]} responded ${res.status}`,
            cve_ids: ["CVE-2014-6277", "CVE-2014-6278"],
          });
        }
      });

      return findings;
    },
  },

  {
    id: "AEG-73000",
    family: "device",
    name: "Embedded device, IoT and hypervisor console fingerprinting",
    run: async (ctx) => {
      const findings: RawFinding[] = [];
      const root = ctx.root;
      if (!root) return findings;

      const haystack = `${root.body.slice(0, 20000)}\n${JSON.stringify(root.headers)}`;
      const SIGNATURES: { name: string; kind: string; re: RegExp; severity: number }[] = [
        {
          name: "VMware ESXi / vSphere console",
          kind: "Hypervisor",
          re: /vmware\s*(esxi|vsphere)|\/ui\//i,
          severity: 3,
        },
        {
          name: "Microsoft Hyper-V management",
          kind: "Hypervisor",
          re: /hyper-?v manager|windows admin center/i,
          severity: 3,
        },
        {
          name: "Network printer web interface",
          kind: "Printer",
          re: /hp laserjet|jetdirect|printer status|brother [a-z]{2,}-/i,
          severity: 2,
        },
        {
          name: "IP camera web interface",
          kind: "Camera",
          re: /hikvision|dahua|axis communications|webcamxp|netsurveillance/i,
          severity: 3,
        },
        {
          name: "Consumer or SOHO router panel",
          kind: "Router",
          re: /mikrotik|routeros|openwrt|dd-wrt|tp-link|zyxel|draytek/i,
          severity: 3,
        },
        {
          name: "NAS management interface",
          kind: "Storage",
          re: /synology|diskstation|qnap|truenas/i,
          severity: 2,
        },
        {
          name: "Out-of-band management (iLO/iDRAC/IPMI)",
          kind: "BMC",
          re: /integrated lights-out|idrac|supermicro|ipmi/i,
          severity: 4,
        },
        {
          name: "Industrial controller web server",
          kind: "ICS",
          re: /simatic|siemens s7|rockwell|allen-bradley|modbus/i,
          severity: 4,
        },
      ];

      for (const sig of SIGNATURES) {
        if (!sig.re.test(haystack)) continue;
        findings.push({
          plugin_id: `AEG-73${String(SIGNATURES.indexOf(sig) + 1).padStart(3, "0")}`,
          family: "device",
          title: `${sig.kind} management interface exposed — ${sig.name}`,
          severity: sig.severity,
          confidence: "medium",
          cwe: "CWE-1188",
          description: `The target serves the web interface of a ${sig.kind.toLowerCase()} device (${sig.name}). Embedded management interfaces frequently ship default credentials and outdated firmware, and should never be reachable from untrusted networks.`,
          solution:
            "Move the management interface behind a VPN or management VLAN, change default credentials, and apply current firmware.",
          evidence: `Signature matched on the root response: /${sig.re.source}/`,
          attack_tactics: ["Initial Access", "Discovery"],
        });
      }

      const authHeader = root.headers["www-authenticate"];
      if (authHeader && /basic/i.test(authHeader)) {
        findings.push({
          plugin_id: "AEG-73900",
          family: "device",
          title: "HTTP Basic authentication prompt on management endpoint",
          severity: ctx.httpsWorks ? 2 : 3,
          confidence: "high",
          cwe: "CWE-522",
          description:
            "The endpoint challenges with HTTP Basic authentication, typical of embedded devices. Credentials are base64-encoded, not encrypted, and such devices commonly retain vendor defaults.",
          solution:
            "Require TLS, replace Basic auth with a modern scheme, and rotate any default credentials.",
          evidence: `WWW-Authenticate: ${authHeader}`,
          attack_tactics: ["Credential Access"],
        });
      }

      return findings;
    },
  },
];

/**
 * Executes extended security plugins (DNS hygiene, mail anti-spoofing, CVE hunts, device consoles)
 * against a target with per-plugin error handling.
 */
export async function runExtendedChecks(
  target: string | URL,
  rootProbe?: ProbeResult | null,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  try {
    const baseUrl = typeof target === "string" ? normalizeTarget(target) : target;
    const root = rootProbe !== undefined ? rootProbe : await probe(baseUrl.href);
    const httpsWorks = baseUrl.protocol === "https:" || (root?.status ?? 0) > 0;

    const ctx: ScanContext = {
      baseUrl,
      root: root ?? null,
      tech: [],
      ports: [],
      httpsWorks,
      httpOnly: baseUrl.protocol === "http:" && !httpsWorks,
    };

    for (const plugin of EXTENDED_PLUGINS) {
      try {
        const results = await plugin.run(ctx);
        if (Array.isArray(results)) {
          findings.push(...results);
        }
      } catch (err) {
        console.error(
          `[ExtendedScanEngine] Plugin ${plugin.id} (${plugin.name}) execution error:`,
          err,
        );
      }
    }
  } catch (err) {
    console.error("[ExtendedScanEngine] Fatal initialization error in runExtendedChecks:", err);
  }

  return findings;
}
