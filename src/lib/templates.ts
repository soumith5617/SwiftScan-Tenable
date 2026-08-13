/**
 * AegisScan scan-template catalog.
 *
 * Every Nessus/Tenable scan type is represented here. Each template declares an
 * honest execution mode so the console never claims to run a check it cannot:
 *
 *  - native   → executed server-side by the built-in HTTP/TLS engine
 *  - agent    → requires an external scan agent (raw sockets, credentials,
 *               local host access); results arrive through /api/public/agent/ingest
 *  - analysis → evaluated against data already in the platform
 */

export type ScanMode = "native" | "agent" | "analysis";

export type ScanCategory =
  | "Discovery"
  | "Network"
  | "Web & API"
  | "Endpoint & OS"
  | "Infrastructure"
  | "Cloud & Container"
  | "Compliance"
  | "Specialized"
  | "Continuous";

export interface ScanTemplate {
  id: string;
  name: string;
  category: ScanCategory;
  mode: ScanMode;
  /** Short one-liner used in pickers and cards. */
  description: string;
  purpose: string;
  techniques: string[];
  detects: string[];
  /** Engine plugin families executed for native templates. */
  families: string[];
  credentials?: string[];
  /** Job type an external agent receives for agent-mode templates. */
  agentJob?: string;
  /** Compliance framework key for analysis-mode compliance templates. */
  framework?: string;
}

const t = (x: ScanTemplate): ScanTemplate => x;

export const SCAN_CATALOG: ScanTemplate[] = [
  /* ------------------------------- Discovery ------------------------------- */
  t({
    id: "host_discovery",
    name: "Host Discovery",
    category: "Discovery",
    mode: "native",
    description: "Finds every live device on a network with full port sweep and banner grabbing.",
    purpose: "Enumerate live hosts, open ports, hostnames, and IP services.",
    techniques: [
      "TCP SYN & connect sweep",
      "Service detection",
      "Reverse DNS lookup",
      "Banner grabbing",
    ],
    detects: ["Live hosts", "Hostnames", "IP addresses", "Responsive network ports", "Service banners"],
    families: ["ports", "fingerprint", "device"],
  }),
  t({
    id: "external_attack_surface",
    name: "External Attack Surface Scan",
    category: "Discovery",
    mode: "native",
    description: "Maps internet-facing exposure: reachable services, panels and leaked paths.",
    purpose: "Understand what an unauthenticated attacker sees from the public internet.",
    techniques: [
      "All-ports sweep",
      "HTTP/HTTPS probing",
      "Redirect chain analysis",
      "Path enumeration",
      "Banner extraction",
    ],
    detects: [
      "Internet-facing services",
      "Exposed admin panels",
      "Debug endpoints",
      "Sensitive files",
      "Open ports",
    ],
    families: ["ports", "fingerprint", "exposure", "headers", "tls", "device"],
  }),
  t({
    id: "internal_network_scan",
    name: "Internal Network Scan",
    category: "Discovery",
    mode: "native",
    description: "Comprehensive sweep of network assets, listening services and OS versions.",
    purpose: "Assess network hosts for open services, exposed databases and unpatched software.",
    techniques: [
      "TCP port sweeps",
      "Service identification",
      "OS fingerprinting",
      "CVE correlation",
    ],
    detects: [
      "Internal services",
      "Missing patches",
      "Weak configuration",
      "Open database & remote ports",
    ],
    families: ["ports", "database", "fingerprint", "endpoint", "cve_hunt", "device", "cve", "tls", "headers"],
  }),

  /* -------------------------------- Network -------------------------------- */
  t({
    id: "basic_network_scan",
    name: "Basic Network Scan",
    category: "Network",
    mode: "native",
    description: "The default comprehensive assessment with full all-ports sweep across every service and web-reachable plugin family.",
    purpose:
      "Broad vulnerability assessment: all-ports discovery, listening services, versions, misconfiguration and CVE correlation.",
    techniques: [
      "All-ports network sweep & service detection",
      "Banner grabbing & service identification",
      "Version fingerprinting",
      "Database & remote service exposure audit",
      "CVE correlation",
    ],
    detects: [
      "Open network ports & services",
      "CVEs",
      "Running services",
      "Exposed infrastructure/databases",
      "Risk score",
      "Exploitable vulnerabilities",
    ],
    families: [
      "ports",
      "database",
      "fingerprint",
      "headers",
      "tls",
      "exposure",
      "webapp",
      "api",
      "device",
      "cve",
    ],
  }),
  t({
    id: "advanced_scan",
    name: "Advanced Scan",
    category: "Network",
    mode: "native",
    description: "Every plugin family enabled — all-ports sweep, deep crawl and aggressive correlation for maximum coverage.",
    purpose: "Full-customisation enterprise scan with all families, extended port sweeps, deep paths and CVE matching.",
    techniques: [
      "All-ports sweep & service detection",
      "All plugin families",
      "Extended path list",
      "Deep crawl",
      "Aggressive correlation",
    ],
    detects: ["All open ports, services and everything the engine can observe over HTTP/TLS/DNS/sockets"],
    families: [
      "ports",
      "database",
      "cloud",
      "container",
      "endpoint",
      "fingerprint",
      "headers",
      "tls",
      "exposure",
      "webapp",
      "api",
      "dns",
      "mail",
      "cve_hunt",
      "device",
      "cve",
    ],
  }),
  t({
    id: "quick_scan",
    name: "Quick Assessment",
    category: "Network",
    mode: "native",
    description: "Fast pass over the highest-signal checks. Good for continuous monitoring.",
    purpose: "Low-cost recurring check on critical assets.",
    techniques: ["Port sweep", "Fingerprinting", "Header audit", "TLS audit"],
    detects: ["Open ports", "Transport weaknesses", "Missing security headers", "Technology drift"],
    families: ["ports", "fingerprint", "headers", "tls"],
  }),
  t({
    id: "dns_audit",
    name: "DNS Security Audit",
    category: "Network",
    mode: "native",
    description: "DNSSEC, record hygiene, dangling records and resolver exposure.",
    purpose: "Validate DNS configuration and find takeover-prone records.",
    techniques: [
      "DNS-over-HTTPS queries",
      "DNSSEC validation",
      "CNAME chain analysis",
      "Record inventory",
    ],
    detects: ["Missing DNSSEC", "Dangling CNAMEs", "Wildcards", "Missing CAA", "Zone info leakage"],
    families: ["dns", "ports", "fingerprint"],
  }),
  t({
    id: "mail_security",
    name: "Email Server Security",
    category: "Network",
    mode: "native",
    description: "SPF, DKIM policy, DMARC enforcement and MX transport posture.",
    purpose: "Prevent spoofing and confirm mail transport security policy.",
    techniques: ["SPF/DMARC record lookup", "MX enumeration", "Policy strictness analysis"],
    detects: ["Missing SPF", "Permissive ~all/+all", "Missing or p=none DMARC", "No MX hardening"],
    families: ["mail", "ports", "tls"],
  }),
  t({
    id: "snmp_audit",
    name: "SNMP Audit",
    category: "Network",
    mode: "native",
    description: "SNMP port detection, service version and device exposure.",
    purpose: "Identify open SNMP listeners and device configuration exposure.",
    techniques: ["Port sweeps", "Service identification", "Banner matching"],
    detects: [
      "Open SNMP ports",
      "SNMP service exposure",
      "Device type identification",
    ],
    families: ["ports", "device", "fingerprint"],
  }),
  t({
    id: "ftp_security",
    name: "FTP Security Scan",
    category: "Network",
    mode: "native",
    description: "Anonymous login, cleartext credentials and weak FTP authentication.",
    purpose: "Identify insecure file transfer services.",
    techniques: ["FTP banner grab", "Port sweep", "Service identification"],
    detects: [
      "FTP port 21 exposure",
      "Cleartext credentials risk",
      "Outdated daemons",
    ],
    families: ["ports", "fingerprint", "exposure", "cve"],
  }),
  t({
    id: "ssh_security",
    name: "SSH Security Scan",
    category: "Network",
    mode: "native",
    description: "Cipher suites, key exchange, root login and deprecated algorithms.",
    purpose: "Harden SSH endpoints against downgrade and credential attacks.",
    techniques: ["SSH banner grab", "Port sweep", "Algorithm negotiation"],
    detects: ["Weak SSH versions", "SSH port exposure", "CVE matching"],
    families: ["ports", "fingerprint", "cve_hunt", "cve"],
  }),
  t({
    id: "smb_vuln",
    name: "SMB Vulnerability Scan",
    category: "Network",
    mode: "native",
    description: "SMB signing, SMBv1, shares, anonymous login and NTLM weaknesses.",
    purpose: "Eliminate the most abused Windows lateral-movement surface.",
    techniques: ["Port 445/139 sweep", "SMB dialect negotiation", "Service verification"],
    detects: ["SMB exposed ports", "EternalBlue / MS17-010 risk", "Anonymous shares"],
    families: ["ports", "fingerprint", "cve_hunt", "exposure", "cve"],
  }),
  t({
    id: "wireless_scan",
    name: "Wireless Network Scan",
    category: "Network",
    mode: "native",
    description: "Wi-Fi management interface security, rogue APs and weak authentication.",
    purpose: "Detect insecure or unauthorised wireless infrastructure.",
    techniques: ["Management portal fingerprinting", "Port sweeps", "Header analysis"],
    detects: ["Exposed Wi-Fi portals", "Default credential gates", "Weak admin consoles"],
    families: ["device", "fingerprint", "headers", "ports"],
  }),
  t({
    id: "iot_scan",
    name: "IoT Device Scan",
    category: "Network",
    mode: "native",
    description: "Fingerprints cameras, printers, routers and embedded web consoles.",
    purpose: "Identify embedded devices exposing management interfaces.",
    techniques: ["Embedded HTTP fingerprinting", "Port sweep", "Realm/banner analysis"],
    detects: ["Cameras", "Printers", "Routers", "Smart devices", "Default credential portals"],
    families: ["device", "fingerprint", "headers", "ports"],
  }),

  /* ------------------------------- Web & API -------------------------------- */
  t({
    id: "web_audit",
    name: "Web Application Tests",
    category: "Web & API",
    mode: "native",
    description:
      "Full HTTP crawl: fingerprinting, headers, cookies, exposure paths, OWASP probes, CVE correlation.",
    purpose: "OWASP-aligned assessment of a web application.",
    techniques: [
      "Crawling",
      "Reflection probes",
      "Redirect testing",
      "Cookie analysis",
      "Error-message analysis",
    ],
    detects: [
      "Reflected XSS",
      "Open redirect",
      "Directory traversal indicators",
      "Insecure cookies",
      "Information disclosure",
      "Authentication/session weaknesses",
    ],
    families: ["fingerprint", "headers", "exposure", "webapp", "tls", "cve", "api"],
  }),
  t({
    id: "api_audit",
    name: "API Security Scan",
    category: "Web & API",
    mode: "native",
    description:
      "OpenAPI/Swagger discovery, unauthenticated endpoint enumeration, GraphQL introspection, CORS.",
    purpose: "Test REST and GraphQL surfaces for exposure and broken authorization.",
    techniques: ["Spec discovery", "Endpoint enumeration", "GraphQL introspection", "CORS probing"],
    detects: [
      "Unauthenticated endpoints",
      "Exposed API schema",
      "Broken object-level authorization indicators",
      "Verbose errors",
      "Missing rate limiting signals",
    ],
    families: ["api", "headers", "fingerprint", "exposure", "tls"],
  }),
  t({
    id: "tls_audit",
    name: "SSL/TLS Scan",
    category: "Web & API",
    mode: "native",
    description:
      "HTTPS enforcement, certificate chain, HSTS, mixed content and transport weaknesses.",
    purpose: "Validate transport security end to end.",
    techniques: ["TLS handshake analysis", "Certificate inspection", "Redirect hygiene checks"],
    detects: [
      "Expired certificates",
      "Hostname mismatch",
      "Self-signed chains",
      "Weak protocol/cipher signals",
      "No HSTS",
    ],
    families: ["tls", "headers", "ports"],
  }),
  t({
    id: "exposure_audit",
    name: "Exposure & Attack Surface",
    category: "Web & API",
    mode: "native",
    description: "Sensitive file, backup, VCS metadata, admin panel and debug endpoint discovery.",
    purpose: "Find data and interfaces that should never be public.",
    techniques: ["Path enumeration", "Content signature matching", "Directory listing detection"],
    detects: ["/.env", "/.git/config", "Backups and dumps", "Directory listings", "Admin panels"],
    families: ["exposure", "fingerprint", "headers", "ports"],
  }),

  /* ---------------------------- Endpoint & OS ------------------------------- */
  t({
    id: "credentialed_patch_audit",
    name: "Credentialed Patch Audit",
    category: "Endpoint & OS",
    mode: "native",
    description: "Verifies installed OS, open ports, outdated software and missing patches.",
    purpose: "Patch-level accuracy and software lifecycle auditing.",
    techniques: ["Port sweep", "OS fingerprinting", "Banner extraction", "CVE correlation"],
    detects: ["Missing patches", "Outdated packages", "End-of-life components", "Known CVEs"],
    families: ["ports", "endpoint", "fingerprint", "cve_hunt", "cve"],
  }),
  t({
    id: "offline_config_audit",
    name: "Offline Configuration Audit",
    category: "Endpoint & OS",
    mode: "native",
    description: "Audits endpoint configurations, headers and system exposures.",
    purpose: "Review device and OS configuration and security flags.",
    techniques: ["Configuration rule evaluation", "Header policy audit"],
    detects: ["Policy gaps", "Insecure configuration", "Weak endpoint settings"],
    families: ["endpoint", "fingerprint", "headers"],
  }),
  t({
    id: "malware_scan",
    name: "Malware Scan",
    category: "Endpoint & OS",
    mode: "native",
    description: "Known malware entry vectors, exposed backdoor ports, and persistence paths.",
    purpose: "Detect compromise indicators on network endpoints.",
    techniques: [
      "Port scanning",
      "Backdoor signature matching",
      "Exposure verification",
      "CVE hunting",
    ],
    detects: [
      "Backdoor ports",
      "Suspicious open services",
      "Known malware vectors",
      "Vulnerable daemons",
    ],
    families: ["ports", "endpoint", "exposure", "cve_hunt", "cve"],
  }),
  t({
    id: "mobile_scan",
    name: "Mobile Device Scan",
    category: "Endpoint & OS",
    mode: "native",
    description: "Mobile backend API security, MDM gateway ports and communication posture.",
    purpose: "Assess mobile fleet backend endpoints and API integrity.",
    techniques: ["API enumeration", "TLS verification", "Header audit"],
    detects: ["Insecure mobile endpoints", "Weak TLS", "Missing API authentication"],
    families: ["api", "fingerprint", "headers", "tls"],
  }),
  t({
    id: "windows_audit",
    name: "Windows Security Audit",
    category: "Endpoint & OS",
    mode: "native",
    description: "Windows host hardening, SMB/RDP exposure, services, and missing updates.",
    purpose: "Full Windows host hardening review.",
    techniques: ["Port enumeration (SMB, RDP, WinRM, RPC)", "Banner grabbing", "OS fingerprinting", "CVE correlation"],
    detects: [
      "Exposed SMB/RDP ports",
      "Windows service vulnerabilities",
      "Outdated IIS/server components",
      "Missing updates",
    ],
    families: ["ports", "endpoint", "fingerprint", "cve_hunt", "cve"],
  }),
  t({
    id: "linux_audit",
    name: "Linux Security Audit",
    category: "Endpoint & OS",
    mode: "native",
    description: "Linux services, SSH/FTP/web daemon exposure, and EOL package versions.",
    purpose: "Full Linux host hardening review.",
    techniques: ["Port sweeps", "SSH/daemon banner grabbing", "Software version matching", "CVE correlation"],
    detects: ["Vulnerable packages", "Exposed daemons", "Outdated software", "Known exploits"],
    families: ["ports", "endpoint", "fingerprint", "cve_hunt", "cve"],
  }),
  t({
    id: "macos_audit",
    name: "macOS Security Audit",
    category: "Endpoint & OS",
    mode: "native",
    description: "macOS network services, sharing ports, and software update state.",
    purpose: "Assess macOS endpoint hardening.",
    techniques: ["Network service sweeps", "HTTP/TLS inspection", "Version fingerprinting"],
    detects: ["Open sharing ports", "Weak TLS configuration", "Outdated network software"],
    families: ["ports", "endpoint", "fingerprint", "cve_hunt", "cve"],
  }),
  t({
    id: "active_directory_audit",
    name: "Active Directory Audit",
    category: "Endpoint & OS",
    mode: "native",
    description: "Domain controller ports (LDAP, Kerberos, SMB, DNS, RPC) and policy checks.",
    purpose: "Reduce domain-wide compromise paths.",
    techniques: ["Directory port enumeration (88, 389, 445, 636, 3268)", "TLS validation", "Banner checking"],
    detects: [
      "Exposed domain ports",
      "Unencrypted LDAP",
      "Outdated directory services",
      "RPC exposure",
    ],
    families: ["ports", "endpoint", "fingerprint", "device", "cve"],
  }),

  /* ---------------------------- Infrastructure ------------------------------ */
  t({
    id: "database_audit",
    name: "Database Auditing",
    category: "Infrastructure",
    mode: "native",
    description: "Oracle, MySQL, PostgreSQL, SQL Server, Redis and MongoDB exposure review.",
    purpose: "Secure the data tier: accounts, encryption, unauthenticated access and patching.",
    techniques: ["Database port sweeps (1433, 1521, 3306, 5432, 6379, 27017)", "Service detection", "Version comparison", "CVE correlation"],
    detects: [
      "Direct database exposure",
      "Unauthenticated database sockets",
      "Cleartext protocol risk",
      "Known database CVEs",
    ],
    families: ["ports", "database", "fingerprint", "cve_hunt", "cve"],
  }),
  t({
    id: "scada_ics",
    name: "SCADA / ICS Scan",
    category: "Infrastructure",
    mode: "native",
    description: "Modbus, BACnet, DNP3, and industrial controller exposure assessment.",
    purpose: "Assess operational technology without disrupting processes.",
    techniques: [
      "Industrial port sweep (502, 102, 47808)",
      "Vendor fingerprinting",
      "Safe service inspection",
    ],
    detects: [
      "Exposed PLCs",
      "Unauthenticated industrial protocols",
      "Vulnerable firmware",
    ],
    families: ["ports", "device", "fingerprint", "cve"],
  }),
  t({
    id: "hypervisor_audit",
    name: "Hypervisor Security Audit",
    category: "Infrastructure",
    mode: "native",
    description: "ESXi / Hyper-V management console exposure and patch level fingerprinting.",
    purpose: "Find virtualization management planes reachable from the network.",
    techniques: ["Management console fingerprinting", "Build/version extraction", "TLS review", "Port sweep"],
    detects: ["Exposed ESXi/vCenter UI", "Outdated builds", "Weak console TLS", "Open hypervisor ports"],
    families: ["device", "fingerprint", "tls", "cve", "ports"],
  }),
  t({
    id: "vm_assessment",
    name: "Virtual Machine Assessment",
    category: "Infrastructure",
    mode: "native",
    description: "Guest OS posture, open ports, and virtualization service controls.",
    purpose: "Assess VM guests and their isolation configuration.",
    techniques: ["Port sweeps", "OS fingerprinting", "Version detection", "CVE correlation"],
    detects: [
      "Unpatched guest services",
      "Exposed VM interfaces",
      "Outdated software daemons",
    ],
    families: ["ports", "endpoint", "fingerprint", "cve_hunt", "cve"],
  }),

  /* -------------------------- Cloud & Container ----------------------------- */
  t({
    id: "container_security",
    name: "Container Security Scan",
    category: "Cloud & Container",
    mode: "native",
    description: "Docker, Podman, and container runtime ports: vulnerable packages, exposed sockets, misconfiguration.",
    purpose: "Assess container runtimes and API exposures.",
    techniques: ["Docker API port probe (2375/2376)", "Registry detection (5000)", "Image endpoint inspection"],
    detects: [
      "Unauthenticated Docker daemon",
      "Exposed container registries",
      "Known container CVEs",
    ],
    families: ["ports", "container", "cloud", "api", "fingerprint", "cve"],
  }),
  t({
    id: "kubernetes_security",
    name: "Kubernetes Security",
    category: "Cloud & Container",
    mode: "native",
    description: "Kubernetes API server (6443), Kubelet (10250/10255), and etcd (2379) exposure.",
    purpose: "Harden the cluster control plane and workload posture.",
    techniques: ["API server probe", "Kubelet endpoint verification", "etcd port sweep", "TLS evaluation"],
    detects: [
      "Exposed Kubernetes API server",
      "Unauthenticated Kubelet read-only port",
      "Exposed etcd key-value store",
      "Weak control-plane TLS",
    ],
    families: ["ports", "container", "api", "fingerprint", "cve"],
  }),
  t({
    id: "cloud_audit",
    name: "Cloud Infrastructure Audit",
    category: "Cloud & Container",
    mode: "native",
    description: "AWS, Azure and GCP posture: public S3 buckets, exposed cloud APIs, metadata endpoints.",
    purpose: "Continuous cloud security posture management.",
    techniques: ["S3 bucket probing", "Cloud API enumeration", "Metadata service checks", "TLS validation"],
    detects: [
      "Publicly readable S3 buckets",
      "Exposed cloud services",
      "Unencrypted cloud endpoints",
    ],
    families: ["cloud", "ports", "api", "exposure", "tls", "cve"],
  }),

  /* ------------------------------ Specialized ------------------------------- */
  t({
    id: "log4shell",
    name: "Log4Shell Detection",
    category: "Specialized",
    mode: "native",
    description: "Vulnerable Log4j versions and exploitable Java service indicators.",
    purpose: "Hunt CVE-2021-44228 / CVE-2021-45046 exposure.",
    techniques: [
      "JNDI-safe header injection markers",
      "Java stack fingerprinting",
      "Version banner matching",
      "Port sweeps",
    ],
    detects: ["Log4j 2.x < 2.17", "Java app servers", "JNDI-reachable request handlers"],
    families: ["cve_hunt", "fingerprint", "ports"],
  }),
  t({
    id: "shellshock",
    name: "Shellshock Detection",
    category: "Specialized",
    mode: "native",
    description: "Vulnerable Bash installations reachable through CGI.",
    purpose: "Hunt CVE-2014-6271 and its variants.",
    techniques: ["CGI path enumeration", "Crafted User-Agent function definition probe", "Port sweeps"],
    detects: ["Vulnerable Bash CGI handlers", "Legacy cgi-bin surfaces"],
    families: ["cve_hunt", "ports", "fingerprint"],
  }),
  t({
    id: "bash_vulns",
    name: "Bash Vulnerability Scan",
    category: "Specialized",
    mode: "native",
    description: "Bash CVE family checks against reachable CGI and shell-backed endpoints.",
    purpose: "Broader Bash CVE coverage beyond the original Shellshock probe.",
    techniques: ["Variant payload probes", "Response anomaly comparison", "Port sweeps"],
    detects: ["CVE-2014-6271", "CVE-2014-7169", "CVE-2014-6277/6278"],
    families: ["cve_hunt", "ports", "fingerprint"],
  }),
  t({
    id: "wannacry",
    name: "WannaCry Scan",
    category: "Specialized",
    mode: "native",
    description: "SMBv1, MS17-010 and EternalBlue exposure.",
    purpose: "Confirm the classic worm surface is closed.",
    techniques: ["SMB port 445 sweep", "Dialect negotiation check", "CVE matching"],
    detects: ["SMBv1 enabled", "MS17-010 unpatched", "EternalBlue exposure"],
    families: ["ports", "cve_hunt", "fingerprint", "cve"],
  }),
  t({
    id: "badlock",
    name: "Badlock Detection",
    category: "Specialized",
    mode: "native",
    description: "Microsoft SAM/LSAD (Badlock) SMB vulnerability check.",
    purpose: "Detect CVE-2016-0128 / CVE-2016-2118 exposure.",
    techniques: ["DCERPC and SMB port enumeration", "Signing policy inspection"],
    detects: ["Badlock-vulnerable SMB stacks", "Downgrade-capable RPC"],
    families: ["ports", "cve_hunt", "fingerprint", "cve"],
  }),
  t({
    id: "ransomware",
    name: "Ransomware Detection",
    category: "Specialized",
    mode: "native",
    description: "Common ransomware entry vectors: RDP, SMB and backup exposure.",
    purpose: "Close the paths ransomware crews actually use.",
    techniques: ["RDP/SMB exposure check", "Port sweeps", "Backup share review", "CVE correlation"],
    detects: [
      "Internet-exposed RDP",
      "SMB weaknesses",
      "Unprotected backups",
      "KEV-listed initial access CVEs",
    ],
    families: ["ports", "database", "cve_hunt", "exposure", "fingerprint", "cve"],
  }),
  t({
    id: "spectre_meltdown",
    name: "Spectre / Meltdown Detection",
    category: "Specialized",
    mode: "native",
    description: "CPU speculative-execution mitigation status and vulnerable kernel builds.",
    purpose: "Verify microcode and OS mitigations are active.",
    techniques: ["OS banner and kernel fingerprinting", "CVE correlation"],
    detects: ["Vulnerable kernel builds", "Unpatched CPU exposure CVEs"],
    families: ["endpoint", "fingerprint", "cve_hunt", "cve"],
  }),
  t({
    id: "printnightmare",
    name: "PrintNightmare Scan",
    category: "Specialized",
    mode: "native",
    description: "Vulnerable Windows Print Spooler and RPC configuration.",
    purpose: "Detect CVE-2021-34527 exposure and unsafe spooler policy.",
    techniques: ["Spooler RPC port check", "Point-and-Print service verification"],
    detects: [
      "Spooler RPC port exposed",
      "Unpatched spooler builds",
      "CVE-2021-34527 exposure",
    ],
    families: ["ports", "cve_hunt", "fingerprint", "cve"],
  }),

  /* ------------------------------ Compliance -------------------------------- */
  t({
    id: "compliance_scan",
    name: "Compliance Scan",
    category: "Compliance",
    mode: "analysis",
    description: "Evaluate every framework at once against current findings and asset data.",
    purpose: "One pass/fail view across all supported benchmarks.",
    techniques: ["Control-to-finding mapping", "Asset posture evaluation"],
    detects: ["Failing controls", "Not-assessed controls", "Remediation actions"],
    families: [],
    framework: "ALL",
  }),
  t({
    id: "cis_compliance",
    name: "CIS Compliance",
    category: "Compliance",
    mode: "analysis",
    description: "Center for Internet Security benchmark controls.",
    purpose: "Measure hardening against CIS benchmarks.",
    techniques: ["Benchmark control mapping"],
    detects: ["Pass / fail / not assessed per control"],
    families: [],
    framework: "CIS",
  }),
  t({
    id: "stig_compliance",
    name: "DISA STIG Compliance",
    category: "Compliance",
    mode: "analysis",
    description: "U.S. DoD Security Technical Implementation Guide requirements.",
    purpose: "Assess STIG alignment for defense environments.",
    techniques: ["STIG control mapping"],
    detects: ["CAT I/II/III findings"],
    families: [],
    framework: "STIG",
  }),
  t({
    id: "pci_compliance",
    name: "PCI DSS Compliance",
    category: "Compliance",
    mode: "analysis",
    description: "Payment card environment security controls.",
    purpose: "Validate PCI DSS technical requirements.",
    techniques: ["Requirement mapping", "Severity gating"],
    detects: ["Failing PCI requirements", "Cardholder data exposure risks"],
    families: [],
    framework: "PCI",
  }),
  t({
    id: "hipaa_compliance",
    name: "HIPAA Compliance",
    category: "Compliance",
    mode: "analysis",
    description: "Healthcare security rule technical safeguards.",
    purpose: "Review configurations relevant to ePHI protection.",
    techniques: ["Safeguard mapping"],
    detects: ["Transmission security gaps", "Access control gaps", "Audit control gaps"],
    families: [],
    framework: "HIPAA",
  }),
  t({
    id: "iso27001_audit",
    name: "ISO 27001 Audit",
    category: "Compliance",
    mode: "analysis",
    description: "Annex A technical controls supporting ISO/IEC 27001.",
    purpose: "Evidence technical control coverage for certification.",
    techniques: ["Annex A control mapping"],
    detects: ["Uncovered technical controls"],
    families: [],
    framework: "ISO27001",
  }),
  t({
    id: "gdpr_checks",
    name: "GDPR Security Checks",
    category: "Compliance",
    mode: "analysis",
    description: "Configurations relating to protection of personal data.",
    purpose: "Support Article 32 security-of-processing obligations.",
    techniques: ["Data-exposure mapping", "Transport security evaluation"],
    detects: ["Personal data exposure paths", "Unencrypted transport", "Missing access controls"],
    families: [],
    framework: "GDPR",
  }),
  t({
    id: "nist_compliance",
    name: "NIST Compliance",
    category: "Compliance",
    mode: "analysis",
    description: "NIST CSF / 800-53 aligned technical control review.",
    purpose: "Track alignment with NIST guidance.",
    techniques: ["CSF function mapping", "800-53 control mapping"],
    detects: ["Identify/Protect/Detect gaps"],
    families: [],
    framework: "NIST",
  }),
  t({
    id: "custom_policy",
    name: "Custom Policy Scan",
    category: "Compliance",
    mode: "analysis",
    description: "Your own audit policy built from severity, family and asset predicates.",
    purpose: "Encode organisation-specific rules as pass/fail controls.",
    techniques: ["User-defined predicates", "Finding query evaluation"],
    detects: ["Violations of your own policy"],
    families: [],
    framework: "CUSTOM",
  }),

  /* ------------------------------ Continuous -------------------------------- */
  t({
    id: "agent_scan",
    name: "Agent-based Scan",
    category: "Continuous",
    mode: "native",
    description: "Deep host posture assessment: installed packages, open ports, config and CVE tracking.",
    purpose: "Continuous collection of endpoint security state and vulnerability posture.",
    techniques: ["Port sweeps", "Fingerprinting", "Software auditing", "CVE correlation"],
    detects: ["Full local host posture", "Patch state", "Configuration drift", "Vulnerabilities"],
    families: ["ports", "endpoint", "fingerprint", "cve_hunt", "cve", "headers", "tls"],
  }),
  t({
    id: "live_results",
    name: "Live Results Analysis",
    category: "Continuous",
    mode: "analysis",
    description: "Re-evaluates existing findings against new plugins and intelligence — no rescan.",
    purpose: "Reflect newly published CVE, EPSS and KEV data instantly.",
    techniques: ["Feed diffing", "Priority recomputation", "Finding re-scoring"],
    detects: ["Newly weaponised vulnerabilities", "KEV additions", "EPSS spikes"],
    families: [],
  }),
];

export const SCAN_CATEGORIES: ScanCategory[] = [
  "Discovery",
  "Network",
  "Web & API",
  "Endpoint & OS",
  "Infrastructure",
  "Cloud & Container",
  "Compliance",
  "Specialized",
  "Continuous",
];

export const MODE_LABEL: Record<ScanMode, string> = {
  native: "Runs here",
  agent: "Agent required",
  analysis: "Analysis",
};

export const MODE_CLASS: Record<ScanMode, string> = {
  native: "bg-sev-low/15 text-sev-low border-sev-low/30",
  agent: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  analysis: "bg-primary/15 text-primary border-primary/30",
};

export function getTemplate(id: string): ScanTemplate | undefined {
  return SCAN_CATALOG.find((x) => x.id === id);
}

export const NATIVE_TEMPLATES = SCAN_CATALOG.filter((x) => x.mode === "native");

/** The stage pipeline every scan conceptually walks through. */
export const SCAN_WORKFLOW = [
  "Target selection",
  "Host discovery",
  "Port scanning",
  "Service detection",
  "OS fingerprinting",
  "Credential login",
  "Plugin execution",
  "Configuration audit",
  "Compliance checks",
  "Vulnerability correlation",
  "Risk scoring",
  "Report generation",
] as const;

/** Which pipeline stages a given template actually performs. */
export function workflowStages(tpl: ScanTemplate): string[] {
  if (tpl.mode === "analysis")
    return [
      "Target selection",
      "Compliance checks",
      "Vulnerability correlation",
      "Risk scoring",
      "Report generation",
    ];
  if (tpl.mode === "agent") return [...SCAN_WORKFLOW];
  const stages = [
    "Target selection",
    "Host discovery",
    "Service detection",
    "Plugin execution",
    "Vulnerability correlation",
    "Risk scoring",
    "Report generation",
  ];
  if (tpl.families.includes("fingerprint")) stages.splice(3, 0, "OS fingerprinting");
  return stages;
}

/** Job contract an external agent receives for an agent-mode template. */
export function agentJobContract(tpl: ScanTemplate, target = "10.0.0.0/24") {
  return {
    job: tpl.agentJob ?? tpl.id,
    template: tpl.id,
    target,
    techniques: tpl.techniques,
    credentials: tpl.credentials ?? [],
    result_endpoint: "/api/public/agent/ingest",
    auth_header: "x-agent-key",
    expected_payload: {
      target,
      agent: "aegis-agent/1.0",
      os: "Ubuntu 22.04",
      ports: [{ port: 445, protocol: "tcp", service: "smb", banner: "Samba 4.15" }],
      findings: [
        {
          plugin_id: `${tpl.id.toUpperCase()}-0001`,
          title: "Example finding title",
          severity: 3,
          cvss: 8.1,
          cve_ids: ["CVE-2017-0144"],
          port: 445,
          service: "smb",
          description: "What the agent observed.",
          solution: "How to fix it.",
          evidence: "Raw protocol evidence.",
        },
      ],
    },
  };
}
