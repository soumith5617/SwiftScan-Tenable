# Full Nessus Scan-Type Catalog (all 50 templates)

Today the app ships 5 scan templates (web, TLS, exposure, API, quick). This adds the complete 50-template catalog from your list, each with its purpose, techniques, detections and an honest execution mode — so the console covers everything Nessus offers, and never pretends to run a check it cannot.

## Three execution modes

Every template is tagged so the UI always tells the truth about how it runs:

- **Native** — runs now, server-side, from this app (HTTP/TLS reachable checks).
- **Agent** — requires an external scan agent (raw sockets, credentials, local host access). The template exists, can be scheduled, and shows the exact agent job contract; results arrive through the existing ingest API and are scored identically.
- **Analysis** — runs against data already in the platform (compliance mapping, live results re-evaluation, attack-surface rollups, custom policies).

## Template catalog

**Native (executed here)**
Basic Network Scan (web-reachable subset), Advanced Scan (custom families/timing/paths), Web Application Tests, API Security Scan, SSL/TLS Scan, External Attack Surface Scan, DNS Security Audit (DoH-based: DNSSEC, records, subdomain exposure), Email Server Security (MX/SPF/DKIM/DMARC posture), Log4Shell, Shellshock/Bash, Spectre-Meltdown banner inference, IoT/device fingerprinting over HTTP, Hypervisor/VM web-console exposure, Live Results Analysis.

**Agent-delegated (contract + ingest)**
Host Discovery, Credentialed Patch Audit, Offline Configuration Audit, Malware Scan, Mobile Device Scan, WannaCry/MS17-010, Badlock, Ransomware vectors, PrintNightmare, SMB Vulnerability Scan, Database Auditing, SCADA/ICS, Container Security, Kubernetes Security, Cloud Infrastructure Audit, Internal Network Scan, Wireless Scan, SNMP Audit, FTP Security, SSH Security, Active Directory Audit, Windows / Linux / macOS Security Audit, Virtual Machine Assessment, Agent-based Scan.

**Analysis / compliance**
Compliance Scan, CIS, DISA STIG, PCI DSS, HIPAA, ISO 27001, GDPR, NIST, Custom Policy Scan.

## New UI

- **Scan Templates library** — searchable, category-grouped grid (Discovery, Network, Web & API, Endpoint & OS, Infrastructure, Cloud & Container, Compliance, Specialized CVE hunts, Continuous). Each card shows purpose, techniques, what it detects, execution mode, and Run / Schedule / View contract.
- **Template detail page** — the full spec of that scan (techniques, detections, plugin families, required credentials, agent job JSON to copy).
- **New Scan flow** — template picker filtered by mode, with credential and port-range fields shown for the templates that use them.
- **Compliance page** — per-framework control list with pass/fail/not-assessed derived from existing findings + asset data, and per-control remediation.
- **Scan workflow visual** — the target → discovery → ports → services → OS → credentials → plugins → config audit → compliance → correlation → scoring → report pipeline, with the stages this app performs highlighted per template.

## Technical notes

- Extend `SCAN_TEMPLATES` in `src/lib/severity.ts` into a richer catalog type: `id, name, category, mode, purpose, techniques[], detects[], families[], credentials?, agentJob?`.
- Add new native plugin families to `src/lib/scan-engine.server.ts`: `dns`, `mail`, `cve_hunt` (Log4Shell/Shellshock probes), `device` (IoT/hypervisor console fingerprints). Existing plugin-registry pattern, no engine changes.
- Agent templates create a `scans` row with `source='agent'`, `status='queued'` and a job payload the agent polls/receives; ingest already correlates and scores results.
- Compliance frameworks defined as data (`src/lib/compliance.ts`): control id, title, framework, mapped finding predicate. Evaluated server-side from findings/assets — no new scan execution.
- New routes: `_authenticated/templates.tsx`, `_authenticated/templates.$templateId.tsx`, `_authenticated/compliance.tsx`; sidebar entries added.
- No schema change required beyond an optional `scans.params jsonb` column for per-template configuration.

## Build order

1. Template catalog data model + all 50 entries with full metadata.
2. Templates library and detail pages, wired into the New Scan flow.
3. New native plugin families (DNS, mail, CVE hunts, device fingerprints).
4. Agent job contract per agent-mode template + queued-scan handoff.
5. Compliance framework engine and page.
6. Workflow visualization and dashboard coverage widget.
