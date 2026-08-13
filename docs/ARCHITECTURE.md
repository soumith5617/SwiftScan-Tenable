# AegisScan Enterprise Architecture Documentation

## 1. System Overview

AegisScan is an enterprise vulnerability management and continuous attack-surface monitoring platform designed with an asynchronous scan engine, real-time threat intelligence correlation, dynamic risk calculation, and multi-dashboard operational intelligence.

```
+-------------------------------------------------------------------------------+
|                             AEGISSCAN ARCHITECTURE                             |
+-------------------------------------------------------------------------------+
                                        |
  [ Web Console / Desktop UI ] <=======> [ TanStack Start / Nitro SSR Edge Layer ]
                                        |
  +-------------------------------------+---------------------------------------+
  |                                                                             |
  v                                                                             v
[ Asynchronous Scanner Engine ]                                    [ Threat Intel Pipeline ]
  * Target Normalization & Reachability                              * NVD CVE Cache
  * Port & Service Discovery                                         * CISA KEV Catalog
  * Extensible Plugin Manager (Lifecycle Hooks)                      * FIRST EPSS Daily Probabilities
  * HTTP / TLS / DNS / Exposure Probes                               * Version CPE Matcher
  * Distributed Agent Ingest API (/api/public/agent)                            |
  |                                                                             |
  +-------------------------------------+---------------------------------------+
                                        |
                                        v
                            [ Multi-Factor Risk Engine ]
                              * CVSS v3.1 / v4 Base
                              * EPSS Exploit Probability Multiplier
                              * CISA KEV Exploited Urgency Boost
                              * Asset Criticality & Exposure Weighting
                              * SLA Due Date Calculation
                              * Custom Risk Overrides (Audit-Logged)
                                        |
                                        v
                            [ PostgreSQL & Supabase DB ]
                              * Row-Level Security (RLS)
                              * Normalized Schemas & Foreign Keys
                              * Asset Groups & Port Inventory
                              * Audit Trail & Saved Filters
```

---

## 2. Core Modules & Subsystems

### 2.1 Asynchronous Scanner Architecture

- **Scanner Manager (`src/lib/scanner/scanner-manager.ts`)**: Controls scan job lifecycle (`queued` &rarr; `running` &rarr; `completed` / `failed`), concurrency limits, and live step updates.
- **Plugin Manager (`src/lib/scanner/plugin-manager.ts`)**: Singleton registry executing modular checks implementing the `ScanPlugin` contract.
- **Built-in Plugins (`src/lib/scanner/builtin-plugins.ts`)**:
  - `AEG-PLUG-1001`: HSTS Enforcement & TLS Transport Verification
  - `AEG-PLUG-1002`: Content-Security-Policy Strictness Audit
  - `AEG-PLUG-2001`: CORS Origin Validation & Credential Leakage
  - `AEG-PLUG-3001`: Sensitive File, Dotfile & Environment Exposure Probe

### 2.2 Risk Calculation & Prioritization Engine

- **Risk Engine (`src/lib/risk/risk-engine.ts`)**:
  $$\text{Adjusted Priority} = \text{CVSS} \times 7.5 \times W_{\text{criticality}} \times W_{\text{exposure}} \times M_{\text{epss}} \times B_{\text{kev}}$$
  - Clamped to $0.0 - 100.0$ range.
  - Generates Effective Severity Levels (0: Info, 1: Low, 2: Medium, 3: High, 4: Critical).
  - Supports SLA due-date generation (Critical = 14 days, High = 30 days, Medium = 60 days, Low = 90 days).
  - Risk Overrides: Analysts can override severity with written business justification, approver ID, and expiration date.

### 2.3 Asset & Port Inventory

- **Asset Hierarchy (`src/routes/_authenticated/assets.tsx`)**:
  - Target segmentation by type (`web`, `host`, `api`, `cloud`, `container`) and criticality (`critical`, `high`, `medium`, `low`).
  - Asset Groups with static membership and dynamic tag/criticality rules.
  - Host Port Inventory recording open ports, protocols, services, and banner fingerprints (`public.host_ports`).

### 2.4 Reporting Engine

- **Report Generator (`src/lib/report-generator.ts`)**:
  - **Executive Summary**: High-level risk score gauges, SLA compliance rate, top 5 business risks, and remediation priorities.
  - **Technical Assessment**: Full finding breakdown with evidence snippets, CWE classifications, and remediation steps.
  - **Asset Breakdown**: Formatted spreadsheet inventory of all monitored targets.
  - **Compliance Scorecard**: Pass/Fail matrix for CIS, NIST, PCI DSS, and HIPAA benchmarks.
  - Export formats: **PDF** (printable layout), **CSV**, and **JSON**.

---

## 3. Security Model

1. **Authentication & Sessions**: Supabase JWT authentication with token validation in SSR server functions.
2. **Row-Level Security (RLS)**: Every table enforces strict `auth.uid() = user_id` row-level policies.
3. **API Key Security**: Distributed worker and REST API keys are stored as SHA-256 hashes (`public.api_keys`). Keys are never returned in plaintext after creation.
4. **Input Validation**: All server function inputs are strictly validated with Zod schemas.
