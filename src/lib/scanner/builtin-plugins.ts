import { ScanPlugin, ScanContext } from "./plugin-interface";
import { RawFinding, probe } from "../scan-engine.server";

export const BUILTIN_PLUGINS: ScanPlugin[] = [
  // 1. Security Headers Plugin
  {
    metadata: {
      id: "AEG-PLUG-1001",
      name: "HTTP Strict-Transport-Security (HSTS) Verification",
      family: "headers",
      category: "configuration",
      version: "1.2.0",
      description:
        "Checks if the server enforces secure connections using the HTTP Strict-Transport-Security (HSTS) response header.",
      solution:
        "Configure the web server to send 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
      defaultSeverity: 2,
      cwe: "CWE-523",
      references: [
        {
          title: "OWASP HSTS Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        },
      ],
    },
    isApplicable: (ctx) => ctx.httpsSupported,
    execute: async (ctx) => {
      const findings: RawFinding[] = [];
      const hsts = ctx.rootProbe?.headers["strict-transport-security"];
      if (!hsts) {
        findings.push({
          plugin_id: "AEG-PLUG-1001",
          family: "headers",
          title: "Missing HTTP Strict-Transport-Security (HSTS) Header",
          severity: 2,
          confidence: "high",
          cwe: "CWE-523",
          description:
            "The remote web server does not enforce HTTPS connections via HSTS. Unencrypted HTTP downgrade and cookie interception attacks are possible.",
          solution:
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
          evidence:
            "Strict-Transport-Security header was not found in response headers from " +
            ctx.targetUrl.origin,
          port: 443,
          service: "https",
          attack_tactics: ["Initial Access", "Credential Access"],
        });
      }
      return findings;
    },
  },

  // 2. Content-Security-Policy (CSP) Plugin
  {
    metadata: {
      id: "AEG-PLUG-1002",
      name: "Content-Security-Policy (CSP) Inspection",
      family: "headers",
      category: "vulnerability",
      version: "1.1.0",
      description:
        "Analyzes the presence and strictness of Content-Security-Policy header to mitigate Cross-Site Scripting (XSS) and data injection.",
      solution:
        "Define a robust Content-Security-Policy header restricting script-src, object-src, and frame-ancestors.",
      defaultSeverity: 2,
      cwe: "CWE-1021",
    },
    isApplicable: () => true,
    execute: async (ctx) => {
      const findings: RawFinding[] = [];
      const csp = ctx.rootProbe?.headers["content-security-policy"];
      if (!csp) {
        findings.push({
          plugin_id: "AEG-PLUG-1002",
          family: "headers",
          title: "Missing Content-Security-Policy (CSP) Header",
          severity: 2,
          confidence: "high",
          cwe: "CWE-1021",
          description:
            "The application does not declare a Content-Security-Policy. Without CSP, the browser cannot prevent inline script injection or unauthorized resource inclusion.",
          solution:
            "Implement a Content-Security-Policy header with restrictive script-src and default-src directives.",
          evidence: "Content-Security-Policy header was missing from root response.",
          port: ctx.targetUrl.protocol === "https:" ? 443 : 80,
          service: ctx.targetUrl.protocol.replace(":", ""),
          attack_tactics: ["Execution", "Collection"],
        });
      } else if (csp.includes("'unsafe-inline'") || csp.includes("*")) {
        findings.push({
          plugin_id: "AEG-PLUG-1003",
          family: "headers",
          title: "Permissive Content-Security-Policy Directives Detected",
          severity: 1,
          confidence: "medium",
          cwe: "CWE-1021",
          description:
            "The Content-Security-Policy contains wildcard '*' or 'unsafe-inline' directives which degrade XSS protection.",
          solution:
            "Refactor scripts to use cryptographic nonces or hashes rather than 'unsafe-inline'.",
          evidence: `CSP Header: ${csp.slice(0, 200)}`,
          port: ctx.targetUrl.protocol === "https:" ? 443 : 80,
          service: ctx.targetUrl.protocol.replace(":", ""),
        });
      }
      return findings;
    },
  },

  // 3. CORS Misconfiguration Plugin
  {
    metadata: {
      id: "AEG-PLUG-2001",
      name: "Cross-Origin Resource Sharing (CORS) Origin Validation",
      family: "api",
      category: "vulnerability",
      version: "1.0.0",
      description:
        "Detects dangerous CORS configurations that allow arbitrary origins to access authenticated API responses.",
      solution:
        "Specify explicit trusted origins in Access-Control-Allow-Origin rather than reflecting arbitrary Origin headers with credentials.",
      defaultSeverity: 3,
      cwe: "CWE-942",
    },
    isApplicable: () => true,
    execute: async (ctx) => {
      const findings: RawFinding[] = [];
      const evilOrigin = "https://attacker-origin.test";
      const testProbe = await probe(ctx.targetUrl.href, {
        headers: { Origin: evilOrigin },
      });

      if (testProbe) {
        const acao = testProbe.headers["access-control-allow-origin"];
        const acac = testProbe.headers["access-control-allow-credentials"];
        if (acao === evilOrigin && acac === "true") {
          findings.push({
            plugin_id: "AEG-PLUG-2001",
            family: "api",
            title: "Dangerous CORS Policy with Arbitrary Origin & Credentials",
            severity: 3,
            confidence: "high",
            cwe: "CWE-942",
            description:
              "The server dynamically reflects untrusted Origin headers and allows credentials (cookies/tokens). This allows malicious sites to exfiltrate private user data.",
            solution:
              "Validate Origin headers against a strict whitelist of allowed domains before reflecting in Access-Control-Allow-Origin.",
            evidence: `Request Origin: ${evilOrigin}\nResponse Access-Control-Allow-Origin: ${acao}\nResponse Access-Control-Allow-Credentials: ${acac}`,
            port: ctx.targetUrl.protocol === "https:" ? 443 : 80,
            service: "http-api",
            attack_tactics: ["Initial Access", "Collection"],
          });
        }
      }
      return findings;
    },
  },

  // 4. Sensitive File & Environment Exposure Plugin
  {
    metadata: {
      id: "AEG-PLUG-3001",
      name: "Sensitive File & Configuration Exposure Probe",
      family: "exposure",
      category: "vulnerability",
      version: "1.3.0",
      description:
        "Probes common sensitive paths for exposed secrets, environment configurations, and version control artifacts.",
      solution:
        "Restrict web server access to dotfiles, backup files, and private configuration directories.",
      defaultSeverity: 4,
      cwe: "CWE-200",
    },
    isApplicable: () => true,
    execute: async (ctx) => {
      const findings: RawFinding[] = [];
      const testPaths = [
        {
          path: "/.env",
          regex: /(DATABASE_URL|API_KEY|SECRET|PASSWORD|SUPABASE_KEY)=/i,
          title: "Exposed Environment Configuration File (.env)",
          sev: 4,
        },
        {
          path: "/.git/HEAD",
          regex: /ref:\s*refs\//i,
          title: "Exposed Git Repository Metadata (.git/HEAD)",
          sev: 3,
        },
        {
          path: "/swagger.json",
          regex: /"swagger"|"openapi"/i,
          title: "Exposed OpenAPI / Swagger API Definition",
          sev: 1,
        },
      ];

      for (const item of testPaths) {
        const checkUrl = new URL(item.path, ctx.targetUrl.origin).href;
        const res = await probe(checkUrl, {}, 5000);
        if (res && res.status === 200 && item.regex.test(res.body)) {
          findings.push({
            plugin_id: `AEG-PLUG-EXP-${item.path.replace(/[^a-zA-Z0-9]/g, "")}`,
            family: "exposure",
            title: item.title,
            severity: item.sev,
            confidence: "high",
            cwe: "CWE-200",
            description: `The sensitive resource at ${item.path} was directly accessible without authentication and returned matching secret or configuration patterns.`,
            solution:
              "Block access to sensitive files and dotfiles in reverse proxy / web server configuration.",
            evidence: `URL: ${checkUrl}\nHTTP Status: ${res.status}\nSnippet:\n${res.body.slice(0, 300)}`,
            port: ctx.targetUrl.protocol === "https:" ? 443 : 80,
            service: ctx.targetUrl.protocol.replace(":", ""),
            attack_tactics: ["Credential Access", "Discovery"],
          });
        }
      }
      return findings;
    },
  },
];
