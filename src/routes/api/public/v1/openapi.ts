import { createFileRoute } from "@tanstack/react-router";

const SPEC = {
  openapi: "3.1.0",
  info: {
    title: "Aegis Vulnerability Platform API",
    version: "1.0.0",
    description:
      "REST API for findings, assets, scans and agent ingest. Authenticate with an API key created in Settings, sent as the X-API-Key header.",
  },
  servers: [{ url: "/api/public" }],
  components: {
    securitySchemes: { ApiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key" } },
    schemas: {
      Finding: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          plugin_id: { type: "string" },
          family: { type: "string" },
          title: { type: "string" },
          severity: { type: "integer", description: "0 Info … 4 Critical" },
          cvss: { type: ["number", "null"] },
          epss: { type: ["number", "null"] },
          kev: {
            type: "boolean",
            description: "Listed in the CISA Known Exploited Vulnerabilities catalog",
          },
          priority: { type: "number", description: "VPR-style 0-10 score" },
          confidence: { type: "string", enum: ["low", "medium", "high"] },
          cve_ids: { type: "array", items: { type: "string" } },
          state: { type: "string", enum: ["open", "fixed", "accepted", "false_positive"] },
          due_at: { type: ["string", "null"], format: "date-time" },
        },
      },
      Asset: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          name: { type: "string" },
          target: { type: "string" },
          criticality: { type: "string", enum: ["low", "medium", "high", "critical"] },
          risk_score: { type: "number" },
          internet_facing: { type: "boolean" },
          technologies: { type: "array", items: { type: "object" } },
        },
      },
      Scan: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          name: { type: "string" },
          target: { type: "string" },
          template: { type: "string" },
          status: {
            type: "string",
            enum: ["queued", "running", "completed", "failed", "awaiting_agent"],
          },
          progress: { type: "integer" },
          stats: { type: "object" },
        },
      },
    },
  },
  security: [{ ApiKeyAuth: [] }],
  paths: {
    "/v1/findings": {
      get: {
        summary: "List findings",
        parameters: [
          { name: "limit", in: "query", schema: { type: "integer", default: 100, maximum: 1000 } },
          { name: "offset", in: "query", schema: { type: "integer", default: 0 } },
          {
            name: "min_severity",
            in: "query",
            schema: { type: "integer", minimum: 0, maximum: 4 },
          },
          { name: "state", in: "query", schema: { type: "string" } },
          { name: "kev", in: "query", schema: { type: "boolean" } },
        ],
        responses: {
          "200": {
            description: "Paginated findings",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    data: { type: "array", items: { $ref: "#/components/schemas/Finding" } },
                    pagination: { type: "object" },
                  },
                },
              },
            },
          },
          "401": { description: "Missing or invalid API key" },
        },
      },
    },
    "/v1/assets": {
      get: {
        summary: "List assets",
        responses: {
          "200": {
            description: "Asset inventory",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    data: { type: "array", items: { $ref: "#/components/schemas/Asset" } },
                  },
                },
              },
            },
          },
        },
      },
    },
    "/v1/scans": {
      get: {
        summary: "List scans",
        responses: { "200": { description: "Scan history" } },
      },
      post: {
        summary: "Queue and run a scan",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["target"],
                properties: {
                  target: { type: "string", example: "example.com" },
                  template: { type: "string", default: "basic_network_scan" },
                  name: { type: "string" },
                },
              },
            },
          },
        },
        responses: {
          "202": {
            description: "Scan executed",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Scan" } } },
          },
        },
      },
    },
    "/agent/ingest": {
      post: {
        summary: "Ingest results from a distributed scan agent",
        description:
          "Used by the Rust/Go scan worker for raw-socket work the browser runtime cannot do: ARP/ICMP sweeps, SYN/UDP port scans, OS fingerprinting and credentialed SMB/SSH checks. Authenticate with X-Agent-Key.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["target"],
                properties: {
                  target: { type: "string" },
                  agent: { type: "string" },
                  os: { type: "string" },
                  ports: { type: "array", items: { type: "object" } },
                  findings: { type: "array", items: { type: "object" } },
                },
              },
            },
          },
        },
        responses: { "200": { description: "Ingested" } },
      },
    },
    "/hooks/run-schedules": {
      post: {
        summary: "Continuous monitoring tick",
        description: "Executes every due schedule. Called by the platform scheduler.",
        responses: { "200": { description: "Schedules processed" } },
      },
    },
  },
} as const;

export const Route = createFileRoute("/api/public/v1/openapi")({
  server: {
    handlers: {
      GET: async () =>
        Response.json(SPEC, {
          headers: { "cache-control": "public, max-age=300", "access-control-allow-origin": "*" },
        }),
    },
  },
});
