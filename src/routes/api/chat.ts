import { createFileRoute } from "@tanstack/react-router";
import { convertToModelMessages, streamText, tool, stepCountIs, type UIMessage } from "ai";
import { z } from "zod";
import { createClient } from "@supabase/supabase-js";
import { createLovableAiGatewayProvider, AI_MODEL } from "@/lib/ai-gateway.server";
import { severityLabel } from "@/lib/severity";
import { buildAttackGraph } from "@/lib/attack-graph";

const SYSTEM = `You are the security copilot inside a vulnerability management platform.
You answer questions strictly from the tools, which read this user's own scan data.
Rules:
- Always call a tool before stating any number, asset name or finding. Never guess.
- If a tool returns nothing, say the data is not in the platform yet and name the scan that would produce it.
- Be terse and technical. Markdown, short sections, tables only when comparing.
- When asked for a remediation plan, order the work by exploitability (KEV, EPSS, internet exposure), not raw CVSS.
- Never claim a vulnerability is exploitable in the wild unless a tool returned kev=true or an EPSS score.`;

export const Route = createFileRoute("/api/chat")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const apiKey = process.env["LOVABLE_API_KEY"];
        if (!apiKey) return new Response("AI is not configured", { status: 500 });

        const auth = request.headers.get("authorization") ?? "";
        if (!auth.startsWith("Bearer ")) return new Response("Unauthorized", { status: 401 });

        const supabase = createClient(
          process.env["SUPABASE_URL"]!,
          process.env["SUPABASE_PUBLISHABLE_KEY"]!,
          {
            auth: { persistSession: false, autoRefreshToken: false },
            global: { headers: { Authorization: auth } },
          },
        );
        const { data: userData } = await supabase.auth.getUser(auth.slice(7));
        const userId = userData.user?.id;
        if (!userId) return new Response("Unauthorized", { status: 401 });

        const { messages } = (await request.json()) as { messages: UIMessage[] };

        const tools = {
          search_findings: tool({
            description:
              "Search this user's findings. Filter by minimum severity, KEV-only, open state, free-text or CVE. Returns the highest-priority matches.",
            inputSchema: z.object({
              query: z
                .string()
                .nullable()
                .describe("free text matched against the title, or a CVE id"),
              minSeverity: z.number().int().min(0).max(4).nullable(),
              kevOnly: z.boolean().nullable(),
              openOnly: z.boolean().nullable(),
              limit: z.number().int().min(1).max(50).nullable(),
            }),
            execute: async ({ query, minSeverity, kevOnly, openOnly, limit }) => {
              let q = supabase
                .from("findings")
                .select(
                  "id, title, severity, priority, cvss, epss, kev, cve_ids, service, port, state, asset_id, confidence, verifications, first_seen",
                )
                .eq("user_id", userId)
                .order("priority", { ascending: false })
                .limit(limit ?? 15);
              if (minSeverity != null) q = q.gte("severity", minSeverity);
              if (kevOnly) q = q.eq("kev", true);
              if (openOnly !== false) q = q.eq("state", "open");
              if (query) q = q.ilike("title", `%${query}%`);
              const { data, error } = await q;
              if (error) return { error: error.message };
              return (data ?? []).map((f) => ({ ...f, severityLabel: severityLabel(f.severity) }));
            },
          }),
          list_assets: tool({
            description:
              "List assets in the inventory, optionally only internet-facing or by criticality.",
            inputSchema: z.object({
              internetFacingOnly: z.boolean().nullable(),
              criticality: z.enum(["low", "medium", "high", "critical"]).nullable(),
            }),
            execute: async ({ internetFacingOnly, criticality }) => {
              let q = supabase
                .from("assets")
                .select(
                  "id, name, target, kind, criticality, internet_facing, risk_score, os, technologies, last_seen",
                )
                .eq("user_id", userId)
                .order("risk_score", { ascending: false })
                .limit(100);
              if (internetFacingOnly) q = q.eq("internet_facing", true);
              if (criticality) q = q.eq("criticality", criticality);
              const { data, error } = await q;
              return error ? { error: error.message } : data;
            },
          }),
          compare_scans: tool({
            description:
              "Compare the two most recent completed scans of a target (or the two most recent overall) and report what changed.",
            inputSchema: z.object({ target: z.string().nullable() }),
            execute: async ({ target }) => {
              let q = supabase
                .from("scans")
                .select("id, name, target, finished_at, stats, status")
                .eq("user_id", userId)
                .eq("status", "completed")
                .order("finished_at", { ascending: false })
                .limit(2);
              if (target) q = q.eq("target", target);
              const { data: scans } = await q;
              if (!scans || scans.length < 2)
                return { error: "Need two completed scans to compare." };
              const [current, previous] = scans;
              const ids = [current!.id, previous!.id];
              const { data: findings } = await supabase
                .from("findings")
                .select("scan_id, title, severity, kev")
                .in("scan_id", ids);
              const inScan = (id: string) => (findings ?? []).filter((f) => f.scan_id === id);
              const titles = (id: string) => new Set(inScan(id).map((f) => f.title));
              const now = titles(current!.id);
              const before = titles(previous!.id);
              return {
                current: { id: current!.id, at: current!.finished_at, stats: current!.stats },
                previous: { id: previous!.id, at: previous!.finished_at, stats: previous!.stats },
                introduced: [...now].filter((t) => !before.has(t)).slice(0, 25),
                resolved: [...before].filter((t) => !now.has(t)).slice(0, 25),
              };
            },
          }),
          attack_paths: tool({
            description:
              "Compute the exposure graph and return the highest-value attack paths from the internet to critical assets.",
            inputSchema: z.object({}),
            execute: async () => {
              const [assets, findings] = await Promise.all([
                supabase
                  .from("assets")
                  .select("id, name, target, kind, criticality, internet_facing, technologies, os")
                  .eq("user_id", userId)
                  .limit(300),
                supabase
                  .from("findings")
                  .select(
                    "id, asset_id, title, severity, kev, service, port, family, attack_tactics",
                  )
                  .eq("user_id", userId)
                  .eq("state", "open")
                  .limit(1500),
              ]);
              const graph = buildAttackGraph(assets.data ?? [], findings.data ?? []);
              const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
              return graph.paths.map((p) => ({
                route: p.nodes.map(label).join(" -> "),
                severity: severityLabel(p.severity),
                kev: p.kev,
              }));
            },
          }),
          create_ticket: tool({
            description:
              "Create a ticket for a finding in every enabled integration (Jira, ServiceNow, Slack, webhook). Requires user approval.",
            inputSchema: z.object({ findingId: z.string().describe("id from search_findings") }),
            execute: async ({ findingId }) => {
              const { data: finding } = await supabase
                .from("findings")
                .select(
                  "id, title, severity, cvss, epss, kev, cve_ids, description, solution, priority, scan_id",
                )
                .eq("id", findingId)
                .eq("user_id", userId)
                .maybeSingle();
              if (!finding) return { error: "Finding not found" };
              const { dispatchFindings } = await import("@/lib/integrations.server");
              const result = await dispatchFindings(supabase as never, userId, [finding as never], {
                target: "copilot",
                scanId: finding.scan_id ?? "",
              });
              return { delivered: result.delivered, finding: finding.title };
            },
          }),
        };

        const gateway = createLovableAiGatewayProvider(apiKey);
        const result = streamText({
          model: gateway(AI_MODEL),
          system: SYSTEM,
          messages: await convertToModelMessages(messages),
          tools,
          stopWhen: stepCountIs(50),
          abortSignal: request.signal,
        });

        return result.toUIMessageStreamResponse();
      },
    },
  },
});
