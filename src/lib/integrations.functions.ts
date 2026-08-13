import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

export const INTEGRATION_KINDS = [
  {
    id: "webhook",
    label: "Generic webhook",
    hint: "Any HTTPS endpoint. Receives the raw finding envelope.",
  },
  { id: "slack", label: "Slack", hint: "Incoming webhook URL from a Slack app." },
  {
    id: "jira",
    label: "Jira",
    hint: "https://<site>/rest/api/3/issue · token = base64(email:api_token)",
  },
  {
    id: "servicenow",
    label: "ServiceNow",
    hint: "https://<instance>.service-now.com/api/now/table/incident",
  },
  {
    id: "splunk",
    label: "Splunk HEC",
    hint: "https://<host>:8088/services/collector · token = HEC token",
  },
  { id: "sentinel", label: "Microsoft Sentinel", hint: "Logic App / data collector endpoint." },
] as const;

export const listIntegrations = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const [integrations, deliveries] = await Promise.all([
      supabase.from("integrations").select("*").eq("user_id", userId).order("created_at"),
      supabase
        .from("integration_deliveries")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(40),
    ]);
    // Never return stored credentials to the browser.
    const safe = (integrations.data ?? []).map((i) => ({
      ...i,
      config: {
        ...(i.config as Record<string, unknown>),
        token: (i.config as Record<string, unknown>)?.["token"] ? "••••••••" : "",
      },
    }));
    return { integrations: safe, deliveries: deliveries.data ?? [] };
  });

const upsertInput = z.object({
  id: z.string().uuid().optional(),
  kind: z.enum(["webhook", "slack", "jira", "servicenow", "splunk", "sentinel"]),
  name: z.string().min(1).max(120),
  endpoint: z.string().url().max(500),
  token: z.string().max(2000).default(""),
  projectKey: z.string().max(40).default(""),
  minSeverity: z.number().int().min(0).max(4),
});

export const saveIntegration = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => upsertInput.parse(data))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const url = new URL(data.endpoint);
    if (url.protocol !== "https:") throw new Error("Integration endpoints must use HTTPS.");

    const config: Record<string, unknown> = { projectKey: data.projectKey, issueType: "Bug" };
    if (data.token && data.token !== "••••••••") config["token"] = data.token;

    if (data.id) {
      const { data: existing } = await supabase
        .from("integrations")
        .select("config")
        .eq("id", data.id)
        .single();
      const merged = { ...(existing?.config as Record<string, unknown>), ...config } as never;
      await supabase
        .from("integrations")
        .update({
          kind: data.kind,
          name: data.name,
          endpoint: data.endpoint,
          min_severity: data.minSeverity,
          config: merged,
        })
        .eq("id", data.id);
      return { id: data.id };
    }

    const { data: row, error } = await supabase
      .from("integrations")
      .insert({
        user_id: userId,
        kind: data.kind,
        name: data.name,
        endpoint: data.endpoint,
        min_severity: data.minSeverity,
        config: config as never,
      })
      .select("id")
      .single();
    if (error) throw new Error(error.message);
    return { id: row.id };
  });

export const toggleIntegration = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) =>
    z.object({ id: z.string().uuid(), enabled: z.boolean() }).parse(data),
  )
  .handler(async ({ data, context }) => {
    await context.supabase.from("integrations").update({ enabled: data.enabled }).eq("id", data.id);
    return { ok: true };
  });

export const deleteIntegration = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ id: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }) => {
    await context.supabase.from("integrations").delete().eq("id", data.id);
    return { ok: true };
  });

/** Send a synthetic finding through the integration and record the result. */
export const testIntegration = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ id: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { deliverOne } = await import("./integrations.server");
    const { data: integration } = await supabase
      .from("integrations")
      .select("*")
      .eq("id", data.id)
      .single();
    if (!integration) throw new Error("Integration not found");

    const result = await deliverOne(
      {
        id: integration.id,
        kind: integration.kind,
        endpoint: integration.endpoint,
        config: (integration.config ?? {}) as Record<string, unknown>,
      },
      {
        id: "00000000-0000-0000-0000-000000000000",
        title: "Test delivery from Aegis",
        severity: 3,
        plugin_id: "AEGIS-TEST",
        priority: 7.5,
        kev: false,
      },
      { target: "test.example.com", scanId: "test" },
    );

    const ok = result.status >= 200 && result.status < 300;
    await supabase.from("integration_deliveries").insert({
      user_id: userId,
      integration_id: integration.id,
      status: ok ? "delivered" : "failed",
      http_status: result.status,
      detail: result.detail,
    });
    await supabase
      .from("integrations")
      .update({
        last_status: ok ? "delivered" : "failed",
        last_delivery_at: new Date().toISOString(),
      })
      .eq("id", integration.id);

    return { ok, status: result.status, detail: result.detail };
  });
