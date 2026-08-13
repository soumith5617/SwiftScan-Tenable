import { createFileRoute } from "@tanstack/react-router";
import { authenticate } from "./findings";

/** GET /api/public/v1/scans — scan history. POST — queue a new scan. */
export const Route = createFileRoute("/api/public/v1/scans")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const auth = await authenticate(request);
        if ("error" in auth) return auth.error;
        const { data, error } = await auth.supabase
          .from("scans")
          .select(
            "id, name, target, template, status, progress, current_step, source, stats, started_at, finished_at, created_at",
          )
          .eq("user_id", auth.userId)
          .order("created_at", { ascending: false })
          .limit(200);
        if (error) return Response.json({ error: error.message }, { status: 500 });
        return Response.json({ data }, { headers: { "cache-control": "no-store" } });
      },
      POST: async ({ request }) => {
        const auth = await authenticate(request);
        if ("error" in auth) return auth.error;

        let body: { target?: unknown; template?: unknown; name?: unknown };
        try {
          body = (await request.json()) as typeof body;
        } catch {
          return Response.json({ error: "Invalid JSON body" }, { status: 400 });
        }
        const target = typeof body.target === "string" ? body.target.trim() : "";
        if (!target || target.length > 255)
          return Response.json({ error: "`target` is required" }, { status: 400 });
        const template = typeof body.template === "string" ? body.template : "basic_network_scan";

        const { data: scan, error } = await auth.supabase
          .from("scans")
          .insert({
            user_id: auth.userId,
            name: typeof body.name === "string" ? body.name.slice(0, 120) : `API scan — ${target}`,
            target,
            template,
            status: "queued",
            source: "api",
          })
          .select("id")
          .single();
        if (error || !scan)
          return Response.json({ error: error?.message ?? "Insert failed" }, { status: 500 });

        const { executeScanById } = await import("@/lib/monitoring.server");
        const result = await executeScanById(auth.supabase as never, auth.userId, scan.id);
        return Response.json({ scan_id: scan.id, ...result }, { status: 202 });
      },
    },
  },
});
