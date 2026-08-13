import { createFileRoute } from "@tanstack/react-router";
import { authenticate } from "./findings";

/** GET /api/public/v1/assets — asset inventory with live risk scores. */
export const Route = createFileRoute("/api/public/v1/assets")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const auth = await authenticate(request);
        if ("error" in auth) return auth.error;

        const { data, error } = await auth.supabase
          .from("assets")
          .select(
            "id, name, target, kind, criticality, tags, os, technologies, internet_facing, risk_score, first_seen, last_seen",
          )
          .eq("user_id", auth.userId)
          .order("risk_score", { ascending: false })
          .limit(1000);
        if (error) return Response.json({ error: error.message }, { status: 500 });
        return Response.json({ data }, { headers: { "cache-control": "no-store" } });
      },
    },
  },
});
