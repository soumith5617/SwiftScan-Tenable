import { createFileRoute } from "@tanstack/react-router";

/**
 * Continuous monitoring tick. Called by the platform scheduler (pg_cron) with
 * the project publishable key. Executes every schedule whose window has
 * elapsed, then re-arms it.
 */
export const Route = createFileRoute("/api/public/hooks/run-schedules")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const apiKey = request.headers.get("apikey") ?? "";
        if (!apiKey) return Response.json({ error: "missing apikey" }, { status: 401 });

        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { executeScanById, nextRunFrom } = await import("@/lib/monitoring.server");

        const nowIso = new Date().toISOString();
        const { data: due, error } = await supabaseAdmin
          .from("schedules")
          .select("*")
          .eq("enabled", true)
          .lte("next_run_at", nowIso)
          .order("next_run_at")
          .limit(10);
        if (error) return Response.json({ error: error.message }, { status: 500 });
        if (!due?.length) return Response.json({ ran: 0 });

        const results: { schedule: string; ok: boolean; findings: number }[] = [];
        for (const schedule of due) {
          // Re-arm first so a slow scan cannot cause a duplicate tick.
          await supabaseAdmin
            .from("schedules")
            .update({
              next_run_at: nextRunFrom(schedule.cadence),
              last_run_at: nowIso,
              runs: (schedule.runs ?? 0) + 1,
            })
            .eq("id", schedule.id);

          const { data: scan } = await supabaseAdmin
            .from("scans")
            .insert({
              user_id: schedule.user_id,
              asset_id: schedule.asset_id,
              name: `${schedule.name} (scheduled)`,
              template: schedule.template,
              target: schedule.target,
              status: "queued",
              source: "schedule",
            })
            .select("id")
            .single();
          if (!scan) continue;

          const outcome = await executeScanById(supabaseAdmin as never, schedule.user_id, scan.id);
          await supabaseAdmin
            .from("schedules")
            .update({ last_scan_id: scan.id })
            .eq("id", schedule.id);
          results.push({ schedule: schedule.name, ok: outcome.ok, findings: outcome.findings });
        }

        return Response.json({ ran: results.length, results });
      },
    },
  },
});
