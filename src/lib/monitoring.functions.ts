import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

export const CADENCES = [
  { id: "hourly", label: "Every hour" },
  { id: "every6h", label: "Every 6 hours" },
  { id: "daily", label: "Daily" },
  { id: "weekly", label: "Weekly" },
] as const;

export const listMonitoring = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const [schedules, changes, assets] = await Promise.all([
      supabase.from("schedules").select("*").eq("user_id", userId).order("next_run_at"),
      supabase
        .from("asset_changes")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(60),
      supabase.from("assets").select("id, name, target").eq("user_id", userId).order("name"),
    ]);
    return {
      schedules: schedules.data ?? [],
      changes: changes.data ?? [],
      assets: assets.data ?? [],
    };
  });

const createInput = z.object({
  name: z.string().min(1).max(120),
  target: z.string().min(1).max(255),
  template: z.string().min(1).max(80),
  cadence: z.enum(["hourly", "every6h", "daily", "weekly"]),
  assetId: z.string().uuid().nullable().default(null),
});

export const createSchedule = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => createInput.parse(data))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { nextRunFrom } = await import("./monitoring.server");
    const { data: row, error } = await supabase
      .from("schedules")
      .insert({
        user_id: userId,
        name: data.name,
        target: data.target,
        template: data.template,
        cadence: data.cadence,
        asset_id: data.assetId,
        next_run_at: nextRunFrom(data.cadence),
      })
      .select()
      .single();
    if (error) throw new Error(error.message);
    return row;
  });

export const toggleSchedule = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) =>
    z.object({ id: z.string().uuid(), enabled: z.boolean() }).parse(data),
  )
  .handler(async ({ data, context }) => {
    await context.supabase.from("schedules").update({ enabled: data.enabled }).eq("id", data.id);
    return { ok: true };
  });

export const deleteSchedule = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ id: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }) => {
    await context.supabase.from("schedules").delete().eq("id", data.id);
    return { ok: true };
  });

/** Fire a schedule immediately without waiting for its next window. */
export const runScheduleNow = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ id: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { executeScanById, nextRunFrom } = await import("./monitoring.server");

    const { data: schedule } = await supabase
      .from("schedules")
      .select("*")
      .eq("id", data.id)
      .single();
    if (!schedule) throw new Error("Schedule not found");

    const { data: scan, error } = await supabase
      .from("scans")
      .insert({
        user_id: userId,
        asset_id: schedule.asset_id,
        name: `${schedule.name} (scheduled)`,
        template: schedule.template,
        target: schedule.target,
        status: "queued",
        source: "schedule",
      })
      .select()
      .single();
    if (error || !scan) throw new Error(error?.message ?? "Could not queue scan");

    const result = await executeScanById(supabase, userId, scan.id);
    await supabase
      .from("schedules")
      .update({
        last_run_at: new Date().toISOString(),
        last_scan_id: scan.id,
        runs: (schedule.runs ?? 0) + 1,
        next_run_at: nextRunFrom(schedule.cadence),
      })
      .eq("id", schedule.id);

    return { scanId: scan.id, ...result };
  });
