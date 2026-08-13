import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { ReportGenerator } from "./report-generator";
import { ReportFormat, ReportKind } from "./types/enterprise";

const reportInput = z.object({
  title: z.string().min(1).max(120),
  kind: z.enum(["executive", "technical", "asset", "compliance"]).default("executive"),
  format: z.enum(["pdf", "csv", "json"]).default("pdf"),
});

export const listReports = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data, error } = await supabase
      .from("reports")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });
    if (error) throw new Error(error.message);
    return data ?? [];
  });

export const generateReport = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => reportInput.parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId, userEmail } = context;

    // Fetch live data to generate report
    const [findingsRes, assetsRes, scansRes] = await Promise.all([
      supabase
        .from("findings")
        .select("*, assets(id, name, target, criticality)")
        .eq("user_id", userId)
        .order("priority", { ascending: false }),
      supabase
        .from("assets")
        .select("*")
        .eq("user_id", userId)
        .order("risk_score", { ascending: false }),
      supabase
        .from("scans")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(20),
    ]);

    const findings = findingsRes.data ?? [];
    const assets = assetsRes.data ?? [];
    const scans = scansRes.data ?? [];

    // Generate output file
    const generated = ReportGenerator.generate({
      title: data.title,
      kind: data.kind as ReportKind,
      format: data.format as ReportFormat,
      findings,
      assets,
      scans,
      userEmail,
    });

    const summary = {
      findings_count: findings.length,
      critical_count: findings.filter((f) => f.severity === 4).length,
      high_count: findings.filter((f) => f.severity === 3).length,
      assets_count: assets.length,
      generated_by: userEmail || "Security Analyst",
    };

    // Save record to DB
    const { data: reportRow, error } = await supabase
      .from("reports")
      .insert({
        user_id: userId,
        title: data.title,
        kind: data.kind,
        format: data.format,
        status: "completed",
        summary: summary as never,
        file_size_bytes: generated.content.length,
      })
      .select("*")
      .single();

    if (error) throw new Error(error.message);

    return {
      report: reportRow,
      content: generated.content,
      mimeType: generated.mimeType,
      fileName: generated.fileName,
    };
  });

export const deleteReport = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await supabase.from("reports").delete().eq("id", data.id).eq("user_id", userId);
    return { ok: true };
  });
