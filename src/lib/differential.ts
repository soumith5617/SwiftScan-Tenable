/**
 * Differential scanning.
 *
 * A differential run compares the current detection set against the most recent
 * completed scan of the same target and reports only what changed, so repeat
 * assessments cost a fraction of a full run and the delta is explicit.
 */
export type Fingerprintable = {
  plugin_id: string;
  port?: number | null | undefined;
  service?: string | null | undefined;
  cve_ids?: string[] | null | undefined;
  title: string;
};

export function fingerprint(f: Fingerprintable): string {
  const cve = (f.cve_ids ?? []).slice().sort().join(",");
  return [f.plugin_id, f.port ?? "-", f.service ?? "-", cve || f.title.slice(0, 60)].join("|");
}

export type DiffResult<T extends Fingerprintable> = {
  added: T[];
  unchanged: T[];
  resolvedFingerprints: string[];
  baselineCount: number;
};

export function diffFindings<T extends Fingerprintable>(
  current: T[],
  baseline: Fingerprintable[],
): DiffResult<T> {
  const baseSet = new Set(baseline.map(fingerprint));
  const currentSet = new Set(current.map(fingerprint));
  const added: T[] = [];
  const unchanged: T[] = [];
  for (const f of current) (baseSet.has(fingerprint(f)) ? unchanged : added).push(f);
  const resolvedFingerprints = [...baseSet].filter((fp) => !currentSet.has(fp));
  return { added, unchanged, resolvedFingerprints, baselineCount: baseSet.size };
}

/** Find the most recent completed scan for a target to diff against. */
export async function findBaselineScan(
  supabase: {
    from: (t: string) => {
      select: (c: string) => {
        eq: (
          c: string,
          v: unknown,
        ) => {
          eq: (
            c: string,
            v: unknown,
          ) => {
            neq: (
              c: string,
              v: unknown,
            ) => {
              order: (
                c: string,
                o: { ascending: boolean },
              ) => {
                limit: (n: number) => {
                  maybeSingle: () => Promise<{ data: { id: string } | null }>;
                };
              };
            };
          };
        };
      };
    };
  },
  userId: string,
  target: string,
  excludeScanId: string,
): Promise<string | null> {
  const { data } = await supabase
    .from("scans")
    .select("id")
    .eq("user_id", userId)
    .eq("target", target)
    .neq("id", excludeScanId)
    .order("finished_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  return data?.id ?? null;
}
