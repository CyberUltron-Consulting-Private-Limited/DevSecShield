// CB-29: which crypto-library advisory data a code scan matched (the run's `advisory_data`: the offline OSV snapshot's
// version and date, stale or not, refreshed online or not). Pure; tested with tsx.

export interface AdvisoryData {
  source?: string;
  snapshot_version?: string;
  generated_at?: string | null;
  age_days?: number | null;
  max_age_days?: number | null;
  stale?: boolean;
  origin?: string;
  online?: { asked?: number; answered?: number } | null;
}

export function readAdvisoryData(...candidates: unknown[]): AdvisoryData | null {
  for (const c of candidates) {
    const v = c && typeof c === "object" ? (c as Record<string, unknown>).advisory_data : null;
    if (v && typeof v === "object" && typeof (v as AdvisoryData).generated_at === "string") return v as AdvisoryData;
  }
  return null;
}

/** "Library advisories: OSV snapshot 2026.11.14.1, data as of 2026-11-14 (3 days old)". */
export function advisoryLine(d: AdvisoryData): string {
  const age = typeof d.age_days === "number" ? ` (${d.age_days} day${d.age_days === 1 ? "" : "s"} old)` : "";
  let text = `Library advisories: OSV snapshot ${d.snapshot_version || "?"}, data as of ${d.generated_at}${age}`;
  if (d.online) text += `; refreshed online for ${d.online.answered ?? 0} of ${d.online.asked ?? 0} package(s)`;
  return text;
}

/** The warning under a stale snapshot, or null when it is fresh. */
export function staleNote(d: AdvisoryData): string | null {
  if (!d.stale) return null;
  return `The advisory data is older than ${d.max_age_days ?? 30} days: newer library vulnerabilities may be missing. `
    + "Load a newer snapshot (CBOM_OSV_SNAPSHOT or CBOM_OSV_SNAPSHOT_URL), or allow online refresh (CBOM_OSV_ONLINE=1).";
}
