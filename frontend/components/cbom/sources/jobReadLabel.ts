// The status label of one collection job in a run ("Partly read · 11 read, 2 gaps").  Pure, so it is unit tested.
//
// C4: the label used to come from the TARGET counts alone, so an Azure subscription (one target) that read 11 assets
// while two vaults refused their keys said "Nothing read · 0 read".  What was read is the job's assets (coverage rows
// excluded: `assets_read`) and what was not is its gaps (places not fully read: `gaps`); both come from the run API.

type LabelTone = "green" | "red" | "amber" | "blue" | "zinc";

export interface JobReadInput {
  status: string;
  outcome: "ok" | "partial" | "failed" | null;
  asset_count: number;
  assets_read?: number | null;
  gaps?: number | null;
  counts: { total?: number; ok?: number; partial?: number; failed?: number; skipped?: number } | null;
  targets: { status: string }[];
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** [tone, label] of the job's badge. */
export function jobReadLabel(job: JobReadInput): [LabelTone, string] {
  if (!job.outcome) return ["blue", job.status === "pending" ? "Waiting" : "Running"];
  const read = typeof job.assets_read === "number" ? job.assets_read : null;
  const gaps = typeof job.gaps === "number" ? job.gaps : null;
  // a job stored before the outcome counted assets: something was read, so it was never "Nothing read"
  const outcome = job.outcome === "failed" && read !== null && read > 0 ? "partial" : job.outcome;
  const problems = job.targets.filter((t) => t.status !== "ok").length;
  const gapText = gaps !== null && gaps > 0 ? plural(gaps, "gap") : null;
  if (outcome === "ok") {
    const base: [LabelTone, string] = problems > 0 || gapText ? ["amber", "Read, with errors"] : ["green", "All targets read"];
    if (read === null) return base;
    return [base[0], `${base[1]} · ${read} read${gapText ? `, ${gapText}` : ""}`];
  }
  if (outcome === "partial") {
    if (read === null) return ["amber", "Partly read"];
    return ["amber", `Partly read · ${read} read${gapText ? `, ${gapText}` : ""}`];
  }
  if (outcome === "failed") return ["red", gapText ? `Nothing read · ${gapText}` : "Nothing read"];
  return ["zinc", outcome];
}

/** The line under the badge: the TARGET counts, named as targets so they are never read as asset counts. */
export function jobTargetsLine(job: JobReadInput): string | null {
  const c = job.counts;
  if (!c) return null;
  const parts = [`${c.ok ?? 0} fully read`];
  if (c.partial) parts.push(`${c.partial} partly read`);
  parts.push(`${c.failed ?? 0} failed`, `${c.skipped ?? 0} skipped`);
  return `Targets: ${parts.join(" · ")} of ${c.total ?? 0}`;
}
