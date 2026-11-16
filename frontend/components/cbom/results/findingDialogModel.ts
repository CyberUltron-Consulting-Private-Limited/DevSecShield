// Pure helpers of the Sources-run finding dialog (results redesign F7–F10): the severity frame and chips, the risk
// ring, the location table, the numbered suggested-fix steps, the compliance-control framework cards and the issue
// rows. No React; tested in findingDialogModel.test.ts.

import type { KbFindingDetail } from "@/utils/backend_api";

export type SeverityTone = "critical" | "high" | "medium" | "low" | "info";

export function severityTone(impact: string | null | undefined): SeverityTone {
  switch ((impact ?? "").toLowerCase()) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "info";
  }
}

/** The dialog frame's severity-tinted top edge (and left edge from 640 px), light and dark. */
export const FRAME_CLASS: Record<SeverityTone, string> = {
  critical: "border-t-4 max-sm:border-t-4 border-t-red-500 sm:border-l-4 sm:border-l-red-500/50 dark:border-t-red-500 dark:sm:border-l-red-500/40",
  high: "border-t-4 max-sm:border-t-4 border-t-orange-500 sm:border-l-4 sm:border-l-orange-500/50 dark:border-t-orange-500 dark:sm:border-l-orange-500/40",
  medium: "border-t-4 max-sm:border-t-4 border-t-amber-400 sm:border-l-4 sm:border-l-amber-400/60 dark:border-t-amber-400 dark:sm:border-l-amber-400/40",
  low: "border-t-4 max-sm:border-t-4 border-t-blue-500 sm:border-l-4 sm:border-l-blue-500/50 dark:border-t-blue-400 dark:sm:border-l-blue-400/40",
  info: "border-t-4 max-sm:border-t-4 border-t-zinc-300 sm:border-l-4 sm:border-l-zinc-300 dark:border-t-zinc-600 dark:sm:border-l-zinc-600",
};

/** Solid chips of the header (25-B). */
export const IMPACT_CHIP_CLASS: Record<SeverityTone, string> = {
  critical: "bg-red-600 text-white dark:bg-red-500",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-zinc-900",
  low: "bg-blue-600 text-white dark:bg-blue-500",
  info: "bg-zinc-600 text-white dark:bg-zinc-600",
};
export const NEUTRAL_CHIP_CLASS = "bg-zinc-700 text-white dark:bg-zinc-700 dark:text-zinc-50";

/** The risk ring's stroke (same bands as the risk score boxes: 9+ critical, 7+ high, 4+ medium). */
export function riskRingClass(score: number | null | undefined): string {
  if (typeof score !== "number") return "stroke-zinc-300 dark:stroke-zinc-600";
  if (score >= 9) return "stroke-red-500";
  if (score >= 7) return "stroke-orange-500";
  if (score >= 4) return "stroke-amber-400";
  return "stroke-emerald-500";
}

/** 0..1 of the ring that is filled (the score is 0–10). */
export function riskRingFraction(score: number | null | undefined): number {
  if (typeof score !== "number" || !Number.isFinite(score)) return 0;
  return Math.min(1, Math.max(0, score / 10));
}

const HOST_PORT = /^(\[[^\]]+\]|[^\s/:#[\]]+):(\d{1,5})(?=$|[#\s/;,])(.*)$/;

/** The location table (19-C): target, then host and port and what follows them when the stored location starts with
 * `host:port`. Never replaces the stored string, which the dialog prints under the table as it is. */
export function locationRows(item: { location: string; target?: string | null }): [string, string][] {
  const rows: [string, string][] = [];
  if (item.target && item.target !== item.location) rows.push(["Target", item.target]);
  const m = HOST_PORT.exec(item.location.trim());
  if (m) {
    if (!item.target || item.target !== m[1]) rows.push(["Host", m[1]]);
    rows.push(["Port", m[2]]);
    const rest = m[3].replace(/^[#\s/;,]+/, "").trim();
    if (rest) rows.push(["Detail", rest]);
  }
  return rows;
}

/** Suggested fix as numbered steps (21-B): each issue's stored fix once, in issue order; the row's own suggested fix
 * leads when it is not one of them; with no issues, the single suggested fix. */
export function fixSteps(details: Pick<KbFindingDetail, "remediation">[] | null | undefined, suggestedFix: string | null): string[] {
  const steps: string[] = [];
  for (const d of details ?? []) {
    const s = d.remediation?.summary?.trim();
    if (s && !steps.includes(s)) steps.push(s);
  }
  if (suggestedFix && !steps.includes(suggestedFix.trim())) steps.unshift(suggestedFix.trim());
  return steps;
}

/** Compliance controls grouped by framework (22-C): "ISO 27001 - A.10 Cryptography" goes under "ISO 27001". */
export function controlGroups(controls: [string, string][], labels: Record<string, string>): { framework: string; items: { key: string; label: string }[] }[] {
  const groups = new Map<string, { key: string; label: string }[]>();
  for (const [key, value] of controls) {
    const label = labels[key] ?? value;
    const cut = label.indexOf(" - ");
    const framework = cut > 0 ? label.slice(0, cut) : "Other controls";
    const short = cut > 0 ? label.slice(cut + 3) : label;
    if (!groups.has(framework)) groups.set(framework, []);
    groups.get(framework)!.push({ key, label: short });
  }
  return [...groups].map(([framework, items]) => ({ framework, items }));
}

/** One row per knowledge-base issue of the asset (20-B), in the detail's order. */
export function issueRows(details: Pick<KbFindingDetail, "code" | "title" | "observed">[] | null | undefined): { code: string; title: string; observed: string | null }[] {
  return (details ?? []).map((d) => ({ code: d.code, title: d.title, observed: d.observed ?? null }));
}

/** Codes tied to their issues for "Where it came from" (23-E): every finding code of the row, with its issue title
 * when the knowledge base knows it. */
export function evidenceCodes(codes: readonly string[], details: Pick<KbFindingDetail, "code" | "title">[] | null | undefined): { code: string; title: string | null }[] {
  const title = new Map((details ?? []).map((d) => [d.code, d.title] as const));
  const all = [...new Set([...codes, ...(details ?? []).map((d) => d.code)])];
  return all.map((code) => ({ code, title: title.get(code) ?? null }));
}
