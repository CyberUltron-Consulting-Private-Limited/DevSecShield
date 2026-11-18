// Badge and score-box classes of the CBOM findings tables, shared by the code-scan page (CbomResults.tsx) and the
// Sources run page so both tables look the same. Moved unchanged out of CbomResults.tsx (CB-38).

export function getImpactBadgeClass(impact: string): string {
  const i = (impact || "").toLowerCase();
  if (i === "critical") return "bg-red-600 hover:bg-red-700 text-white";
  if (i === "high") return "bg-orange-500 hover:bg-orange-600 text-white";
  if (i === "medium") return "bg-amber-500 hover:bg-amber-600 text-white";
  if (i === "low") return "bg-blue-500 hover:bg-blue-600 text-white";
  return "bg-zinc-500 hover:bg-zinc-600 text-white";
}

export function getFindingStatusBadgeClass(status: string): string {
  const s = (status ?? "").toLowerCase().replace(/\s/g, "_");
  if (s === "fixed") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
  if (s === "ignored") return "bg-zinc-100 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-200";
  if (s === "in_progress") return "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200";
  if (s === "not_started") return "bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300";
  return "bg-zinc-100 text-zinc-600 dark:bg-zinc-700/50 dark:text-zinc-300";
}

export function getStrengthBadgeClass(strength: string | undefined | null): string {
  const s = (strength ?? "").toLowerCase();
  if (s === "weak") return "border-red-500/50 text-red-600 dark:text-red-400";
  if (s === "moderate") return "border-amber-500/50 text-amber-600 dark:text-amber-400";
  if (s === "strong") return "border-emerald-500/50 text-emerald-600 dark:text-emerald-400";
  if (s === "quantum_safe") return "border-blue-500/50 text-blue-600 dark:text-blue-400";
  return "border-zinc-400/50 text-zinc-600 dark:text-zinc-400";
}

/** Risk score color tiers on the 0–10 scale (Critical ≥9, High 7–9, Medium 5–7, Low <5), matching SBOM/SAST/list page. */
export function getRiskScoreBoxClass(score: number | null | undefined): string {
  const s = score ?? 0;
  if (s >= 9) return "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200";
  if (s >= 7) return "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-200";
  if (s >= 5) return "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200";
  return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
}
