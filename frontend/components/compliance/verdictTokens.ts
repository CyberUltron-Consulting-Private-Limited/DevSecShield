import type { ComplianceVerdict } from "./types";

/** Single source for compliance verdict palette / badges / labels / stack order. */
export const VERDICT_COLOR: Record<ComplianceVerdict, string> = {
  pass: "#10b981", // emerald-500
  pass_with_evidence: "#14b8a6", // teal-500
  fail: "#dc2626", // red-600
  out_of_scope: "#64748b", // slate-500
  not_bom_evidenceable: "#8b5cf6", // violet-500
  na: "#a1a1aa", // zinc-400
};

export const VERDICT_BADGE: Record<ComplianceVerdict, string> = {
  pass: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
  pass_with_evidence:
    "bg-teal-100 text-teal-800 dark:bg-teal-900/40 dark:text-teal-200",
  fail: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200",
  out_of_scope:
    "bg-slate-100 text-slate-700 dark:bg-slate-700/50 dark:text-slate-200",
  not_bom_evidenceable:
    "bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200",
  na: "bg-zinc-100 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-200",
};

export const VERDICT_LABEL: Record<ComplianceVerdict, string> = {
  pass: "Pass",
  pass_with_evidence: "Pass (evidence)",
  fail: "Fail",
  out_of_scope: "Out of scope",
  not_bom_evidenceable: "Not BOM-evidenceable",
  na: "N/A",
};

export const VERDICT_ORDER: ComplianceVerdict[] = [
  "pass",
  "pass_with_evidence",
  "fail",
  "out_of_scope",
  "not_bom_evidenceable",
  "na",
];

export const isFailingVerdict = (v: ComplianceVerdict) =>
  v === "fail" || v === "not_bom_evidenceable";
