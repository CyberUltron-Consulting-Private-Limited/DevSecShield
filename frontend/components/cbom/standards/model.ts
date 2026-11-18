// Standards status per asset (CB-16): the asset detail's `standards` rows, as the API sends them
// (backend/utilities/cbom_sources/standards.py `rows`): FIPS 203/204/205, NSA CNSA 2.0, NIST SP 800-131A.

export type StandardId = "fips_203_204_205" | "cnsa_2_0" | "sp800_131a"

export type StandardRow = {
  id: StandardId | string
  label: string
  status: string
  reasons: string[]
  standard?: string  // FIPS 203/204/205 when approved: the standards met ("FIPS 203")
  category?: number  // and the lowest NIST category of the approved parts
}

/** The status as a reader says it; an unseen status is printed as it came. */
export const STATUS_TEXT: Record<string, string> = {
  approved: "Approved",
  not_approved: "Not approved",
  compliant: "Compliant",
  not_compliant: "Not compliant",
  acceptable: "Acceptable",
  disallowed: "Disallowed",
  unknown: "Unknown",
  not_applicable: "Not applicable",
}

export type StandardTone = "pass" | "fail" | "unknown" | "na"

export function statusTone(status: string): StandardTone {
  if (status === "approved" || status === "compliant" || status === "acceptable") return "pass"
  if (status === "not_approved" || status === "not_compliant" || status === "disallowed") return "fail"
  if (status === "not_applicable") return "na"
  return "unknown"  // "unknown" and any status this UI has not seen: never shown as a pass
}

export function statusText(row: Pick<StandardRow, "status" | "standard" | "category">): string {
  const base = STATUS_TEXT[row.status] ?? row.status
  if (row.status === "approved" && row.standard && row.category) return `${base}: ${row.standard} category ${row.category}`
  return base
}

export const TONE_CLASS: Record<StandardTone, string> = {
  pass: "bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950 dark:text-emerald-200 dark:border-emerald-800",
  fail: "bg-red-50 text-red-800 border-red-200 dark:bg-red-950 dark:text-red-200 dark:border-red-800",
  unknown: "bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950 dark:text-amber-200 dark:border-amber-800",
  na: "bg-zinc-50 text-zinc-600 border-zinc-200 dark:bg-zinc-900 dark:text-zinc-400 dark:border-zinc-700",
}
