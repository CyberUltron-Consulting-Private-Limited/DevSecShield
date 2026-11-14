/**
 * One honest status for a certificate authority a scan node reads (AD CS, Vault, EJBCA): the newer of the last
 * connection test and the last collection (backend `last_collect`), and "Not checked since ..." once that result is
 * older than CA_STATUS_STALE_HOURS (owner bug C8, 14 Nov 2026: "Passed" two days after the server was gone, then
 * "Connected" next to "Failed"). Pure, so caCardStatus.test.ts pins every rule.
 */
import type { CbomTestStatus } from "@/utils/backend_api"

import type { Tone } from "./shared"

export const CA_STATUS_STALE_HOURS = 24

export interface CaLastCollect {
  status: "ok" | "partial" | "failed"
  at: string | null
  summary: string | null
  job_id: number
  run_id: number | null
}

export interface CaStatusInput {
  last_test_status: CbomTestStatus
  last_test_at: string | null
  last_test_summary: string | null
  last_collect?: CaLastCollect | null
}

export type CaStatusKind = "failed" | "error" | "stale" | "partial" | "testing" | "never" | "passed"

export interface CaCardStatus {
  kind: CaStatusKind
  tone: Tone
  label: string
  /** what the status is based on, with its time and the result's own summary */
  detail: string | null
  basis: "test" | "collection" | null
  at: string | null
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

/** "14 Nov 2026, 11:00 UTC": the same text on every browser and in every time zone */
export function formatUtc(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`
}

const RESULT: Record<"passed" | "partial" | "failed" | "error", [CaStatusKind, Tone, string]> = {
  passed: ["passed", "green", "Passed"],
  partial: ["partial", "amber", "Partly read"],
  failed: ["failed", "red", "Failed"],
  error: ["error", "amber", "Could not test"],
}

interface Result {
  kind: keyof typeof RESULT
  at: string
  ms: number
  summary: string | null
  basis: "test" | "collection"
}

function results(source: CaStatusInput): Result[] {
  const out: Result[] = []
  const t = source.last_test_status
  if ((t === "passed" || t === "partial" || t === "failed" || t === "error") && source.last_test_at) {
    const ms = Date.parse(source.last_test_at)
    if (!Number.isNaN(ms)) out.push({ kind: t, at: source.last_test_at, ms, summary: source.last_test_summary, basis: "test" })
  }
  const c = source.last_collect
  if (c?.at) {
    const ms = Date.parse(c.at)
    const kind = c.status === "ok" ? "passed" : c.status === "partial" ? "partial" : "failed"
    if (!Number.isNaN(ms)) out.push({ kind, at: c.at, ms, summary: c.summary, basis: "collection" })
  }
  return out
}

export function caCardStatus(source: CaStatusInput, now: Date = new Date(), staleHours = CA_STATUS_STALE_HOURS): CaCardStatus {
  if (source.last_test_status === "pending") {
    return { kind: "testing", tone: "blue", label: "Testing", detail: null, basis: "test", at: null }
  }
  const all = results(source)
  if (all.length === 0) return { kind: "never", tone: "zinc", label: "Not checked", detail: null, basis: null, at: null }
  // the newer result decides; on a tie the collection (it read more than a test does)
  const latest = all.reduce((a, b) => (b.ms > a.ms || (b.ms === a.ms && b.basis === "collection") ? b : a))
  const [kind, tone, label] = RESULT[latest.kind]
  const what = latest.basis === "test" ? "test" : "collection"
  const detail = `Last ${what}: ${label}, ${formatUtc(latest.at)}${latest.summary ? ` · ${latest.summary}` : ""}`
  if (now.getTime() - latest.ms > staleHours * 3600_000) {
    return { kind: "stale", tone: "amber", label: `Not checked since ${formatUtc(latest.at)}`, detail, basis: latest.basis, at: latest.at }
  }
  return { kind, tone, label, detail, basis: latest.basis, at: latest.at }
}

const ORDER: CaStatusKind[] = ["failed", "error", "stale", "partial", "testing", "never", "passed"]

/** The status a row of several sources shows: the worst one. */
export function worstCardStatus(list: CaCardStatus[]): CaCardStatus {
  if (list.length === 0) return { kind: "never", tone: "zinc", label: "Not checked", detail: null, basis: null, at: null }
  return list.reduce((a, b) => (ORDER.indexOf(b.kind) < ORDER.indexOf(a.kind) ? b : a))
}
