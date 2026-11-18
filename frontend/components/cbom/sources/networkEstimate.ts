// Network TLS tab: what "Before the first run" and a range's last test say (owner bug list 14 Nov 2026).
// N7: the estimate is the API's network_totals (planning.network_sweep_totals): unique addresses after the never-scan
//     list over ENABLED ranges, so a disabled range and an address in two overlapping ranges are not counted (the tab
//     used to add every range's own count: 510 for ranges the nodes sweep at most ~252 of).
// N9: a range's connection test probes up to 25 addresses spread over the range; the readiness label says how many.

import type { CbomSource, CbomTestStatus } from "@/utils/backend_api"

import { pluralize } from "./logic"

export interface NetworkTotals {
  addresses: number
  ranges_enabled: number
  ranges_disabled: number
}

/** The API's totals; for an API that predates them, the enabled ranges' own counts (an overlap may count twice). */
export function sweepTotals(ranges: CbomSource[], totals?: NetworkTotals | null): NetworkTotals {
  if (totals) return totals
  const enabled = ranges.filter((r) => r.enabled)
  return {
    addresses: enabled.reduce((sum, r) => sum + (r.target_count || 0), 0),
    ranges_enabled: enabled.length,
    ranges_disabled: ranges.length - enabled.length,
  }
}

export function totalsLine(t: NetworkTotals, ports: number): string {
  const disabled = t.ranges_disabled
    ? ` ${pluralize(t.ranges_disabled, "disabled range")} ${t.ranges_disabled === 1 ? "is" : "are"} not counted.`
    : ""
  return (
    `${pluralize(t.addresses, "unique address", "unique addresses")} across ${pluralize(t.ranges_enabled, "enabled range")} ` +
    `after the never-scan list, ${pluralize(ports, "port")}.${disabled}`
  )
}

const ANSWERED = new Set(["ready", "ok", "passed"])

/** "18 of 25 sampled" for a finished range test, from the samples the node probed; null when there are none. */
export function sampleDetail(status: CbomTestStatus, result: CbomSource["last_test_result"] | null | undefined): string | null {
  if (status !== "passed" && status !== "partial" && status !== "failed") return null
  const samples = (result?.samples ?? []).filter((s) => s && s.target && s.target !== "-")
  if (samples.length === 0) return null
  const answered = samples.filter((s) => ANSWERED.has(String(s.status))).length
  return `${answered} of ${samples.length} sampled`
}
