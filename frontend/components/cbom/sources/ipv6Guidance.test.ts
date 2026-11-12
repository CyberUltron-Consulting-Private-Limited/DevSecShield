/**
 * CB-08: an IPv6 target read through a scan node without IPv6 shows "No route" with the node's reason "IPv6 is not
 * available on this scan node" (scan_node/zs_scan_node/tlsprobe.py connect_error), and nothing told the customer what
 * to do: the default `docker run` from the wizard puts the node on Docker's IPv4-only bridge. Run results now add the
 * fix under the reason.
 * Run: npx --yes tsx components/cbom/sources/ipv6Guidance.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import * as logic from "./logic"

const results = fs.readFileSync(path.join(__dirname, "RunResults.tsx"), "utf8")
const probe = fs.readFileSync(path.join(__dirname, "../../../../scan_node/zs_scan_node/tlsprobe.py"), "utf8")
assert.ok(probe.includes('return ProbeError("no_route", "IPv6 is not available on this scan node")'),
  "the node's reason this guidance answers")

const { IPV6_NO_ROUTE_GUIDANCE, targetGuidance } = logic as unknown as {
  IPV6_NO_ROUTE_GUIDANCE: string
  targetGuidance: (status: string, error: string | null | undefined, target: string) => string | null
}
assert.match(IPV6_NO_ROUTE_GUIDANCE, /IPv6 route/)
assert.match(IPV6_NO_ROUTE_GUIDANCE, /--ipv6/)
assert.match(IPV6_NO_ROUTE_GUIDANCE, /dual-stack/)
// the node's IPv6 reason, or an IPv6 address with no route
assert.equal(targetGuidance("no_route", "IPv6 is not available on this scan node", "[fd00:cb::17]:443"), IPV6_NO_ROUTE_GUIDANCE)
assert.equal(targetGuidance("no_route", "OSError", "fd00:cb::17"), IPV6_NO_ROUTE_GUIDANCE)
assert.equal(targetGuidance("no_route", null, "2001:db8::5:443"), IPV6_NO_ROUTE_GUIDANCE)
// IPv4 and other statuses: no IPv6 advice
assert.equal(targetGuidance("no_route", "OSError", "10.231.0.17:443"), null)
assert.equal(targetGuidance("no_route", "OSError", "app.example.com"), null)
assert.equal(targetGuidance("timeout", "connect timed out", "[fd00:cb::17]:443"), null)
assert.equal(targetGuidance("ok", null, "[fd00:cb::17]:443"), null)
// review 5876424957: a host name whose only address is IPv6 (the node's reason says so), and a bracketed address with
// a generic error
assert.equal(targetGuidance("no_route", "IPv6 is not available on this scan node", "v6only.example:443"), IPV6_NO_ROUTE_GUIDANCE)
assert.equal(targetGuidance("no_route", "OSError", "[fd00::1]:443"), IPV6_NO_ROUTE_GUIDANCE)

// rendered: the run results' target row shows the reason and the guidance under it
async function rendered() {
  const { createElement: h } = await import("react")
  const { renderToStaticMarkup } = await import("react-dom/server")
  const { TargetProblemRow } = await import("./RunResults")
  const row = (t: { target: string; status: string; error: string | null }) =>
    renderToStaticMarkup(h("ul", null, h(TargetProblemRow, { t }))).replace(/<[^>]+>/g, " ")
  const v6 = row({ target: "[fd00:cb::17]:443", status: "no_route", error: "IPv6 is not available on this scan node" })
  assert.ok(v6.includes("No route") && v6.includes("IPv6 is not available on this scan node") && v6.includes("Give the scan node an IPv6 route"), v6)
  const v4 = row({ target: "10.231.0.17:443", status: "no_route", error: "OSError" })
  assert.ok(v4.includes("No route") && !v4.includes("IPv6 route"), v4)
  assert.ok(results.includes("<TargetProblemRow"), "the targets list renders this row")
  console.log("ipv6 guidance tests passed")
}
rendered().catch((err) => {
  console.error(err)
  process.exit(1)
})
