/**
 * The team never-scan list takes addresses, ranges and host names (N2, 14 Nov 2026: a host name listed there must keep
 * the host out of range sweeps too; the node resolves it). A mistyped range that only reads as a name is still refused,
 * a stored name says on its row what the node does with it, and a save the API refuses puts its never-scan detail
 * under the field. Names that are loopback by definition only keep the loopback out (re-review 5879769432).
 * Run: npx --yes tsx components/cbom/sources/teamNeverScan.test.ts
 */
import assert from "node:assert/strict"

import {
  ADDRESS_TYPO,
  heldFor,
  heldNote,
  exclusionSaveError,
  isLoopbackName,
  LOOPBACK_NAMES,
  RANGE_HINT,
  rangeError,
  readsAsHostName,
  SOURCE_NEVER_SCAN_HINT,
  storedExclusionIssue,
  teamExclusionError,
} from "./teamNeverScan"

// typed host names are accepted (the node resolves them; fail closed until they resolve)
for (const name of ["printer.corp.invalid", "printer", "localhost", "bücher.corp", "web-01.corp.", "Web-01.Corp", "shop.lab"]) {
  assert.equal(teamExclusionError(name), null, name)
}
// a mistyped address or range is not a host name: it gets the precise range message
for (const typo of ["10.0.0.0-24", "0x0a000001", "10.20.0.0/24-25"]) {
  assert.ok(ADDRESS_TYPO.test(typo) || rangeError(typo, false) !== null, typo)
  assert.notEqual(teamExclusionError(typo), null, typo)
}
assert.equal(teamExclusionError("10.0.0.0-24"), "10.0.0.0-24 is not a valid address range")
// what is not a name keeps the precise range message
assert.equal(teamExclusionError("10.0.0.5/24"), "10.0.0.5/24 has host bits set; did you mean 10.0.0.0/24?")
assert.equal(teamExclusionError("10.0.0.9-10.0.0.1"), "10.0.0.9-10.0.0.1: the range ends before it starts")
assert.equal(teamExclusionError("*.corp"), "*.corp is not a valid IP address or CIDR range")
// addresses and ranges are accepted
for (const ok of ["10.20.99.0/24", "10.0.0.5", "10.0.1.1-10.0.1.9", "fd00::/64", "fd00::1-fd00::5", "::ffff:10.0.0.0/120"]) {
  assert.equal(teamExclusionError(ok), null, ok)
  assert.equal(rangeError(ok, false), null, ok)
}

// stored rows: a host name says what the node does with it; addresses, ranges and zone ids get no note
assert.ok(readsAsHostName("printer.corp.invalid") && readsAsHostName("printer"))
for (const name of ["printer.corp.invalid", "printer", "xn--bcher-kva.corp"]) {
  const issue = storedExclusionIssue(name)
  assert.ok(issue && issue.includes("never connects to any address it answers, in range sweeps too"), name)
  assert.ok(issue!.includes("every job of this team waits"), name)
  assert.ok(!issue!.includes("refused"), name) // no longer refused on save
}
for (const fine of ["10.20.99.0/24", "10.0.0.5", "fd00::1-fd00::5", "fe80::1%br-ab12", "fe80::1%eth0", "2001:db8::/48"]) {
  assert.equal(storedExclusionIssue(fine), null, fine)
}

// a refused save: the never-scan part of the server's detail goes inline; anything else does not
const refused = (status: number, detail: unknown) => ({ response: { status, data: { detail } } })
const detail = "network_exclusions: 10.0.0.0-24 is not a valid IP address or CIDR range (it reads as a mistyped address, not a host name)"
assert.equal(exclusionSaveError(refused(400, detail)), detail.slice("network_exclusions: ".length))
assert.equal(exclusionSaveError(refused(400, "network_exclusions: Never-scan line 1: '10.0.0.0/33' is not a valid IP address or CIDR range")),
  "Never-scan line 1: '10.0.0.0/33' is not a valid IP address or CIDR range")
assert.equal(exclusionSaveError(refused(400, "soc_email: not an email address")), null)
assert.equal(exclusionSaveError(refused(409, detail)), null)
assert.equal(exclusionSaveError(refused(422, [{ loc: ["body"], msg: "x" }])), null)
assert.equal(exclusionSaveError(new Error("network down")), null)
assert.equal(exclusionSaveError(null), null)

// Minor 2: a held name, per node, matched to its stored entry (case and a trailing dot aside)
const held = [{ name: "shop.lab", node_id: 1, node_name: "dc-1" }, { name: "shop.lab", node_id: 2, node_name: "dc-2" }, { name: "pay.lab", node_id: 1, node_name: "dc-1" }]
assert.deepEqual(heldFor("Shop.Lab.", held).map((h) => h.node_name), ["dc-1", "dc-2"])
assert.deepEqual(heldFor("10.0.0.0/24", held), [])
assert.deepEqual(heldFor("shop.lab", undefined), [])
assert.equal(heldNote("dc-1", "14 Nov, 08:30"), "dc-1 cannot resolve this name (since 14 Nov, 08:30), so it scans no network address for this team: every job of the team on dc-1 that connects to an address (servers, appliances, databases, registries, range sweeps) holds all its targets until the name resolves there or is removed from this list. Jobs that reach no address, such as a PKCS#11 token on the node, still run.")

// N3: the range form says which addresses a range scans (the node and the backend count the same)
assert.ok(RANGE_HINT.includes("skipped only at the edges of the network your ranges form together, disabled ranges included"))
assert.ok(RANGE_HINT.includes("a /24 split into two /25s still scans .127 and .128; a subnet on its own skips its own"))

// names that are loopback by definition: the node blocks only 127.0.0.0/8 and ::1 for them and holds nothing
for (const name of ["localhost", "LOCALHOST.", " db.localhost ", "a.b.localhost", "ip6-localhost", "ip6-loopback", "localhost.localdomain",
  "localhost4", "localhost4.localdomain4", "localhost6", "localhost6.localdomain6"]) {
  assert.equal(isLoopbackName(name), true, name)
}
for (const name of ["localhost.corp", "notlocalhost", "localhostx", "my-localhost", "ip6-localnet", "localhost5", "x.localhost.corp", "127.0.0.1"]) {
  assert.equal(isLoopbackName(name), false, name)
}
assert.equal(LOOPBACK_NAMES.size, 8)
// a stored loopback name in the team list says what the node does with it: only the loopback, never looked up
const loopbackIssue = storedExclusionIssue("localhost")
assert.ok(loopbackIssue && loopbackIssue.includes("keeps only the loopback addresses (127.0.0.0/8 and ::1) out"), loopbackIssue ?? "")
assert.ok(loopbackIssue!.includes("nothing is held") && !loopbackIssue!.includes("every job of this team waits"))
assert.equal(storedExclusionIssue("ip6-localhost"), loopbackIssue)
assert.ok(storedExclusionIssue("printer")!.includes("every job of this team waits"))
// the hint of a server source's own list says it too (rendered by ServersTab: neverScanRender.test.ts)
assert.ok(SOURCE_NEVER_SCAN_HINT.includes("are not looked up: they cover only 127.0.0.0/8 and ::1"))
// #17: a name is skipped with every address it resolves to; the range limit is stated, with what covers it
assert.ok(SOURCE_NEVER_SCAN_HINT.includes("skipped, with every address it resolves to"))
assert.ok(SOURCE_NEVER_SCAN_HINT.includes("list such a host by name or by both addresses"))

// the Network tab and the Servers tab are tested rendered, as a customer uses them: neverScanRender.test.ts
console.log("team never-scan tests passed")
