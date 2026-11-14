/**
 * The team never-scan list takes addresses and ranges only (PR #32 re-review 5876196533, NetworkTab.tsx:706): a typed
 * host name gets the settings API's own guidance inline, a save the API refuses puts its never-scan detail under the
 * field (not only in a toast), and a host name stored before the API refused them is marked on its row. Round 4
 * (re-review 5879769432): one template for the UI and the API, and names that are loopback by definition.
 * Run: npx --yes tsx components/cbom/sources/teamNeverScan.test.ts
 */
import assert from "node:assert/strict"

import {
  exclusionSaveError,
  HOST_NAME_NOT_ALLOWED,
  hostNameNotAllowed,
  isLoopbackName,
  LOOPBACK_NAMES,
  rangeError,
  readsAsHostName,
  SOURCE_NEVER_SCAN_HINT,
  storedExclusionIssue,
  teamExclusionError,
} from "./teamNeverScan"

const GUIDANCE = "the team never-scan list takes addresses and ranges only. List host names in a server source's own Never scan field"

// typed host names (and CIDR typos the server also reads as names) get the API's guidance, word for word
for (const name of ["printer.corp.invalid", "printer", "localhost", "bücher.corp", "web-01.corp.", "Web-01.Corp", "10.0.0.0-24", "0x0a000001"]) {
  const error = teamExclusionError(name)
  assert.equal(error, `${name} is not an address or range (it reads as a host name); ${GUIDANCE}`, name)
  assert.equal(error, hostNameNotAllowed(name))
}
// what is not a name keeps the precise range message
assert.equal(teamExclusionError("10.0.0.5/24"), "10.0.0.5/24 has host bits set; did you mean 10.0.0.0/24?")
assert.equal(teamExclusionError("10.0.0.9-10.0.0.1"), "10.0.0.9-10.0.0.1: the range ends before it starts")
assert.equal(teamExclusionError("*.corp"), "*.corp is not a valid IP address or CIDR range")
// addresses and ranges are accepted
for (const ok of ["10.20.99.0/24", "10.0.0.5", "10.0.1.1-10.0.1.9", "fd00::/64", "fd00::1-fd00::5", "::ffff:10.0.0.0/120"]) {
  assert.equal(teamExclusionError(ok), null, ok)
  assert.equal(rangeError(ok, false), null, ok)
}

// stored rows: a legacy host name is marked; addresses, ranges and zone ids the server accepted are not
assert.ok(readsAsHostName("printer.corp.invalid") && readsAsHostName("printer"))
for (const legacy of ["printer.corp.invalid", "printer", "xn--bcher-kva.corp"]) {
  const issue = storedExclusionIssue(legacy)
  assert.ok(issue && issue.includes("holds every job of this team") && issue.includes("Remove it"), legacy)
}
for (const fine of ["10.20.99.0/24", "10.0.0.5", "fd00::1-fd00::5", "fe80::1%br-ab12", "fe80::1%eth0", "2001:db8::/48"]) {
  assert.equal(storedExclusionIssue(fine), null, fine)
}

// a refused save: the never-scan part of the server's detail goes inline; anything else does not
const refused = (status: number, detail: unknown) => ({ response: { status, data: { detail } } })
const detail = `network_exclusions: printer.corp.invalid is not an address or range (it reads as a host name); ${GUIDANCE}`
assert.equal(exclusionSaveError(refused(422, detail)), detail.slice("network_exclusions: ".length))
assert.equal(exclusionSaveError(refused(400, "network_exclusions: Never-scan line 1: '10.0.0.0/33' is not a valid IP address or CIDR range")),
  "Never-scan line 1: '10.0.0.0/33' is not a valid IP address or CIDR range")
assert.equal(exclusionSaveError(refused(400, "soc_email: not an email address")), null)
assert.equal(exclusionSaveError(refused(409, detail)), null)
assert.equal(exclusionSaveError(refused(422, [{ loc: ["body"], msg: "x" }])), null)
assert.equal(exclusionSaveError(new Error("network down")), null)
assert.equal(exclusionSaveError(null), null)

// one template for the UI and the API (re-review 5879769432): the entry as typed, trimmed, unquoted; the backend test
// test_never_scan_node_agreement.py compares HOST_NAME_NOT_ALLOWED with the API's own template
assert.equal(HOST_NAME_NOT_ALLOWED, `{entry} is not an address or range (it reads as a host name); ${GUIDANCE}`)
assert.equal(hostNameNotAllowed("  Printer.Corp.  "), `Printer.Corp. is not an address or range (it reads as a host name); ${GUIDANCE}`)
assert.equal(hostNameNotAllowed("a$&b"), `a$&b is not an address or range (it reads as a host name); ${GUIDANCE}`) // no replace() patterns

// names that are loopback by definition: the node blocks only 127.0.0.0/8 and ::1 for them and holds nothing
for (const name of ["localhost", "LOCALHOST.", " db.localhost ", "a.b.localhost", "ip6-localhost", "ip6-loopback", "localhost.localdomain",
  "localhost4", "localhost4.localdomain4", "localhost6", "localhost6.localdomain6"]) {
  assert.equal(isLoopbackName(name), true, name)
}
for (const name of ["localhost.corp", "notlocalhost", "localhostx", "my-localhost", "ip6-localnet", "localhost5", "x.localhost.corp", "127.0.0.1"]) {
  assert.equal(isLoopbackName(name), false, name)
}
assert.equal(LOOPBACK_NAMES.size, 8)
// a stored loopback name in the team list is marked too (the API refuses it there), but its note says what the node does
const loopbackIssue = storedExclusionIssue("localhost")
assert.ok(loopbackIssue && loopbackIssue.includes("only keeps the loopback addresses (127.0.0.0/8 and ::1) out; nothing is held"), loopbackIssue ?? "")
assert.ok(!loopbackIssue!.includes("holds every job"))
assert.equal(storedExclusionIssue("ip6-localhost"), loopbackIssue)
assert.ok(storedExclusionIssue("printer")!.includes("holds every job of this team"))
// the hint of a server source's own list says it too (rendered by ServersTab: neverScanRender.test.ts)
assert.ok(SOURCE_NEVER_SCAN_HINT.includes("are not looked up: they cover only 127.0.0.0/8 and ::1"))

// the Network tab and the Servers tab are tested rendered, as a customer uses them: neverScanRender.test.ts
console.log("team never-scan tests passed")
