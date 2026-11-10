/**
 * Lab UI r1 F1: Edit from the Servers / Databases table left the page at the table. Radix returns focus to the row
 * menu's trigger ~150 ms after the item is chosen, and that focus() cancelled the smooth scroll to the form. The row
 * menus now skip that focus return when an item moves to a section, and reveal the section from onCloseAutoFocus:
 * first field focused with preventScroll, then the smooth scroll.
 * Browser check after a rebuild: r1 bin/run edit_scroll3.js (tab=servers, then ctx.tab="k8s-db"; ctx.name=<db row>):
 * no focus() on "Actions for ..." after the click, the form's top ends near 0.
 * Run: npx --yes tsx components/cbom/sources/reveal.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { FIRST_FIELD, FIRST_FOCUSABLE, menuReveal, revealSection, type Focusable, type Revealable } from "./reveal"

type Call = [string, unknown]

function fakeSection(fields: Record<string, string | null>, calls: Call[]): Revealable {
  const focusable = (name: string): Focusable => ({ focus: (o) => calls.push([`focus ${name}`, o]) })
  return {
    scrollIntoView: (o) => calls.push(["scrollIntoView", o]),
    querySelector: (sel) => (fields[sel] ? focusable(fields[sel] as string) : null),
  }
}

// revealSection: first field focused without scrolling, then the smooth scroll (the order matters: a focus() after
// the scroll started is what cancelled it)
{
  const calls: Call[] = []
  assert.equal(revealSection(fakeSection({ [FIRST_FIELD]: "name", [FIRST_FOCUSABLE]: "button" }, calls)), true)
  assert.deepEqual(calls, [
    ["focus name", { preventScroll: true }],
    ["scrollIntoView", { behavior: "smooth", block: "start" }],
  ])
}
// read-only section (the "Register again" wizard): the first focusable control
{
  const calls: Call[] = []
  revealSection(fakeSection({ [FIRST_FIELD]: null, [FIRST_FOCUSABLE]: "Done" }, calls))
  assert.deepEqual(calls[0], ["focus Done", { preventScroll: true }])
}
assert.equal(revealSection(null), false)
assert.ok(FIRST_FIELD.includes('input:not([type="hidden"]):not([disabled])') && !/(^|, )button:/.test(FIRST_FIELD),
  "the server-type switch buttons in the card header are not the first field")

// menuReveal: an item that requested a section stops the focus return and reveals it; any other item keeps it
{
  const calls: Call[] = []
  const sections: Record<string, Revealable> = { "servers-form": fakeSection({ [FIRST_FIELD]: "name" }, calls) }
  const reveal = menuReveal((id) => sections[id] ?? null)
  let prevented = 0
  const event = { preventDefault: () => { prevented += 1 } }

  reveal.onCloseAutoFocus(event) // "Run connection test": nothing requested, Radix focuses the trigger
  assert.equal(prevented, 0)
  assert.deepEqual(calls, [])

  reveal.request("servers-form") // "Edit"
  reveal.onCloseAutoFocus(event)
  assert.equal(prevented, 1)
  assert.deepEqual(calls.map((c) => c[0]), ["focus name", "scrollIntoView"])

  reveal.onCloseAutoFocus(event) // a request is used once
  assert.equal(prevented, 1)

  reveal.request("scan-node-wizard") // a section that is not there yet (token still being issued): focus not returned
  reveal.onCloseAutoFocus(event)
  assert.equal(prevented, 2)
}

// every row menu with an item that moves to a section below uses it (Servers, Kubernetes & Databases, Cloud
// accounts, Scan nodes); Network TLS and Schedules have no row menus (inline buttons), identity rows open dialogs
const src = (f: string) => fs.readFileSync(path.join(__dirname, f), "utf8")
for (const [file, ids] of Object.entries({
  "ServersTab.tsx": ['rowMenu.request("servers-form")', 'if (fromMenu) rowMenu.request("servers-test")'],
  "ClustersDatabasesTab.tsx": ['rowMenu.request("k8s-form")', 'rowMenu.request("km-form")', 'rowMenu.request("db-form")'],
  "CloudIdentityTab.tsx": ['rowMenu.request("cbom-cloud-connect")'],
  "ScanNodesTab.tsx": ["rowMenu.request(WIZARD_ID)"],
})) {
  const text = src(file)
  assert.ok(text.includes("onCloseAutoFocus={rowMenu.onCloseAutoFocus}"), `${file}: the row menu skips the focus return`)
  for (const id of ids) assert.ok(text.includes(id), `${file}: ${id}`)
  // the old pattern: scrolling from the item itself (cancelled by the trigger focus ~150 ms later)
  assert.ok(!/const startEdit[\s\S]{0,400}?scrollIntoView|const startEdit[\s\S]{0,400}?scrollToId\(/.test(text), `${file}: startEdit does not scroll itself`)
}
assert.ok(src("ServersTab.tsx").includes("onSelect={() => showResults(source, true)}"), "Test results from the menu")

console.log("reveal tests passed")
