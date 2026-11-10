/**
 * Review & Run shows the scan window on every row that waits for it, and says before charging when a run that is
 * outside the window will start (round 5, G3 item 5: servers and databases sat "Queued · Outside the scan window").
 * Run: npx --yes tsx components/cbom/sources/scanWindow.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"
import { formatDateTime, windowLine, windowStartNotice, windowWait } from "./logic"

const at = "2026-11-11T02:00:00Z"
const later = "2026-11-11T05:00:00Z"
const server = { status: "queued", window_applies: true, window_starts_at: later }
const db = { status: "queued", window_applies: true, window_starts_at: at }
const cloud = { status: "queued", window_applies: false, window_starts_at: null }
const skipped = { status: "skipped", window_applies: true, window_starts_at: at }
const inWindow = { status: "queued", window_applies: true, window_starts_at: null }

assert.deepEqual(windowWait([server, db, cloud, skipped]), { applies: 2, waiting: 2, firstStart: at })
assert.equal(windowLine([cloud]), null, "a cloud row has no window line")
assert.equal(windowLine([inWindow]), "In the scan window now")
assert.equal(windowLine([server, db]), `Outside the scan window: starts ${formatDateTime(at)}`)
assert.equal(windowStartNotice([inWindow, cloud]), null)
assert.match(windowStartNotice([db]) ?? "", /^1 source is outside the scan window\. The run is charged now; it starts when the window opens/)
assert.match(windowStartNotice([server, db]) ?? "", /^2 sources are outside .* at the earliest\) and stay queued until then\.$/)

const tab = fs.readFileSync(path.join(__dirname, "ReviewRunTab.tsx"), "utf8")
assert.ok(tab.includes("windowLine(groupItems)"), "every node-run row shows its window")
assert.ok(tab.includes("windowStartNotice(queued)"), "the estimate says when an out-of-window run starts")
console.log("scan window tests passed")
