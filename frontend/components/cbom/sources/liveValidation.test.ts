// Run: npx --yes tsx components/cbom/sources/liveValidation.test.ts
import assert from "node:assert/strict"

import { keepLiveValidation } from "./liveValidation"

const live = { sourceId: 7, status: "passed", at: "2026-11-05T10:00:05Z" }
const stored = { id: 7, last_test_status: "passed", last_test_at: "2026-11-05T10:00:05Z" }

// nothing received in this browser
assert.equal(keepLiveValidation(null, [stored], "2026-11-05T10:00:09Z", 7), false)
// the server holds the same result: keep showing it
assert.equal(keepLiveValidation(live, [stored], "2026-11-05T10:00:09Z", null), true)
// a list read before the validation finished cannot overrule it
assert.equal(keepLiveValidation(live, [{ ...stored, last_test_at: null, last_test_status: "never" }], "2026-11-05T10:00:01Z", null), true)
// review round 5: a connection change on the server reset the test to "never" (runs skip the account) -> server wins
assert.equal(keepLiveValidation(live, [{ ...stored, last_test_at: null, last_test_status: "never" }], "2026-11-05T10:03:00Z", null), false)
// a newer test (another tab, another user) -> server wins
assert.equal(keepLiveValidation(live, [{ ...stored, last_test_at: "2026-11-05T10:02:00Z", last_test_status: "failed" }], "2026-11-05T10:03:00Z", null), false)
// the server dropped this result (the connection changed during the test): its older record wins
assert.equal(keepLiveValidation(live, [{ ...stored, last_test_at: "2026-11-04T08:00:00Z" }], "2026-11-05T10:03:00Z", null), false)
// just created: the list does not have the account yet, the form does
assert.equal(keepLiveValidation(live, [], "2026-11-05T10:00:09Z", 7), true)
// deleted elsewhere and not being edited
assert.equal(keepLiveValidation(live, [], "2026-11-05T10:00:09Z", null), false)

console.log("liveValidation tests passed")
