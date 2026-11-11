/**
 * X1 (round 5 customer walkthrough): a double-click on "Create node and show install command" sent two
 * POST /{team}/cbom/sources/nodes and created two scan nodes with the same name (x1-seg-a twice, one never
 * registers; both install commands use the same container and volume name). The button's disabled={isPending}
 * only takes effect after React re-renders, which is after the second click.
 * Browser check after a rebuild: Scan nodes > Add scan node > name > double-click Create: one POST, one row.
 * Run: npx --yes tsx components/cbom/sources/nodeDoubleCreate.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { singleFlight } from "./logic"

const guard = singleFlight()
assert.equal(guard.tryStart(), true, "the first click starts the request")
assert.equal(guard.tryStart(), false, "the second click of a double-click is dropped")
guard.done()
assert.equal(guard.tryStart(), true, "after the request settles (e.g. a 400 to correct), Create works again")

const a = singleFlight()
const b = singleFlight()
assert.equal(a.tryStart(), true)
assert.equal(b.tryStart(), true, "each guard is independent")

const tab = fs.readFileSync(path.join(__dirname, "ScanNodesTab.tsx"), "utf8")
const submit = tab.slice(tab.indexOf("const submitWizard"), tab.indexOf("const online ="))
assert.ok(submit.includes("if (!createGuard.tryStart()) return;"), "submitWizard asks the guard before creating")
assert.ok(submit.includes("createMutation.mutate(undefined, { onSettled: () => createGuard.done() })"), "the guard is released when the request settles")
assert.ok(submit.indexOf("NAME_RE.test") < submit.indexOf("createGuard.tryStart()"), "a name error does not take the guard")
assert.ok(tab.includes("const [createGuard] = useState(singleFlight);"), "one guard per mounted tab")

console.log("node double-create tests passed")
