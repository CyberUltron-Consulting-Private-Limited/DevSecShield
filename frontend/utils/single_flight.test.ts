/**
 * X1 (round 5 customer walkthrough): a double-click on Create in the "Create New Scan" dialog sent two
 * POST /13/sast/scan {"title": ...} and left two SAST scans with the same title (the same Create dialog and handler
 * are on the SAST, SCA + SBOM, CBOM, AI BOM, MCP, LLM, IAC and DAST list pages; Enter pressed twice did the same).
 * disabled={mutation.isPending} only applies after React re-renders, which is after the second click.
 * Browser check after a rebuild: <page> > New Scan > title > double-click Create: one POST, one new scan.
 * Run: npx --yes tsx utils/single_flight.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { singleFlight } from "./single_flight"
import { singleFlight as fromSources } from "../components/cbom/sources/logic"

const g = singleFlight()
assert.equal(g.tryStart(), true, "first click starts")
assert.equal(g.tryStart(), false, "second click of the burst is dropped")
assert.equal(g.tryStart(), false, "and a third")
g.done()
assert.equal(g.tryStart(), true, "after the request settles (success or error) Create works again")
assert.equal(fromSources, singleFlight, "CBOM Sources uses the same guard")

const pages = ["sast", "sbom_sca", "cbom", "ai_bom", "mcp", "llm", "iac", "dast"]
for (const name of pages) {
  const src = fs.readFileSync(path.join(__dirname, "..", "app", "[team_id]", name, "page.tsx"), "utf8")
  const body = src.slice(src.indexOf("const confirmCreate = () => {"), src.indexOf("const confirmCreate = () => {") + 400)
  assert.ok(src.includes('import { singleFlight } from "@/utils/single_flight";'), `${name}: imports the guard`)
  assert.ok(src.includes("const [createGuard] = useState(singleFlight);"), `${name}: one guard per page`)
  assert.ok(body.includes("if (!createGuard.tryStart()) return;"), `${name}: confirmCreate asks the guard`)
  assert.ok(body.includes("{ onSettled: () => createGuard.done() }"), `${name}: the guard is released when the request settles`)
  assert.ok(body.indexOf("newScanTitle.trim()") < body.indexOf("createGuard.tryStart()"), `${name}: an empty title does not take the guard`)
  // the hook sits with the other hooks (right before the create mutation), never after an early return
  assert.ok(src.indexOf("const [createGuard] = useState(singleFlight);") < src.indexOf("Mutation = useMutation({", src.indexOf("const [createGuard]")), `${name}: hook order`)
}

console.log("single flight tests passed")
