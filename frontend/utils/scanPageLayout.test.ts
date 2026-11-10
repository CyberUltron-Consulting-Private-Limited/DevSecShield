/**
 * On a phone (390x844) the scan page put the chat and the 384 px options sidebar side by side, which squeezed the
 * chat to 32 px (round 5, G3 item 8). Below md the two now stack (chat first, the page scrolls); from md up they sit
 * side by side as before.
 * Run: npx --yes tsx utils/scanPageLayout.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const root = path.join(__dirname, "..")
const pages = ["cbom/[scan_id]", "sast/[scan_id]", "sbom_sca/[scan_id]", "iac/[scan_id]", "ai_bom/[scan_id]",
  "dast/[scan_id]", "llm/[conversation_id]", "mcp/[conversation_id]"]
for (const p of pages) {
  const text = fs.readFileSync(path.join(root, "app", "[team_id]", p, "page.tsx"), "utf8")
  assert.ok(text.includes('<div className="flex flex-col md:flex-row h-screen'), `${p}: stacks below md`)
  assert.ok(!text.includes('<div className="flex h-screen">'), `${p}: still a fixed side-by-side row`)
  assert.ok(text.includes("flex-1 min-h-[75vh] md:min-h-0 min-w-0"), `${p}: the chat keeps a usable height on a phone`)
}
for (const name of ["cbom", "sast", "sca-sbom", "iac", "ai-bom", "llm", "mcp", "dast"]) {
  const text = fs.readFileSync(path.join(root, "components", `${name}-options-sidebar.tsx`), "utf8")
  assert.ok(/<ScrollArea className="w-full md:w-(96|80) shrink-0 md:h-screen/.test(text), `${name}: full width below md`)
  assert.ok(!/<ScrollArea className="w-(96|80) h-screen/.test(text), `${name}: fixed width on every screen`)
}
console.log("scan page layout tests passed")
