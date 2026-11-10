/**
 * Scan menus and dialogs say "Rename scan" / "Delete scan", never "Rename/Delete Conversation" (round 5, G3 item 9).
 * Run: npx --yes tsx utils/scanMenuWording.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const app = path.join(__dirname, "..", "app", "[team_id]")
const pages = ["cbom", "sast", "llm", "ai_bom", "sbom_sca", "iac", "mcp", "dast"]
  .map((p) => path.join(app, p, "page.tsx"))
  .filter((f) => fs.existsSync(f))
const files = [...pages, path.join(__dirname, "backend_api.ts")]
const banned = [/Rename Conversation/, /Delete Conversation/, /this conversation/, /"Conversation name"/,
  /scan conversation/, /conversation (renamed|deleted) successfully/i]
for (const file of files) {
  const text = fs.readFileSync(file, "utf8")
  for (const re of banned) assert.ok(!re.test(text), `${path.relative(app, file)} still says ${re}`)
}
for (const p of ["cbom", "sast", "llm", "ai_bom", "sbom_sca", "iac", "mcp"]) {
  const text = fs.readFileSync(path.join(app, p, "page.tsx"), "utf8")
  assert.ok(text.includes("/>Rename scan"), `${p}: menu item says Rename scan`)
  assert.ok(text.includes("/>Delete scan"), `${p}: menu item says Delete scan`)
}
const cbom = fs.readFileSync(path.join(app, "cbom", "page.tsx"), "utf8")
assert.ok(cbom.includes("<DialogTitle>Rename scan</DialogTitle>") && cbom.includes("<DialogTitle>Delete scan</DialogTitle>"))
console.log("scan menu wording tests passed")
