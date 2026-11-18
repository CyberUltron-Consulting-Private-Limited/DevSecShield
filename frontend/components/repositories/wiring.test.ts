// Run: npx --yes tsx components/repositories/wiring.test.ts
// Review of #66: the Connections tab has the Edit the wizard points to, a webhook secret is rotated only after a
// confirmation (and shown once), and an inventory filter change empties the selection. Checked on the component
// sources (patterns over the TSX text).
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const read = (f: string) => fs.readFileSync(path.join(__dirname, f), "utf8")

// major 1: Edit exists, opens the dialog, and the dialog uses the tested helpers and the PATCH route
const tab = read("ConnectionsTab.tsx")
assert.match(read("ImportWizard.tsx"), /corrected with Edit on the Connections tab/)
assert.match(tab, /onClick=\{\(\) => setEditOpen\(true\)\}>\s*<Pencil[^>]*\/>Edit\s*<\/Button>/, "an Edit button on each connection")
assert.match(tab, /<EditConnectionDialog teamId=\{teamId\} connection=\{c\}/)
const dialog = read("EditConnectionDialog.tsx")
for (const helper of ["editFormFrom(", "editErrors(", "editMovesCredential(", "editPatch(", "updateScmConnection("]) {
  assert.ok(dialog.includes(helper), `the Edit dialog uses ${helper}`)
}
assert.match(dialog, /<SecretField[\s\S]*?isSet=\{!moves\}[\s\S]*?required=\{moves\}/, "the saved credential is kept unless the edit moves it")
assert.doesNotMatch(dialog, /secrets_set\b.*value=/, "no saved secret is ever put in a field")

// major 2: the button only opens a confirmation; the rotation runs from the confirmation, and the secret shows once
const button = tab.slice(tab.indexOf("New webhook secret") - 300, tab.indexOf("New webhook secret"))
assert.match(button, /onClick=\{\(\) => setConfirmRotate\(true\)\}/, "the button asks first")
assert.doesNotMatch(button, /rotate\.mutate\(\)/, "the button never rotates by itself")
assert.match(tab, /<ConfirmDialog\s+open=\{confirmRotate\}[\s\S]*?description=\{ROTATE_WARNING\}[\s\S]*?onConfirm=\{\(\) => rotate\.mutate\(\)\}/)
assert.match(tab, /<Dialog open=\{Boolean\(secret\)\}[\s\S]*?<CopyButton text=\{secret\.secret\} label="Copy secret" \/>/, "shown once with copy")
assert.match(tab, /onOpenChange=\{\(v\) => !v && setSecret\(null\)\}/, "closing forgets the secret")

// minor 5: every filter goes through filterChange (selection emptied); paging does not
const inv = read("InventoryTab.tsx")
assert.match(inv, /const next = filterChange\(query, patch\);\s*setQuery\(next\.query\);\s*setSelected\(next\.selected\);/)
assert.match(inv, /setSearch\(e\.target\.value\); set\(\{\}\);/, "typing a search is a filter change")
assert.doesNotMatch(inv, /setQuery\(\(q\) => \(\{ \.\.\.q, \.\.\.patch/, "no filter path that keeps the selection")

console.log("repositories wiring: ok")
