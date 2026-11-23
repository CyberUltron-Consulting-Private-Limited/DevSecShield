/**
 * FIX-A3 (SOW audit A-11): the regulated-entity setting picks the RBI instrument of the regulatory mapping; the
 * frontend choices, the default and the instrument names agree with the backend (regulated_entity.py and the board
 * report's ENTITY_INSTRUMENTS), and the Grade inputs card offers the setting.
 * Run: npx --yes tsx components/cbom/sources/regulatedEntity.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { DEFAULT_REGULATED_ENTITY, REGULATED_ENTITY_CHOICES, regulatedEntityOf } from "./regulatedEntity"

const read = (p: string) => fs.readFileSync(path.join(__dirname, p), "utf8")
const backend = read("../../../../backend/utilities/cbom_sources/regulated_entity.py")
const board = read("../../../../backend/utilities/pdf/cbom_board_report_pdf.py")

assert.deepEqual(REGULATED_ENTITY_CHOICES.map((c) => c.value), ["nbfc", "bank", "other"])
assert.ok(backend.includes('ENTITY_TYPES = ("nbfc", "bank", "other")'), "the backend accepts the same three")
assert.equal(DEFAULT_REGULATED_ENTITY, "nbfc")
assert.ok(backend.includes('DEFAULT_ENTITY = "nbfc"'), "the backend default is NBFC too")
assert.equal(regulatedEntityOf("bank"), "bank")
assert.equal(regulatedEntityOf(undefined), "nbfc", "an older server without the field means NBFC")
assert.equal(regulatedEntityOf("insurer"), "nbfc")
for (const c of REGULATED_ENTITY_CHOICES) {
  // the board report names the same instrument (its text wraps the long names over two string literals)
  const words = c.instrument.replace(/^RBI /, "").split(" ").slice(0, 4).join(" ")
  assert.ok(board.includes(words), `the board report names ${c.instrument}`)
}
const card = read("GradeInputsCard.tsx")
assert.ok(card.includes("<RegulatedEntitySelect teamId={teamId} isAdmin={isAdmin} />"), "the card offers the setting")
const select = read("RegulatedEntitySelect.tsx")
assert.ok(select.includes("disabled={!isAdmin || save.isPending}"), "only an admin changes it")
assert.ok(select.includes("regulated_entity, expected_version"), "it saves with the settings version (409 on a race)")
console.log("regulatedEntity tests passed")
