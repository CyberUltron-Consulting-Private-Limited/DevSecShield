/**
 * SOW audit A-11: the regulatory profile setting. The frontend choices, the default and the instrument names agree
 * with the backend (regulated_entity.py and the deliverables' ENTITY_INSTRUMENTS); the Grade inputs card offers it.
 * Review m7 (deploy skew): on a backend without the setting the control is hidden, so the page never shows a value
 * the server does not hold and never sends a field it rejects (422).
 * Run: npx --yes tsx components/cbom/sources/regulatedEntity.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import {
  DEFAULT_REGULATED_ENTITY,
  REGULATED_ENTITY_CHOICES,
  REGULATORY_FLAGS,
  hasRegulatoryProfile,
  regulatedEntityOf,
  regulatoryFlagsOf,
} from "./regulatedEntity"

const read = (p: string) => fs.readFileSync(path.join(__dirname, p), "utf8")
const backend = read("../../../../backend/utilities/cbom_sources/regulated_entity.py")
const texts = read("../../../../backend/utilities/pdf/cbom_deliverable_text.py")
const schema = read("../../../../backend/utilities/cbom_sources/schemas.py")

const values = REGULATED_ENTITY_CHOICES.map((c) => c.value)
assert.deepEqual(values, ["nbfc", "bank", "sfb", "payments_bank", "ucb", "aifi", "credit_info_company", "other"])
const backendTypes = /ENTITY_TYPES = \(([^)]*)\)/.exec(backend)?.[1].match(/"([a-z_]+)"/g)?.map((s) => s.slice(1, -1))
assert.deepEqual(backendTypes, values, "the backend accepts the same entity types, in the same order")
for (const v of values) assert.ok(schema.includes(`"${v}"`), `the settings schema accepts ${v}`)
assert.equal(DEFAULT_REGULATED_ENTITY, "nbfc")
assert.ok(backend.includes('DEFAULT_ENTITY = "nbfc"'), "the backend default is NBFC too")
assert.equal(regulatedEntityOf("bank"), "bank")
assert.equal(regulatedEntityOf("sfb"), "sfb")
assert.equal(regulatedEntityOf(undefined), "nbfc")
assert.equal(regulatedEntityOf("insurer"), "nbfc")
for (const c of REGULATED_ENTITY_CHOICES) {
  if (c.instrument === null) {
    assert.ok(/"other": None/.test(texts), "the deliverables cite no RBI direction for other entities")
    continue
  }
  // the deliverables name the same instrument and paragraph (their text wraps the long names over string literals)
  const words = c.instrument.replace(/^RBI /, "").split(" ").slice(0, 2).join(" ")
  const para = /para \d+/.exec(c.instrument)?.[0] ?? ""
  assert.ok(texts.includes(words), `the deliverables name ${c.instrument}`)
  assert.ok(texts.includes(para), `the deliverables cite ${para}`)
}
// the flags: the same three as the backend
const backendFlags = /FLAGS = \(([^)]*)\)/.exec(backend)?.[1].match(/"([a-z_]+)"/g)?.map((s) => s.slice(1, -1))
assert.deepEqual(REGULATORY_FLAGS.map((f) => f.value), backendFlags, "the backend has the same flags")
// strict booleans (PR #485 review 2 m2): "yes" or 1 is refused, never a silently switched-on framework
for (const f of REGULATORY_FLAGS) assert.ok(schema.includes(`${f.value}: StrictBool | None`), `the schema accepts ${f.value}`)

// deploy skew (m7): an older backend sends neither the entity nor the flags
assert.equal(hasRegulatoryProfile({}), false, "no field: the control is hidden")
assert.equal(hasRegulatoryProfile(undefined), false)
assert.equal(hasRegulatoryProfile({ regulated_entity: "nbfc" }), true)
assert.deepEqual(regulatoryFlagsOf({}), {}, "an older backend: no flag offered")
assert.deepEqual(regulatoryFlagsOf({ processes_card_data: false, sebi_regulated: true }),
  { processes_card_data: false, sebi_regulated: true })

const card = read("GradeInputsCard.tsx")
assert.ok(card.includes("<RegulatedEntitySelect teamId={teamId} isAdmin={isAdmin} />"), "the card offers the setting")
const select = read("RegulatedEntitySelect.tsx")
assert.ok(select.includes("!hasRegulatoryProfile(settings.data)) return null"), "hidden on a backend without it")
assert.ok(select.includes("f.value in flags"), "a flag is offered only when the server sends it")
assert.ok(select.includes("disabled={!isAdmin || save.isPending}"), "only an admin changes it")
assert.ok(select.includes("expected_version: settings.data?.row_version"), "it saves with the settings version")
console.log("regulatedEntity tests passed")
