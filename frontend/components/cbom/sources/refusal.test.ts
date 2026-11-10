/**
 * Lab UI r1 minor items:
 * - /7/cbom/sources (a team one is not in: 403 "User is not in team") said only "Could not load this section. Please
 *   try again."; every ErrorBlock of the Sources tabs now gets its query's error and shows the server's reason, as
 *   the toasts do since L1 (utils/error-handler.ts, 92cc395).
 * - the code-scan lists' row menu trigger (an icon button) had no accessible name.
 * Browser check after a rebuild: r1 bin/run auth403b.js (/7/cbom/sources text) and phone_menu.js (button names).
 * Run: npx --yes tsx components/cbom/sources/refusal.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { refusalReason } from "./logic"

const axiosLike = (status: number, detail: unknown) => ({ message: `Request failed with status code ${status}`, response: { status, data: { detail } } })
assert.equal(refusalReason(axiosLike(403, "User is not in team")), "User is not in team")
assert.equal(refusalReason(axiosLike(404, "Run not found")), "Run not found")
assert.equal(refusalReason(axiosLike(409, "  This was changed elsewhere.  ")), "This was changed elsewhere.")
assert.equal(refusalReason(axiosLike(401, "Not authenticated")), null, "a 401 signs in again")
assert.equal(refusalReason(axiosLike(500, "Internal server error")), null, "a 5xx keeps the generic sentence")
assert.equal(refusalReason(axiosLike(422, [{ msg: "x", loc: ["body"] }])), null, "a validation list is not a sentence")
assert.equal(refusalReason(new Error("Network Error")), null)
assert.equal(refusalReason(undefined), null)
assert.equal(refusalReason(axiosLike(403, "x".repeat(400)))?.length, 300)

const dir = __dirname
const shared = fs.readFileSync(path.join(dir, "shared.tsx"), "utf8")
assert.ok(shared.includes("const reason = refusalReason(error);"), "ErrorBlock reads the reason")
assert.ok(shared.includes('{message ?? reason ?? "Could not load this section. Please try again."}'), "and shows it")
// every ErrorBlock of the Sources tabs is given its query's error
for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".tsx"))) {
  const text = fs.readFileSync(path.join(dir, file), "utf8")
  const blocks = text.split("<ErrorBlock").slice(1).map((b) => b.slice(0, b.indexOf("/>")))
  for (const block of blocks) assert.ok(/\berror=\{/.test(block), `${file}: an ErrorBlock without its error`)
}

// row menu triggers of the code-scan lists have a name
const app = path.join(dir, "../../../app/[team_id]")
for (const type of ["sast", "iac", "sbom_sca", "cbom", "ai_bom", "llm", "mcp"]) {
  const page = fs.readFileSync(path.join(app, type, "page.tsx"), "utf8")
  assert.ok(page.includes('aria-label={`Actions for ${conversation.title || `scan #${conversation.id}`}`}><MoreVertical'),
    `${type}: the row menu trigger has an accessible name`)
  assert.ok(!page.includes('className="h-8 w-8 cursor-pointer"><MoreVertical'), `${type}: no unnamed trigger left`)
}

console.log("refusal and a11y tests passed")
