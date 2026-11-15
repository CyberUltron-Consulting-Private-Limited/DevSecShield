/**
 * #216 / #217 in the Databases and KMIP forms: the same rules the API applies at save.
 * Run: npx --yes tsx components/cbom/sources/dbKmipRules.test.ts
 */
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import { dbHostError } from "./dbHost"

for (const ok of ["db.bank.local", "10.0.0.5", "fd00::5", "2001:db8::1", "::ffff:10.0.0.5"]) assert.equal(dbHostError(ok), null, ok)
for (const bad of ["db.bank.local:5433", "10.0.0.5:5432", "db:"]) assert.match(dbHostError(bad) ?? "", /Port field/, bad)
assert.equal(dbHostError("not a host"), "Enter a host name or IP address")
assert.equal(dbHostError("", "Enter the KMIP server's host name or IP address"), "Enter the KMIP server's host name or IP address")

const tab = readFileSync(join(__dirname, "ClustersDatabasesTab.tsx"), "utf8")
assert.match(tab, /const CA_REQUIRED_ENGINES: ReadonlySet<Engine> = new Set\(\["mysql", "redis", "mssql", "oracle", "mongodb"\]\)/)
assert.equal((tab.match(/dbHostError\(form\.host/g) ?? []).length, 2) // the database form and the KMIP form
assert.doesNotMatch(tab, /HOST_RE\.test\(form\.host/)

console.log("database and KMIP form rules: tests passed")
