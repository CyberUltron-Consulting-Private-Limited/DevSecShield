/**
 * #225 follow-up: Settings > Integrations > ServiceNow offers a field for every optional CMDB import column the backend
 * maps (servicenow.CMDB_EXTRA_FIELDS), each with its own (i) tip.
 * Run: npx --yes tsx components/integrations/cmdbMapping.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const here = path.dirname(new URL(import.meta.url).pathname);
const backend = fs.readFileSync(path.join(here, "../../../backend/utilities/integrations/servicenow.py"), "utf8");
const tuple = /CMDB_EXTRA_FIELDS = \(([^)]*)\)/.exec(backend);
assert.ok(tuple, "CMDB_EXTRA_FIELDS not found in servicenow.py");
const extra = Array.from(tuple[1].matchAll(/"([a-z_]+)"/g)).map((m) => m[1]);
assert.ok(extra.length >= 12);

const page = fs.readFileSync(path.join(here, "IntegrationsPage.tsx"), "utf8");
const tips = fs.readFileSync(path.join(here, "../../content/infotips.ts"), "utf8");
for (const key of extra) {
  assert.match(page, new RegExp(`infoId: "int\\.sn\\.cmdb_${key}", key: "cmdb_mapping\\.${key}"`), `no form field for ${key}`);
  assert.match(tips, new RegExp(`"int\\.sn\\.cmdb_${key}": \\{`), `no (i) tip for ${key}`);
}
console.log("cmdbMapping.test.ts: ok");
