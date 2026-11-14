/** CB-29 advisory-data line on the code-scan results page. Run: npx --yes tsx@4.23.15 components/cbom/advisoryData.test.ts */
import assert from "node:assert/strict";

import { advisoryLine, readAdvisoryData, staleNote } from "./advisoryData";

const fresh = { source: "osv-snapshot", snapshot_version: "2026.11.14.1", generated_at: "2026-11-14", age_days: 1, stale: false };
assert.deepEqual(readAdvisoryData(null, { advisory_data: fresh }), fresh);
assert.equal(readAdvisoryData({ advisory_data: { generated_at: null } }, {}), null); // an older scan: nothing shown
assert.equal(advisoryLine(fresh), "Library advisories: OSV snapshot 2026.11.14.1, data as of 2026-11-14 (1 day old)");
assert.equal(staleNote(fresh), null);
const stale = { ...fresh, age_days: 40, stale: true, max_age_days: 30, online: { asked: 2, answered: 1 } };
assert.match(advisoryLine(stale), /40 days old\); refreshed online for 1 of 2 package\(s\)$/);
assert.match(staleNote(stale) ?? "", /older than 30 days/);
console.log("advisoryData.test.ts: ok");
