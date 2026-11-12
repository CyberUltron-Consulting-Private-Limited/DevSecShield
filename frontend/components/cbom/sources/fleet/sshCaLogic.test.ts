// Run: npx --yes tsx components/cbom/sources/fleet/sshCaLogic.test.ts
import assert from "node:assert/strict";

import { principalOk, readinessText } from "./sshCaLogic";

const fmt = (iso: string | null) => `<${iso}>`;

// No rotation waiting: nothing to show.
assert.equal(readinessText(null, fmt), null);

// Younger than the minimum age: promote needs force; the counts are shown.
let r = readinessText({ age_s: 60, min_age_s: 900, promote_after: "2026-11-12T10:15:00Z", fetchers_total: 2, fetchers_ready: 1 }, fmt);
assert.deepEqual(r, { text: "1 of 2 servers that fetch the trust bundle have this key. Promote after <2026-11-12T10:15:00Z>, or force it.", early: true });

// Old enough: no force needed; no fetcher yet is said plainly.
r = readinessText({ age_s: 901, min_age_s: 900, promote_after: null, fetchers_total: 0, fetchers_ready: 0 }, fmt);
assert.deepEqual(r, { text: "No server fetches the trust bundle with a trust token yet.", early: false });

// Principals: this team's, one spelling.
assert.equal(principalOk("zs-7-prod", 7), true);
assert.equal(principalOk("zs-07-prod", 7), false);
assert.equal(principalOk("zs-8-prod", 7), false);
assert.equal(principalOk("root", 7), false);

console.log("sshCaLogic: all assertions passed");
