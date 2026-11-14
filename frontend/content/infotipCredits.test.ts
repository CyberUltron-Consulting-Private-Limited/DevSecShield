/**
 * Every credit amount in a CBOM Sources (i) tip is recomputed from the prices in
 * backend/utilities/cbom_sources/planning.py (RATES_C, centi-credits), so a tip can never drift from what a run
 * charges (review of #135, M2: three examples used 0.01 instead of 0.2 credits per server target).
 *  1. RATES_C is read from planning.py (the source of truth), not copied here.
 *  2. Each claim below rebuilds the expected amount from those rates and the example's own counts.
 *  3. Any cbsrc.* tip with a credit amount (a number before "credit", or an x.yy amount) must be listed below.
 * Run: npx --yes tsx content/infotipCredits.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { INFO_TIPS } from "./infotips";

const planning = fs.readFileSync(path.join(__dirname, "..", "..", "backend", "utilities", "cbom_sources", "planning.py"), "utf8");
const rates: Record<string, number> = {};
const dict = planning.match(/^RATES_C = \{([^}]*)\}/m);
assert.ok(dict, "planning.py: RATES_C = {...} not found");
for (const m of dict![1].matchAll(/"(\w+)":\s*(\d+)/g)) rates[m[1]] = Number(m[2]);
for (const m of planning.matchAll(/^RATES_C\["(\w+)"\] = (\d+)/gm)) rates[m[1]] = Number(m[2]);
for (const k of ["server", "kubernetes", "database", "cloud_account", "network_block", "image", "ct_domain"]) {
  assert.ok(Number.isInteger(rates[k]), `planning.py: RATES_C["${k}"] missing`);
}
/** credits from centi-credits, as the UI prints them (two decimals) */
const c = (centi: number) => (centi / 100).toFixed(2);
/** a per-unit price as the tips write it ("0.2", "4", "1") */
const per = (centi: number) => String(centi / 100);

type Tip = { what: string; why?: string; example: string };
const tip = (id: string) => INFO_TIPS[id as keyof typeof INFO_TIPS] as Tip;
const server = rates.server, cloud = rates.cloud_account, db = rates.database, image = rates.image, ct = rates.ct_domain;

// id -> the strings its text must contain, rebuilt from the rates
const CLAIMS: Record<string, string[]> = {
  "cbsrc.rr.coverage": [`612 targets`, c(612 * server), `${per(server)} per target`],
  "cbsrc.rr.start": [c(612 * server), c(cloud), c(612 * server + cloud)],
  "cbsrc.sidebar.include": [`31 targets add ${c(31 * server)}`, `${per(server)} per target`],
  "cbsrc.rr.col.credits": [`${c(cloud)} for one AWS account`, `${per(cloud)} credits per account`],
  "cbsrc.cloud.list": [`${per(cloud)} credits per account per run`],
  "cbsrc.rr.after": [`2 databases, 1 AWS account and 32 server targets: ${c(2 * db + cloud + 32 * server)} credits charged`, `${c(db)} refunded for a database job`],
  "cbsrc.rr.runs": [`${c(2 * db + cloud + 32 * server)} charged / ${c(db)} refunded`],
  "cbsrc.rr.col.run_credits": [`${c(2 * db + cloud + 32 * server)} charged / ${c(db)} refunded`],
  "cbsrc.rr.job.credits": [`${c(128 * server)} refunded: a 128-target server job`],
  "cbsrc.img.card": [`${per(image)} credit per image per run`],
  "cbsrc.img.col.images": [`${per(image)} credit per run`, `12 images: ${12 * image / 100} credits per run`],
  "cbsrc.ct.discovery": [`${per(ct)} credits per domain searched`],
};

const problems: string[] = [];
for (const [id, wants] of Object.entries(CLAIMS)) {
  const t = tip(id);
  if (!t) { problems.push(`${id}: not in the registry`); continue; }
  const text = [t.what, t.why ?? "", t.example].join(" ");
  for (const w of wants) if (!text.includes(w)) problems.push(`${id}: expected "${w}" (from planning.py RATES_C) in: ${text}`);
}
// every Sources tip that states a credit amount is checked above
const AMOUNT = /(?<![\d.])\d+(?:\.\d+)?\s+credits?\b|(?<![\d.:])\d+\.\d\d(?![\d.])/;
for (const id of Object.keys(INFO_TIPS)) {
  if (!id.startsWith("cbsrc.")) continue;
  const t = tip(id);
  const text = [t.what, t.why ?? "", t.example].join(" ");
  if (AMOUNT.test(text) && !(id in CLAIMS)) problems.push(`${id}: states a credit amount; add it to CLAIMS so it is recomputed from planning.py`);
}
assert.deepEqual(problems, [], problems.join("\n"));
console.log(`info tip credits: ${Object.keys(CLAIMS).length} tips recomputed from planning.py RATES_C, tests passed`);
