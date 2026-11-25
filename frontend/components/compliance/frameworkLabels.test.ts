/**
 * #498 round 3: the "India" preset chip of a compliance matrix is named after the Indian regulators whose frameworks the
 * page shows. A bank or NBFC that SEBI does not regulate (its AI BOM compliance has no sebi_cscrf_aibom after the
 * server's ai_bom_applicability filter) must not read "India / CERT-In / SEBI".
 * Run: npx --yes tsx components/compliance/frameworkLabels.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  FRAMEWORK_GROUPS_AIBOM_WITH_INDIA,
  FRAMEWORK_GROUPS_CBOM_WITH_INDIA,
  groupsForFrameworks,
  PROFILE_NOT_SET_SUFFIX,
} from "./frameworkLabels";

const india = (groups: { id: string; label: string; keys: string[] }[]) => groups.find((g) => g.id === "india");

// a bank / NBFC not regulated by SEBI: CERT-In and RBI FREE-AI bind, SEBI CSCRF does not
const bank = groupsForFrameworks(FRAMEWORK_GROUPS_AIBOM_WITH_INDIA, ["eu_ai_act_annexIV", "nist_rmf", "rbi_free_ai", "cert_in_aibom"]);
assert.equal(india(bank)?.label, "India / CERT-In / RBI");
assert.deepEqual(india(bank)?.keys, ["cert_in_aibom", "rbi_free_ai"]);

// a SEBI-regulated bank keeps SEBI
const sebi = groupsForFrameworks(FRAMEWORK_GROUPS_AIBOM_WITH_INDIA, ["rbi_free_ai", "cert_in_aibom", "sebi_cscrf_aibom"]);
assert.equal(india(sebi)?.label, "India / CERT-In / RBI / SEBI");

// an "other" entity whose scan has only CERT-In of the Indian frameworks
assert.equal(india(groupsForFrameworks(FRAMEWORK_GROUPS_AIBOM_WITH_INDIA, ["cert_in_aibom", "hipaa"]))?.label, "India / CERT-In");

// no Indian framework shown: no India chip; "All" stays
const none = groupsForFrameworks(FRAMEWORK_GROUPS_AIBOM_WITH_INDIA, ["hipaa", "fda_524b"]);
assert.equal(india(none), undefined);
assert.deepEqual(none.map((g) => g.id), ["all"]);

// CBOM: other chips untouched, India narrowed the same way
const cbom = groupsForFrameworks(FRAMEWORK_GROUPS_CBOM_WITH_INDIA, ["nist_800_57", "cert_in_cbom"]);
assert.deepEqual(cbom.map((g) => g.id), ["all", "quantum", "baseline", "regulatory", "india"]);
assert.equal(india(cbom)?.label, "India / CERT-In");

// wiring: the AI BOM matrix wrapper derives its chips from the frameworks it receives (the CBOM / SBOM code-mode markup
// is pinned by codeModeSnapshot.test.ts and keeps its chips)
const here = path.dirname(new URL(import.meta.url).pathname);
assert.match(
  fs.readFileSync(path.join(here, "../ai-bom/AiBomVisualizations.tsx"), "utf8"),
  /groups=\{groupsForFrameworks\(groups, keys, profileSet \? "" : PROFILE_NOT_SET_SUFFIX\)\}/,
);

// review 6062066749 nits: the static AI BOM chip names its three regulators; with no profile the chip says so
assert.equal(india(FRAMEWORK_GROUPS_AIBOM_WITH_INDIA)?.label, "India / CERT-In / RBI / SEBI");
const unset = groupsForFrameworks(FRAMEWORK_GROUPS_AIBOM_WITH_INDIA, ["rbi_free_ai", "cert_in_aibom", "sebi_cscrf_aibom"],
  PROFILE_NOT_SET_SUFFIX);
assert.equal(india(unset)?.label, "India / CERT-In / RBI / SEBI (profile not set)");
assert.match(
  fs.readFileSync(path.join(here, "../ai-bom/AiBomVisualizations.tsx"), "utf8"),
  /profileSet=\{!applicability \|\| Boolean\(applicability\.regulatory_profile\)\}/,
);

console.log("frameworkLabels tests passed");
