/** Engine step 3 drawer section. Run (frontend/): npx --yes tsx@4.23.15 components/cbom/estate/correlation.test.ts */
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { CorrelationSection } from "./Correlation";
import { classificationText, gaps, linkText, scanHref, type Correlation } from "./correlation";

const C: Correlation = {
  estate_key: "ep:" + "a".repeat(40), owners: ["Alice", "Bob"], applications: ["Payments"], data_classification: "restricted",
  data_classifications: ["confidential", "restricted"], conflicts: ["owner", "data_classification"], unknown: [],
  links: [{ kind: "sbom", scan_id: 501, scan_title: "payments sbom", component: "openssl@1.1.1k", purl: null, match: "name_version" }],
};
assert.equal(classificationText(C), "Restricted (highest of 2 systems)");
assert.equal(classificationText({ data_classification: null }), "Not set");
assert.equal(linkText(C.links[0]), "SBOM scan #501 (payments sbom): openssl@1.1.1k, same name and version");
assert.equal(scanHref(1, C.links[0]), "/1/sbom_sca/501/results");
assert.deepEqual(gaps(C), ["Its sources disagree on the owner, data classification."]);
assert.deepEqual(gaps({ unknown: ["owner", "data_classification"], conflicts: [] }), ["No source names its owner, data classification."]);
const html = renderToStaticMarkup(React.createElement(CorrelationSection, { teamId: 1, correlation: C }));
assert.ok(html.includes("Alice, Bob") && html.includes('data-class="restricted"') && html.includes("/1/sbom_sca/501/results"));
assert.ok(renderToStaticMarkup(React.createElement(CorrelationSection, { correlation: null })).includes("Not in the team estate yet"));
assert.equal(renderToStaticMarkup(React.createElement(CorrelationSection, { correlation: undefined })), "");
console.log("correlation.test.ts: ok");
