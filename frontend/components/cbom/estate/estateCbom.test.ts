/**
 * CB-26: the estate CBOM download. Parameters, file name from the server (or built the same way), headers read into
 * what the page shows, and the result line with its hooks.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/estate/estateCbom.test.ts
 */
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { EstateCbomResult } from "./EstateCbomDownload";
import { estateFileName, estateParams, readEstateHeaders } from "./estateCbom";

assert.deepEqual(estateParams("xml", { application: " Payments ", source: "", type: undefined }),
  { format: "xml", application: "Payments" });
assert.equal(estateFileName(3, "json", 'attachment; filename="cbom-estate-team3-2026-11-14.cdx.json"'),
  "cbom-estate-team3-2026-11-14.cdx.json");
assert.equal(estateFileName(3, "xml", null, new Date("2026-11-14T23:30:00Z")), "cbom-estate-team3-2026-11-14.cdx.xml");
const sha = "a".repeat(64);
const info = readEstateHeaders(3, "json", {
  "content-disposition": 'attachment; filename="x.cdx.json"', "x-cbom-sha256": sha, "x-cbom-signature": "unsigned",
  "x-cbom-assets": "12",
});
assert.deepEqual(info, { fileName: "x.cdx.json", sha256: sha, signature: "unsigned", assets: 12 });
assert.equal(readEstateHeaders(3, "json", {}).assets, null);
const html = renderToStaticMarkup(React.createElement(EstateCbomResult, { info }));
assert.match(html, /data-testid="estate-cbom-result"/);
assert.match(html, /12 assets · unsigned · SHA-256/);
assert.ok(html.includes(`data-testid="estate-cbom-sha256">${sha}</code>`));
console.log("estateCbom.test.ts: ok");
