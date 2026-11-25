/**
 * PR #500 review 6061095673 #6: the configuration mentions (not counted) are visible on the results page: a collapsed
 * section with the total, the first CONFIG_MENTIONS_SHOWN rows, and nothing when there are none.
 * Run (frontend/): npx --yes tsx@4.23.15 --test components/cbom/results/configMentions.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { CONFIG_MENTIONS_SHOWN, ConfigMentions } from "./ConfigMentions";

const h = React.createElement;
const mention = (i: number) => ({ location: "src/settings.py", line: i, algorithm: "md5", binding: "algo", value: "md5" });

test("collapsed section with the total and a capped list", () => {
  const rows = Array.from({ length: 60 }, (_, i) => mention(i + 1));
  const html = renderToStaticMarkup(h(ConfigMentions, { mentions: rows, total: 73 }));
  assert.match(html, /<details[^>]*data-testid="cbom-config-mentions"/);
  assert.ok(!/<details[^>]*\bopen\b/.test(html), "collapsed by default");
  assert.match(html, /Configuration mentions \(not counted\) · 73/);
  assert.equal((html.match(/<li /g) ?? []).length, CONFIG_MENTIONS_SHOWN);
  assert.match(html, /The first 50 of 73 are listed/);
  assert.match(html, /src\/settings\.py:1/);
});

test("nothing when there is no mention", () => {
  assert.equal(renderToStaticMarkup(h(ConfigMentions, { mentions: [], total: 0 })), "");
  assert.equal(renderToStaticMarkup(h(ConfigMentions, { mentions: null })), "");
});

test("the code scan results page renders it from the scan metadata", () => {
  const src = readFileSync(new URL("../../CbomResults.tsx", import.meta.url), "utf8");
  assert.match(src, /<ConfigMentions\s+mentions=\{[^}]*config_evidence[^}]*\}\s+total=\{[^}]*config_evidence_total/);
});
