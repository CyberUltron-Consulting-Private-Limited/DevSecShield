// node --test e2e/cbom/flow/  (no browser): G11 reads run Results rows from their data-* attributes (#282 review)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { collectRunRows, runRowFromDom } from "./rows.mjs";

// dataset of a row as RunFindingsTable renders it (assetRowAttrs + data-type-label), in the browser's camelCase
const TLS = {
  testid: "run-asset-11",
  data: { testid: "run-asset-11", impact: "High", type: "tls_endpoint", typeLabel: "TLS endpoint", location: "10.0.0.5:443",
          target: "web01", algorithm: "TLS 1.2", keySize: "", finding: "Accepts RSA key exchange", quantum: "vulnerable",
          status: "not_started" },
  // the default columns only: Type and Finding are hidden, so a positional reader would misread every field
  cells: { select: "", impact: "High", algorithm: "TLS 1.2", where: "10.0.0.5:443web01", quantum: "Vulnerable",
           risk: "7.5", status: "not started", actions: "ActionDetails" },
};

test("a row is read from its attributes, in fieldmap.ui_expected's text forms", () => {
  assert.deepEqual(runRowFromDom(TLS), {
    id: 11, impact: "High", type: "TLS endpoint", location: "10.0.0.5:443", target: "web01", algorithm: "TLS 1.2",
    finding: "Accepts RSA key exchange", quantum: "Vulnerable", status: "not_started",
    visible_columns: ["select", "impact", "algorithm", "where", "quantum", "risk", "status", "actions"],
  });
});

test("the same row whatever columns are shown", () => {
  const allCols = { ...TLS, cells: { ...TLS.cells, type: "TLS endpoint", finding: "Accepts RSA key exchange", wave: "Wave 1" } };
  const { visible_columns: a, ...left } = runRowFromDom(TLS);
  const { visible_columns: b, ...right } = runRowFromDom(allCols);
  assert.deepEqual(left, right);
  assert.notDeepEqual(a, b);
});

test("empty values take the table's fallbacks", () => {
  const row = runRowFromDom({ testid: "run-asset-7", data: { impact: "", type: "certificate", location: "/a.pem", target: "/a.pem",
                                                             algorithm: "RSA", keySize: "2048", finding: "", quantum: "" } });
  assert.equal(row.id, 7);
  assert.equal(row.impact, "Info");
  assert.equal(row.type, "certificate", "an older build without data-type-label: the raw type (fails the join closed)");
  assert.equal(row.target, null, "target only when it differs from the location");
  assert.equal(row.algorithm, "RSA 2048");
  assert.equal(row.finding, "—");
  assert.equal(row.quantum, "—");
  assert.equal(runRowFromDom({ testid: "run-asset-8", data: { quantum: "safe" } }).algorithm, "—");
  assert.equal(runRowFromDom({ testid: "run-asset-8", data: { quantum: "safe" } }).quantum, "Safe");
});

test("collectRunRows keeps run-asset-<id> rows only and reads cells by data-col", () => {
  const td = (col, text) => ({ dataset: { col }, textContent: ` ${text} ` });
  const tr = (testid, cells, extra = {}) => ({ dataset: { testid, ...extra }, querySelectorAll: () => cells });
  const out = collectRunRows([
    tr("run-asset-3", [td("impact", "Low"), td("where", "x")], { impact: "Low" }),
    tr("run-asset-select-3", []),
    tr("run-asset-details-3", []),
  ]);
  assert.deepEqual(out, [{ testid: "run-asset-3", data: { testid: "run-asset-3", impact: "Low" }, cells: { impact: "Low", where: "x" } }]);
});

test("gate.mjs uses the attribute reader and closes the finding dialog after the drill-down", () => {
  const gate = readFileSync(new URL("./gate.mjs", import.meta.url), "utf8");
  assert.match(gate, /\$\$eval\('\[data-testid\^="run-asset-"\]', collectRunRows\)\)\.map\(runRowFromDom\)/);
  assert.ok(!/td\[\d\]/.test(gate), "no positional cell reads");
  const drill = gate.indexOf('await s.shot(page, "drilldown");');
  const esc = gate.indexOf('await page.keyboard.press("Escape")', drill);
  const g12 = gate.indexOf('await step("G12"');
  assert.ok(drill > 0 && esc > drill && esc < g12, "Escape after the drilldown screenshot, before G12");
  assert.match(gate.slice(esc, g12), /getByTestId\("run-finding-dialog"\)\.waitFor\(\{ state: "hidden"/);
});
