// The run Results table row the gate records (G11), read from the row's own data-* attributes (RunFindingsTable:
// assetRowAttrs + data-type-label), never by column position: the table hides columns by default and per user
// (#267), so cell N is not a fixed field. The output keeps the keys and text forms harness/fieldmap.ui_observed reads
// (impact "Info" when none, the type label, "<algorithm or protocol or —>[ <key size>]", finding "—" when none,
// quantum "Vulnerable" / "Safe" / "—"). Pure, so `node --test e2e/cbom/flow/` covers it without a browser.

/** What the page's $$eval returns for one row: its data-testid, its dataset and the visible cells by data-col. */
export function runRowFromDom({ testid, data = {}, cells = {} }) {
  const id = Number(String(testid).replace(/^run-asset-/, ""));
  const alg = data.algorithm || "—";
  const quantum = data.quantum === "vulnerable" ? "Vulnerable" : data.quantum === "safe" ? "Safe" : "—";
  return {
    id,
    impact: data.impact || "Info",
    type: data.typeLabel || data.type || null,
    location: data.location || null,
    target: data.target && data.target !== data.location ? data.target : null,
    algorithm: data.keySize ? `${alg} ${data.keySize}` : alg,
    finding: data.finding || "—",
    quantum,
    status: data.status || null,
    // the columns the customer saw (for the screenshot record only; never judged)
    visible_columns: Object.keys(cells),
  };
}

/** Runs in the page: every run-asset-<id> row as {testid, data, cells}. Passed to page.$$eval as is. */
export function collectRunRows(trs) {
  return trs.filter((tr) => /^run-asset-\d+$/.test(tr.dataset.testid)).map((tr) => ({
    testid: tr.dataset.testid,
    data: { ...tr.dataset },
    cells: Object.fromEntries([...tr.querySelectorAll("td[data-col]")].map((td) => [td.dataset.col, td.textContent.trim()])),
  }));
}
