/**
 * Results redesign, page shell (plan §1, §2, §6): the URL writer (section and table view merged in one write), the
 * drill to the findings table (switches view, then scrolls once the table is mounted), the bug fixes on a run (no code
 * scan changes / waves panels; a PQC item opens the run's dialog; RBI / CERT-In "view findings" through the run's
 * table), the summary's figures, and a render of every view of a run.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/views/runViews.test.ts
 */
import "../__tests__/cssStub";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { renderCodeMode } from "../__tests__/codeModeRender";
import { createDrill, drillTarget, pqcRunAssetId, runRefsDrill, scrollToFindings } from "./drill";
import { explainLabel } from "./ExplainPanel";
import { fakeRunSource, POSTURE, renderRunMode, RUN, TARGETS } from "../__tests__/runModeFixture";
import { runProblem, tileFigures, jobsLine } from "./selectors";
import { riskIssues, splitTopRisks } from "./TopRisksSummary";
import { createUrlWriter, DETAIL_SECTIONS, mergeResultsSearch, parseSection, PENDING_MS } from "./url";
import { runDashboardModel, runSectionPlan } from "../model";
import type { RunTableFilters } from "../model";

const read = (...p: string[]) => fs.readFileSync(path.join(__dirname, ...p), "utf8");
const template = read("..", "..", "..", "CbomResults.tsx");

// ------------------------------------------------------------------------------------------------ URL (§1)
test("url: section and view merge into the query, other keys kept", () => {
  assert.equal(mergeResultsSearch("?run=1&origin=chat", { section: "quantum" }), "?run=1&origin=chat&section=quantum");
  assert.equal(mergeResultsSearch("?run=1&section=quantum&view=findings", { section: "", view: "all" }), "?run=1&view=all");
  assert.equal(mergeResultsSearch("run=1", {}), "?run=1");
  assert.equal(mergeResultsSearch("", { section: "" }), "");
  assert.equal(parseSection("inventory"), "inventory");
  assert.equal(parseSection("bogus"), "", "an unknown section is the summary");
  assert.equal(parseSection(null), "");
  assert.deepEqual([...DETAIL_SECTIONS], ["collection", "quantum", "inventory", "migration", "compliance", "remediation"]);
});

test("url: two writes in one tick (view, then section) keep both: one merged URL, push vs replace", () => {
  let url = "?run=1&section=quantum&view=findings";
  const writes: [string, boolean][] = [];
  let t = 1000;
  // the router commits later: read() keeps returning the old URL until we say so
  const w = createUrlWriter({ read: () => url, write: (s, push) => writes.push([s, push]), now: () => t });
  w.patch({ view: "all" });                         // the table's toggle (replace)
  w.patch({ section: "" }, { push: true });         // the drill's return to the summary (push)
  assert.deepEqual(writes, [["?run=1&section=quantum&view=all", false], ["?run=1&view=all", true]]);
  // the router shows the last write: the next one reads the URL again
  url = "?run=1&view=all";
  w.settle(url);
  w.patch({ section: "migration" }, { push: true });
  assert.deepEqual(writes.at(-1), ["?run=1&view=all&section=migration", true]);
  // a write the router never shows (Back pressed meanwhile) stops being the base after PENDING_MS
  url = "?run=1&section=compliance";
  t += PENDING_MS + 1;
  w.patch({ view: "findings" });
  assert.deepEqual(writes.at(-1), ["?run=1&section=compliance&view=findings", false]);
});

test("url: one writer — the route's table toggle goes through useResultsUrl", () => {
  const route = read("..", "RunResultsRoute.tsx");
  assert.match(route, /const \{ patch \} = useResultsUrl\(\);\n\s*const onViewChange = useCallback\(\(next: "findings" \| "all"\) => patch\(\{ view: next \}\), \[patch\]\);/);
  assert.ok(!route.includes("router.replace"), "no second URL writer in the route");
  assert.match(template, /const goSection = useCallback\(\(next: ResultsSection\) => patchResultsUrl\(\{ section: next \}, \{ push: true \}\), \[patchResultsUrl\]\);/,
               "tiles and Back to summary push");
});

// ------------------------------------------------------------------------------------------------ drill (§1)
test("drillToFindings: filters, switches to a view with the table, then asks for the scroll", () => {
  const log: string[] = [];
  const io = (section: Parameters<typeof createDrill>[0]["section"]) => ({
    onFilters: (p: Partial<RunTableFilters>) => log.push(`filters ${JSON.stringify(p)}`),
    section,
    goSection: (s: string) => log.push(`go "${s}"`),
    requestScroll: () => log.push("scroll"),
  });
  createDrill(io("quantum"))({ pqc_group: "any" });
  assert.deepEqual(log, ['filters {"pqc_group":"any"}', 'go ""', "scroll"]);
  log.length = 0;
  createDrill(io(""))({ impact: "High" });
  assert.deepEqual(log, ['filters {"impact":"High"}', "scroll"], "the summary has the table: no view change");
  log.length = 0;
  createDrill(io("remediation"))({ status: "fixed" });
  assert.deepEqual(log, ['filters {"status":"fixed"}', "scroll"], "the remediation view lists the table too");
  for (const s of ["collection", "quantum", "inventory", "migration", "compliance"] as const) assert.equal(drillTarget(s), "");
});

test("drillToFindings: the scroll waits for #bom-findings to be mounted", () => {
  let scrolled = 0;
  const el = { scrollIntoView: () => { scrolled += 1; } };
  assert.equal(scrollToFindings({ getElementById: () => null } as unknown as Document), false);
  assert.equal(scrollToFindings(undefined), false);
  assert.equal(scrollToFindings({ getElementById: (id: string) => (id === "bom-findings" ? el : null) } as unknown as Document), true);
  assert.equal(scrolled, 1);
  const drill = read("drill.ts");
  // from an effect on every render while a scroll is pending (not requestAnimationFrame)
  assert.match(drill, /useEffect\(\(\) => \{\n\s*if \(pending\.current && scrollToFindings\(/);
  assert.ok(!drill.includes("requestAnimationFrame("));
  // every run drill of the template goes through it
  assert.match(template, /const \{ patch, truncated \} = runDrillFilters\(target\);\n\s*drillToFindings\(patch\);/);
  assert.ok(!/run\.onFilters\(/.test(template.replace("createDrill({ onFilters: run.onFilters,", "")), "no direct table filter on a run");
  assert.match(read("SummaryView.tsx"), /onShowAssets=\{\(action\) => ctx\.drill\(readinessDrillFilters\(action\)\)\}/);
  assert.match(read("PostureSummary.tsx"), /onDrill\(readinessDrillFilters\(a\)\)/);
});

// ------------------------------------------------------------------------------------------------ bug fixes (§0)
test("(a) a run never mounts the code scan's changes and waves panels (they read and write code scan #<run id>)", () => {
  assert.match(template, /\{!run && cryptoDistributions && Number\.isFinite\(tid\) && tid > 0 && Number\.isFinite\(sid\) && sid > 0 && \(\n\s*<>\n\s*<CodeChanges teamId=\{tid\} scanId=\{sid\} \/>\n\s*<CodeWavesPanel teamId=\{tid\} scanId=\{sid\} \/>/);
  // rendered: a run with distributions (what used to mount them) on every view
  for (const s of ["", ...DETAIL_SECTIONS]) {
    const html = renderRunMode(s ? `section=${s}` : "");
    assert.ok(!html.includes('data-testid="code-changes"') && !html.includes('data-testid="code-waves"'), `no code panels on "${s}"`);
  }
});

test("(b) a PQC list item on a run opens the run's dialog for its asset; the code dialog is gated", () => {
  assert.equal(pqcRunAssetId({ id: "zs-asset-12", bom_ref: "zs-asset-12" }), 12);
  assert.equal(pqcRunAssetId({ id: "x", bom_ref: null, asset_id: 9 }), 9, "asset_id first");
  assert.equal(pqcRunAssetId({ id: "RSA", bom_ref: "crypto-rsa-1" }), null, "a code bom-ref is no run asset");
  assert.match(template, /const id = pqcRunAssetId\(f as CbomFinding & \{ asset_id\?: number \| null \}\);\n\s*if \(id != null\) run\.openAsset\(id,/);
  assert.match(template, /onOpenPqcFinding: openRunPqcFinding,/);
  for (const v of ["InventoryView.tsx", "MigrationView.tsx"]) assert.match(read(v), /onOpenFinding=\{ctx\.onOpenPqcFinding\}/, v);
  assert.match(template, /<Dialog open=\{!run && !!selectedFinding\}/, "the code scan's finding dialog never opens on a run");
  assert.match(read("..", "..", "CbomCryptoCharts.tsx"), /asset_id\?: number \| null;/, "the run migration row's asset_id is typed");
});

test("(c) RBI CSF / CERT-In 'view findings' on a run filter the run's table by asset, or say there is none", () => {
  const d = runRefsDrill(["zs-asset-4", "zs-asset-5", "crypto-x"], "Assets of this requirement");
  assert.ok(d);
  assert.deepEqual(d!.patch.asset_ids, [4, 5]);
  assert.equal(d!.patch.view, "all");
  assert.equal(runRefsDrill(["crypto-x"], "x"), null, "no run asset: no unfiltered table under a drill label");
  const view = read("ComplianceView.tsx");
  assert.match(view, /<RbiCsfRollup [^>]*onViewFindings=\{ctx\.onViewRefs\}/);
  assert.match(view, /<CertInLanePosture [^>]*onViewFindings=\{ctx\.onViewRefs\}/);
  assert.ok(!/onAttest=/.test(view), "a run never attests");
  assert.match(template, /onViewRefs: handleViewRunRefs,/);
  assert.match(template, /const d = runRefsDrill\(refs, "Assets of this requirement"\);[^]*?drillToFindings\(d\.patch\);/);
});

// ------------------------------------------------------------------------------------------------ figures (§2)
test("status banner: what the run did not read, and nothing when it read everything", () => {
  const p = runProblem(RUN, { assets: 3, targets: TARGETS });
  assert.deepEqual(p?.lines, ["The run finished partly: some jobs or targets were not read.", "1 job of 2 ended with an error.", "1 target not fully read."]);
  const ok = { ...RUN, status: "done" as const, jobs: [RUN.jobs![0]] };
  assert.equal(runProblem(ok, { assets: 3, targets: [TARGETS[0]] }), null);
  assert.deepEqual(runProblem(ok, { assets: 0, targets: [] })?.lines, ["No asset was read."]);
  assert.equal(jobsLine(RUN.jobs), "2 jobs: 1 done, 1 failed");
});

test("drill tiles: each from its view's data; a dash and the view's note when there is none", () => {
  const src = fakeRunSource();
  const fig = tileFigures({ run: RUN, posture: POSTURE, plan: src.plan, resultsPending: false, dashboardModel: src.dashboardModel,
    distributions: src.results!.distributions!, frameworks: [{ framework: "NIST", verdict: "fail" } as never],
    waves: { byWave: { "1": 1, "4": 1 }, loading: false, deferred: false } });
  assert.equal(fig.collection.value, "2 jobs: 1 done, 1 failed · 3 assets");
  assert.equal(fig.quantum.value, "Q1 Critical 1 · Q2 High 1 · Q4 Low 1 · self-fixable 66.7%");
  assert.equal(fig.inventory.value, "5 crypto assets · 0 certificates · 1 key");
  assert.equal(fig.migration.value, "1 quantum-vulnerable asset · 1 fix");
  assert.match(fig.compliance.value, /^NIST /);
  assert.equal(fig.remediation.value, "Wave 1: 1 · Wave 4: 1");
  // an older backend: no /results
  const missing = runSectionPlan({ results: { kind: "missing" }, posture: POSTURE });
  const old = tileFigures({ run: RUN, posture: null, plan: missing, resultsPending: false, dashboardModel: runDashboardModel(null, null),
    distributions: null, frameworks: [], waves: { byWave: null, loading: false, deferred: true } });
  assert.equal(old.inventory.value, "—");
  assert.match(old.inventory.note ?? "", /does not offer the run results summary/);
  assert.equal(old.migration.value, "—");
  assert.ok(old.quantum.loading, "the posture is still loading");
  assert.match(old.remediation.note ?? "", /when the run has finished/);
});

test("explain label and top risks split", () => {
  assert.equal(explainLabel("16.7%"), "Explain 16.7%");
  assert.equal(explainLabel("—"), "Explain PQC readiness");
  assert.equal(explainLabel("Not enough identified"), "Explain PQC readiness");
  assert.deepEqual(riskIssues("SSLv3 accepted; TLS 1.0 accepted"), ["SSLv3 accepted", "TLS 1.0 accepted"]);
  assert.deepEqual(riskIssues(null), []);
  assert.deepEqual(splitTopRisks([1, 2, 3, 4, 5]), { cards: [1, 2, 3], rest: [4, 5] });
});

// ------------------------------------------------------------------------------------------------ render (§2, §3)
const count = (html: string, s: string) => html.split(s).length - 1;

test("summary: hero, status area with the jobs line, KPIs, posture, explain, top risks once, tiles, findings table", () => {
  const html = renderRunMode();
  const order = ['data-testid="results-hero"', 'data-testid="run-status-area"', 'data-testid="run-summary-kpis"', 'data-testid="run-posture"',
    'data-testid="readiness-explain"', 'data-testid="run-top-risks"', 'data-testid="results-drill"', 'id="bom-findings"'];
  const at = order.map((s) => html.indexOf(s));
  assert.ok(at.every((i, n) => i > 0 && (n === 0 || i > at[n - 1])), JSON.stringify(order.map((s, n) => [s, at[n]])));
  assert.equal(count(html, 'data-testid="cbom-results-title"'), 1);
  for (const j of TARGETS) assert.equal(count(html, `data-testid="run-results-job-${j.job_id}"`), 1, `job ${j.job_id} on the summary`);
  assert.equal(count(html, 'data-testid="run-status-banner"'), 1);
  assert.equal(count(html, 'data-testid="cbom-coverage-notes"'), 1, "the run's coverage notes");
  assert.equal(count(html, 'data-testid="run-lab-mode"'), 1, "the lab-mode note on the summary");
  for (const id of ["run-results-download", "run-results-download-xml", "run-results-download-oscal", "run-verify-signature", "run-results-compare",
    "run-results-open-sources", "run-results-status", "run-results-credits", "run-meta-sources", "posture-readiness", "posture-hndl", "posture-mosca", "mosca-edit",
    "posture-class-quantum-vulnerable", "run-kpi-readiness", "run-kpi-assets", "run-kpi-avg_risk"]) {
    assert.ok(html.includes(`data-testid="${id}"`), id);
  }
  // each top risk once (cards then the table), with the posture's heading as the subtitle; clauses + Z note follow them
  for (const r of POSTURE.top_risks) assert.equal(count(html, `data-testid="run-top-risk-${r.id}"`), 1, `risk ${r.id}`);
  assert.match(html, /Highest risk \(impact × business criticality × internet exposure\)/);
  assert.match(html, /Scored with the criticality and exposure the sources had when this run started\./);
  assert.equal(count(html, 'data-testid="posture-compliance-toggle"'), 1);
  assert.ok(html.indexOf('data-testid="posture-compliance-toggle"') > html.indexOf('data-testid="run-top-risks"'), "the clauses follow the risks");
  assert.equal(count(html, 'data-testid="posture-z-note"'), 1);
  // the explanation is in the page, collapsed
  assert.match(html, /aria-expanded="false"[^>]*data-testid="readiness-explain-toggle"/);
  assert.match(html, /<div id="readiness-explain-[^"]*" hidden=""><div [^>]*data-testid="pqc-readiness-explained" data-layout="columns"/);
  for (const s of DETAIL_SECTIONS) assert.equal(count(html, `data-testid="results-tile-${s}"`), 1, `tile ${s}`);
  // no heavy chart on the summary
  assert.ok(!html.includes('data-testid="run-section-dashboard"') && !html.includes('data-testid="run-section-coverage"'));
});

test("a run with 1–3 top risks still shows every column tip (cards carry the labelled fields)", () => {
  const COLS = ["cbom.run.top_risks", "cbom.run.col.priority", "cbom.run.col.asset", "results.table.impact", "cbom.run.col.source",
    "cbom.run.col.criticality", "cbom.run.col.exposure", "cbom.run.col.hndl"];
  for (const n of [1, 2, 3]) {
    const p = { ...POSTURE, top_risks: POSTURE.top_risks.slice(0, n) };
    const html = renderRunMode("", fakeRunSource({ posture: p, plan: runSectionPlan({ results: { kind: "ok", data: fakeRunSource().results! }, posture: p }) }), p);
    const sec = html.slice(html.indexOf('data-testid="run-top-risks"'), html.indexOf('data-testid="results-drill"'));
    for (const id of COLS) assert.ok(sec.includes(`data-infotip="${id}"`), `${n} risk(s): ${id}`);
    assert.ok(!sec.includes('data-testid="run-top-risk-table"'), `${n} risk(s): no table`);
  }
});

test("a run with no top risk keeps the clauses toggle and the Z note in the posture card", () => {
  const p = { ...POSTURE, top_risks: [] };
  const html = renderRunMode("", fakeRunSource({ posture: p, plan: runSectionPlan({ results: { kind: "ok", data: fakeRunSource().results! }, posture: p }) }), p);
  assert.ok(!html.includes('data-testid="run-top-risks"'));
  const posture = html.slice(html.indexOf('data-testid="run-posture"'), html.indexOf('data-testid="results-drill"'));
  assert.ok(posture.includes('data-testid="posture-compliance-toggle"') && posture.includes('data-testid="posture-z-note"'));
});

test("every detail view: the hero on top, Back to summary, its title, its sections; one findings table at most", () => {
  const expect: Record<string, string[]> = {
    collection: ['data-testid="run-section-coverage"', 'data-testid="run-results-targets"'],
    quantum: ['data-testid="run-quantum-cards"'],
    inventory: ['data-testid="run-section-dashboard"', 'data-testid="run-certificates-card"'],
    migration: [],
    compliance: ['data-testid="run-section-compliance"'],
    remediation: ['data-testid="run-section-waves"', 'data-testid="run-section-changes"', 'id="bom-findings"'],
  };
  for (const s of DETAIL_SECTIONS) {
    const html = renderRunMode(`section=${s}`);
    assert.ok(html.indexOf('data-testid="results-hero"') >= 0 && html.indexOf('data-testid="results-hero"') < html.indexOf(`data-testid="results-section-${s}"`), s);
    assert.ok(html.includes('data-testid="results-back"'), `${s}: back`);
    assert.ok(!html.includes('data-testid="results-summary"'), `${s}: not the summary`);
    for (const want of expect[s]) assert.ok(html.includes(want), `${s}: ${want}`);
    assert.ok(count(html, 'id="bom-findings"') <= 1, `${s}: #bom-findings unique`);
    // the lab-mode note: the collection view's jobs card has it, the hero on the others; never twice
    assert.equal(count(html, 'data-testid="run-lab-mode"'), 1, `${s}: lab note once`);
  }
});

test("deep links: a view whose data is loading shows a loader; an older backend shows the view with its notes", () => {
  const loading = fakeRunSource({ resultsState: { kind: "loading" }, results: null, plan: runSectionPlan({ results: { kind: "loading" }, posture: POSTURE }) });
  for (const s of ["inventory", "migration", "compliance"]) {
    assert.ok(renderRunMode(`section=${s}`, loading).includes(`data-testid="results-section-${s}-loading"`), s);
  }
  const plan = runSectionPlan({ results: { kind: "missing" }, posture: POSTURE });
  const old = fakeRunSource({ resultsState: { kind: "missing" }, results: null, plan, parityState: "missing", parity: null });
  const inv = renderRunMode("section=inventory", old);
  assert.ok(inv.includes('data-testid="results-section-inventory"') && inv.includes('data-testid="run-crypto-charts-note"'), "the not-available note");
  assert.ok(inv.includes('data-testid="results-back"'), "and a way back");
  assert.ok(renderRunMode("section=migration", old).includes('data-testid="run-migration-note"'));
  assert.ok(renderRunMode("section=compliance", old).includes('data-testid="run-rbi-note"'));
});

test("a code scan ignores ?section=", () => {
  // codeModeUnchanged.test.ts pins the default render; with a section in the URL it is the same page
  assert.equal(renderCodeMode("section=quantum"), renderCodeMode());
  assert.match(template, /const section: ResultsSection = run \? resultsUrl\.section : "";/);
});

test("(c) the run's compliance view lets RBI CSF / CERT-In requirements show 'View related findings'", async () => {
  // the drilldown hides the button when given a findings list with no related rows; a run's findings are server-paged,
  // so the run view must pass none (unknown count) rather than an empty list
  const view = read("ComplianceView.tsx");
  assert.ok(!/<RbiCsfRollup [^>]*findings=/.test(view) && !/<CertInLanePosture [^>]*findings=/.test(view), "no findings list on a run");
  const { RbiCsfRequirementDrilldown } = await import("@/components/rbi/RbiCsfRequirementDrilldown");
  const { renderToStaticMarkup } = await import("react-dom/server");
  const React = await import("react");
  const rollup = JSON.parse(read("..", "__tests__", "complianceRollupFixture.json")).rbi_csf_rollup;
  const pillar = (rollup.rbi_csf_rollup ?? rollup).identification;
  const render = (findings?: []) => renderToStaticMarkup(React.createElement(RbiCsfRequirementDrilldown,
    { pillarKey: "identification", requirements: pillar.requirements, onViewFindings: () => {}, findings }));
  assert.ok(render().includes("View related findings"), "without a findings list (run): the drill is offered");
  assert.ok(!render([]).includes("View related findings"), "with an empty list (the bug): no button");
});

test("inventory: all three certificate tabs stay mounted (their tips and state are kept)", () => {
  const html = renderRunMode("section=inventory");
  for (const t of ["expiry", "calendar", "orphaned"]) assert.ok(html.includes(`data-testid="run-certificates-tab-${t}"`), t);
  assert.ok(html.includes('data-infotip="cbom.run.certificates"'));
  // the expiry tab is the default; the orphaned / unmanaged section (its tip and testid) lives in an inactive tab and must
  // still be in the page (hidden, not unmounted)
  assert.ok(html.includes('data-testid="run-section-certificates"') && html.includes('data-infotip="cbom.run.certs"'),
    "the inactive Orphaned and unmanaged panel is rendered");
});

test("Explanations drawer: every tip rendered by a run view is listed for that view", async () => {
  const { drawerIds } = await import("../../../../content/infotips/drawerManifest");
  const views: Array<[string, string]> = [["", "run.summary"], ["section=collection", "run.collection"], ["section=quantum", "run.quantum"],
    ["section=inventory", "run.inventory"], ["section=migration", "run.migration"], ["section=compliance", "run.compliance"], ["section=remediation", "run.remediation"]];
  for (const [search, view] of views) {
    const html = renderRunMode(search);
    const shown = new Set([...html.matchAll(/data-infotip="([^"]+)"/g)].map((m) => m[1]));
    const listed = new Set<string>(drawerIds(view as Parameters<typeof drawerIds>[0]));
    const missing = [...shown].filter((id) => !listed.has(id));
    assert.deepEqual(missing, [], `${view}: rendered but not in the drawer`);
  }
});
