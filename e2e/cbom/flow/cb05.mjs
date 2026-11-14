// CB-05: the customer steps of the CBOM Tier-L gate that CB-01's runner left open (DEVILS-ADVOCATE.md §4.3):
// G4 servers, G5b IDNA, G6 database, G7 cloud & identity, G8 evidence + vendor link, the G9 rate recomputation, the G10
// charge after runtime skips, G11 posture / calendar / Mosca, G12 validators and VEX states, G13 drift and G13b drift
// with a never-scan entry in range. gate.mjs builds one context object (`ctx`) and calls these functions at its
// placeholders (round6/cbom/INTERFACES.md v5).
//
// Rules kept (§4.1): every state change goes through the UI as the customer; the API is only read, with the customer's
// own token; the lab's administrator (gen.py, `docker exec` into a lab host) does what a customer's sysadmin would do
// on their own server (install the node's public key, change the servers between runs) and every such action is
// recorded in steps/<G>/customer-side.json. Expected values come from the lab oracle (CB-02), the rates and rules the
// spec states (§4.3 G9, OA-10b, OA-10c), or the owner's staging snapshot; never from the product.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { plannedCharge, RATES_C } from "./rates.mjs";

// ------------------------------------------------------------------------------------------------ oracle constants
export { RATES_C };  // the spec's rates live in rates.mjs (CB-01's G9 and CB-05's G10 use the same rule)
// The owner's staging snapshot (round6/cbom/owner-staging-snapshot.md), word for word.
export const AWS_NOT_CONFIGURED_TEXT = "This ZeroShield deployment is not set up for AWS collection; contact your administrator";
// OA-10c (DA default): observed weakness -> exploitable; future-risk code -> in_triage; drift-resolved -> resolved.
export const VEX_FUTURE_RISK = new Set(["QUANTUM_VULNERABLE", "NO_PQ_KEX", "SSH_NO_PQ_KEX"]);
// Statuses a target can be skipped with at run time (OA-10b: refunded); the UI's labels for them.
export const RUNTIME_SKIPS = new Set(["skipped_never_scan", "skipped_window", "skipped_stop", "skipped_deadline", "skipped_cancelled"]);
const DAY = 86400000;

// ------------------------------------------------------------------------------------------------ small helpers
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const dateOnly = (d) => d.toISOString().slice(0, 10);

/** Accepted connections a lab listener logged in [from, to] (UTC ISO); null when its log is missing. */
export function accepts(ctx, name, from, to) {
  const l = (ctx.lab?.listeners || []).find((x) => x.name === name);
  if (!l) return null;
  const p = join(ctx.RUN, l.log || `lab/listeners/${name}.jsonl`);
  if (!existsSync(p)) return null;
  const lo = Date.parse(from) - 999, hi = Date.parse(to) + 999;
  return readFileSync(p, "utf8").split("\n").filter(Boolean).map((ln) => { try { return JSON.parse(ln); } catch { return null; } })
    .filter((e) => e && Date.parse(e.ts) >= lo && Date.parse(e.ts) <= hi).length;
}

/** O-8: a missing canary log reads as 0 only when the control's log in the same window shows accepts. */
function canaryCount(ctx, canary, control, from, to) {
  const c = accepts(ctx, canary, from, to);
  const k = accepts(ctx, control, from, to);
  return { canary: c ?? ((k || 0) > 0 ? 0 : null), control: k };
}

function customerSide(ctx, gate, action) {
  const p = join(ctx.RUN, "steps", gate, "customer-side.json");
  const doc = ctx.readJson(p) || { note: "actions of the lab's administrator on the lab's own servers (a customer's sysadmin), not product side doors", actions: [] };
  doc.actions.push({ at: ctx.iso(), ...action });
  ctx.writeJson(p, doc);
}

function deferred(ctx, part) {
  return (ctx.lab?.deferred || []).find((d) => d.part === part && d.deferred) || null;
}

/** A lab part CB-02 marks deferred (lab.json deferred[]): NOT-RUN with the marking's reason, never pass or silence.
 * `gate` lets G4 report the G15 row of the same part (the ForceCommand allow-list needs the Tier-2 host). */
function notRunDeferred(ctx, s, part, gate = s.gate, what = "") {
  const d = deferred(ctx, part);
  if (!d) return false;
  const id = `deferred_${part}`;  // the judge adds `<G>/deferred_<part>` for any part no step recorded (CB-01 943b820)
  s.checks.push({ id: `${gate}/${id}`, gate, kind: "flow", verdict: "NOT-RUN", reason: `lab part deferred by CB-02: ${d.reason}`, expected: null, observed: null, evidence: [],
    subject: { check: "deferred", part, address: d.address ?? null, gates: d.gate ?? null, issue: d.issue ?? null, issue_draft: d.issue_draft ?? null, ...(what ? { what } : {}) } });
  console.log(`  NOT-RUN ${gate}/${id}: deferred by CB-02`);
  return true;
}

/** The customer opens a CBOM Sources tab: closes whatever sheet or dialog is open, clicks the tab by its label, and
 * opens the tab's URL (?tab=<value>) only when no tab is on the page. */
const TAB_VALUE = { "Scan nodes": "scan-nodes", Servers: "servers", "Kubernetes & Databases": "k8s-db", "Cloud & Identity": "cloud",
  "Network TLS": "network", Evidence: "evidence", "Review & Run": "review" };
async function openTab(ctx, label) {
  const { page } = ctx.A;
  for (let i = 0; i < 3 && (await page.getByRole("dialog").count()); i++) { await page.keyboard.press("Escape"); await page.waitForTimeout(300); }
  const tab = page.getByRole("tab", { name: label, exact: true });
  if (await tab.count()) await tab.first().click();
  else await page.goto(`${ctx.UI}/${ctx.A.team}/cbom/sources?tab=${TAB_VALUE[label]}`, { waitUntil: "networkidle" });
  await page.waitForFunction((v) => new URLSearchParams(location.search).get("tab") === v, TAB_VALUE[label], { timeout: 15000 }).catch(() => {});
  await page.waitForLoadState("networkidle");
}

function sourceOf(ctx, name) { return (ctx.lab?.sources || []).find((x) => x.name === name) || null; }

async function pickNode(page, testId) {
  await page.getByTestId(testId).locator("button, [role=combobox]").first().click();
  await page.getByRole("option", { name: /e2e-node-1/ }).first().click();
}

function dbSource(ctx, name) {
  const [row] = ctx.db(`SELECT id, kind, last_test_status, coalesce(last_test_result::text, '{}'), config::text FROM cbomcollectionsource WHERE team_id = ${ctx.A.team} AND name = '${name.replace(/'/g, "''")}'`);
  if (!row) return null;
  return { id: Number(row[0]), kind: row[1], status: row[2], result: JSON.parse(row[3] || "{}"), config: JSON.parse(row[4] || "{}") };
}

async function waitTest(ctx, name, maxMs = 150000) {
  const t0 = Date.now();
  let src = null;
  while (Date.now() - t0 < maxMs) {
    src = dbSource(ctx, name);
    const samples = src?.result?.samples || [];
    const done = src && !["pending", "never", "running", "queued"].includes(src.status) && !samples.some((x) => ["pending", "running"].includes(x.status));
    if (done) break;
    await ctx.sleep(3000);
  }
  return src;
}

function addScope(ctx, name) {
  ctx.state.scope = ctx.state.scope || { sources: [], ranges: [] };
  if (!ctx.state.scope.sources.includes(name)) ctx.state.scope.sources.push(name);
  ctx.state.configured = [...new Set([...(ctx.state.configured || []), name])];
}

/** Servers tab: one Linux source through the UI form; returns the window [from, to] of its Save-and-test. */
async function addServerSource(ctx, s, { name, targets, port, neverScan, installNodeKeyOn }) {
  const { page } = ctx.A;
  await page.goto(`${ctx.UI}/${ctx.A.team}/cbom/sources?tab=servers`, { waitUntil: "networkidle" });
  await page.getByTestId("servers-kind-linux").click().catch(() => {});
  await page.fill("#servers-name", name);
  await pickNode(page, "servers-node");
  await page.fill("#servers-targets", targets.join("\n"));
  if (port) await page.fill("#servers-port", String(port));
  if (neverScan?.length) await page.fill("#servers-exclusions", neverScan.join("\n"));
  // the node's own key (the default credential): the customer copies it from the page and installs it on the server
  const keyEl = page.getByTestId("servers-node-key");
  await keyEl.waitFor({ timeout: 20000 });
  const pub = ((await keyEl.textContent()) || "").trim();
  s.check(`${name}_node_key_shown`, /^ssh-(ed25519|rsa) [A-Za-z0-9+/=]+/.test(pub), { expected: "the node's SSH public key", observed: pub.slice(0, 40) });
  if (installNodeKeyOn) {
    const r = spawnSync("docker", ["exec", "-i", installNodeKeyOn, "sh", "-c", 'umask 077; mkdir -p "$HOME/.ssh"; cat >> "$HOME/.ssh/authorized_keys"'], { input: pub + "\n", encoding: "utf8" });
    customerSide(ctx, s.gate, { what: `installed the node's public key for the login user on ${installNodeKeyOn}`, exit: r.status, key_sha256: ctx.sha256(pub) });
    s.check(`${name}_node_key_installed`, r.status === 0, { expected: "authorized_keys updated by the server admin", observed: (r.stderr || "").slice(0, 160) || "ok", reason: "lab" });
  }
  if (installNodeKeyOn) {
    await page.getByTestId("servers-view-commands").click().catch(() => {});
    const cmds = await page.getByTestId("servers-commands").locator("code, li").allTextContents().catch(() => []);
    ctx.writeJson(join(ctx.RUN, "steps", s.gate, "commands-ui.json"), { tier: 1, commands: cmds.map((c) => c.trim()).filter(Boolean) });
  }
  const from = ctx.iso();
  await page.getByTestId("servers-save-test").click();
  const toast = await Promise.race([
    page.getByText(/saved|testing|connection test/i).first().waitFor({ timeout: 20000 }).then(() => "ok"),
    page.locator("[role=alert]").filter({ hasText: /./ }).first().waitFor({ timeout: 20000 }).then(async () => `alert: ${(await page.locator("[role=alert]").first().textContent())?.slice(0, 160)}`),
  ]).catch(() => "no feedback");
  const src = await waitTest(ctx, name);
  await ctx.sleep(1500);
  const to = ctx.iso();
  s.check(`${name}_saved`, !!src, { expected: `source ${name} in the DB`, observed: src ? { id: src.id, status: src.status } : toast });
  if (src) addScope(ctx, name);
  // the test results card: one row per sample (target, status label) == the DB's last_test_result
  let uiRows = [];
  for (let i = 0; i < 15; i++) {
    uiRows = await page.getByTestId("servers-test-results").locator("tbody tr").evaluateAll((trs) => trs.map((tr) => [...tr.querySelectorAll("td")].map((td) => td.textContent.trim())))
      .catch(() => []);
    if (uiRows.length && !uiRows.some((r) => /^(waiting|testing|pending|queued|running)/i.test(String(r[4] || "")))) break;
    await page.waitForTimeout(2000);
  }
  ctx.writeJson(join(ctx.RUN, "steps", s.gate, `test-${name}.json`), { window: { from, to }, db: src, ui: uiRows });
  const dbSamples = src?.result?.samples || [];
  const seenFailed = (uiRows.length > 0 && uiRows.every((r) => !/^(ready|read|ok)/i.test(String(r[4] || "")))) || src?.status === "failed";
  ctx.state.tests = { ...(ctx.state.tests || {}), [name]: seenFailed ? "failed" : "passed" };
  const uiTargets = uiRows.map((r) => r[0]).filter(Boolean).sort();
  s.check(`${name}_test_ui_eq_db`, dbSamples.length > 0 && JSON.stringify(uiTargets) === JSON.stringify(dbSamples.map((x) => x.target).sort()),
    { expected: dbSamples.map((x) => x.target).sort(), observed: uiTargets, evidence: [await s.shot(page, `test-${name}`)] });
  return { src, from, to, samples: dbSamples };
}

// ------------------------------------------------------------------------------------------------ G4 servers
export async function g4(ctx) {
  await ctx.step("G4", ctx.A.ctx, async (s) => {
    const host = sourceOf(ctx, "S-host");
    const canary = sourceOf(ctx, "S-canary");
    if (!host || !canary) { s.check("lab_server_sources", false, { expected: "lab.json sources S-host and S-canary", observed: ctx.lab ? "absent" : "no lab.json", reason: "no-lab" }); return; }
    const hostC = ctx.lab.hosts?.host?.container;
    // Tier 2 needs the product's sudoers installed on an Ubuntu host: CB-02 defers that part; the source stays Tier 1
    notRunDeferred(ctx, s, "ubuntu-tier2", "G4", "sudoers");
    notRunDeferred(ctx, s, "ubuntu-tier2", "G15", "forcecommand_allowlist");
    const h = await addServerSource(ctx, s, { name: "S-host", targets: host.targets, port: 22, installNodeKeyOn: hostC });
    const hs = (h.samples || []).find((x) => x.target === host.targets[0]);
    s.check("S-host_login", !!hs && hs.login === true && hs.reachable === true && ["ready", "ok"].includes(String(hs.status)),
      { expected: { target: host.targets[0], reachable: true, login: true, status: "ready" }, observed: hs || null });
    // S-canary: the canary is listed by NAME in the source's own Never scan (the team list takes addresses only)
    const name = (ctx.lab.never_scan || [])[0];
    const c = await addServerSource(ctx, s, { name: "S-canary", targets: canary.targets, port: (canary.ports || [443])[0], neverScan: [name] });
    const counts = canaryCount(ctx, "canary", "control", c.from, c.to);
    ctx.state.accepts_g4 = counts;
    s.check("canary_accepts_g4", counts.canary === 0, { expected: 0, observed: counts.canary, reason: counts.canary === null ? "listener-log-missing" : "never-scan-reached",
      subject: { check: "canary_accepts", never_scan_by: "name", window: "G4 test" }, evidence: ["lab/listeners/canary.jsonl"] });
    s.check("control_accepts_g4", (counts.control || 0) >= 1, { expected: ">= 1 (positive control)", observed: counts.control, reason: "control-not-reached",
      subject: { check: "control_accepts", window: "G4 test" }, evidence: ["lab/listeners/control.jsonl"] });
    const cs = (c.samples || []).find((x) => x.target === canary.targets[0]);
    s.check("canary_sample_skipped_never_scan", !cs || cs.status === "skipped_never_scan",
      { expected: "no sample for the canary, or skipped_never_scan", observed: cs || null, subject: { check: "canary_sample", never_scan_by: "name" } });
  });
}

// ------------------------------------------------------------------------------------------------ G5b IDNA
export async function g5b(ctx) {
  for (const name of ctx.state.configured || []) addScope(ctx, name);  // G5 rebuilds state.scope from the network sources
  await ctx.step("G5b", ctx.A.ctx, async (s) => {
    const idn = sourceOf(ctx, "S-idn");
    if (!idn) { s.check("lab_idn_source", false, { expected: "lab.json source S-idn", observed: "absent", reason: "no-lab" }); return; }
    const r = await addServerSource(ctx, s, { name: "S-idn", targets: idn.targets, port: (idn.ports || [443])[0] });
    const fass = accepts(ctx, "idn-fass", r.from, r.to);
    const puny = accepts(ctx, "idn-punycode", r.from, r.to);
    ctx.state.accepts_g5b = { fass, puny };
    s.check("idna_punycode_reached", (puny || 0) >= 1, { expected: `>= 1 accept at ${idn.expect_resolves_to} (xn--fa-hia.lab, IDNA 2008)`, observed: puny, subject: { check: "idna_punycode_reached" } });
    s.check("idna_2003_name_untouched", fass === 0 || (fass === null && (puny || 0) > 0), { expected: "0 accepts at fass.lab (IDNA 2003 form)", observed: fass, subject: { check: "idna_2003_name_untouched" } });
  });
}

// ------------------------------------------------------------------------------------------------ G6 database
export async function g6(ctx) {
  await ctx.step("G6", ctx.A.ctx, async (s) => {
    const pg = sourceOf(ctx, "DB-pg-tls");
    if (!pg) { s.check("lab_db_source", false, { expected: "lab.json source DB-pg-tls", observed: "absent", reason: "no-lab" }); return; }
    const can = (ctx.readJson(join(ctx.RUN, "oracle", "canaries.json"))?.canaries || []).find((x) => x.id === pg.secret_ref);
    const pwPath = can?.control ? join(ctx.RUN, can.control) : null;
    if (!pwPath || !existsSync(pwPath)) { s.check("lab_db_secret", false, { expected: `the lab's control file for ${pg.secret_ref}`, observed: pwPath, reason: "no-lab" }); return; }
    const password = readFileSync(pwPath, "utf8").trim();
    ctx.remember(password);
    const { page } = ctx.A;
    await openTab(ctx, "Kubernetes & Databases");
    await page.locator("#db-form").scrollIntoViewIfNeeded();
    await page.fill("#db-name", pg.name);
    await page.getByTestId("db-engine").click();
    await page.getByRole("option", { name: /postgres/i }).first().click();
    await page.fill("#db-host", pg.address);
    await page.fill("#db-port", String(pg.port));
    await page.fill("#db-login", pg.user);
    await page.fill("#db-password", password);
    const tls = page.locator("#db-require-tls");
    if (pg.require_tls && !(await tls.isChecked().catch(() => false))) await tls.check().catch(async () => tls.click());
    await page.getByTestId("db-ca").setInputFiles(join(ctx.RUN, pg.ca_pem));
    await pickNode(page, "db-node");
    // the page shows the grant to run as the database administrator; the customer runs it for its login (the page
    // says to replace zs_cbom with the login entered), without CREATE ROLE (the login exists)
    const grantPre = page.getByTestId("db-grant").locator("pre").filter({ visible: true }).first();
    const grant = (((await grantPre.count()) ? await grantPre.textContent() : await page.getByTestId("db-grant").textContent().catch(() => "")) || "").trim();
    writeFileSync(join(s.dir, "grant-ui.sql"), grant + "\n");
    const sql = grant.split("\n").filter((l) => !/^\s*CREATE ROLE /i.test(l)).join("\n").replace(/\bzs_cbom\b/g, pg.user);
    const pgC0 = (ctx.lab.targets || []).find((t) => t.address === pg.address)?.container;
    const g = pgC0 ? spawnSync("docker", ["exec", "-i", pgC0, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"], { input: sql, encoding: "utf8" }) : { status: null, stderr: "no container" };
    customerSide(ctx, "G6", { what: `ran the page's grant as the DBA on ${pgC0} for ${pg.user} (zs_cbom replaced, CREATE ROLE dropped)`, exit: g.status, stderr: (g.stderr || "").slice(0, 300) });
    s.check("db_grant_applied", grant.length > 0 && g.status === 0, { expected: "the grant shown on the page runs cleanly", observed: { lines: grant.split("\n").length, exit: g.status, stderr: (g.stderr || "").slice(0, 200) } });
    const from = ctx.iso();
    await page.getByTestId("db-test").click();
    const src = await waitTest(ctx, pg.name);
    const to = ctx.iso();
    if (src) addScope(ctx, pg.name);
    // the row's test line follows the job by polling: give it the UI's own refresh time before comparing
    let line = "";
    for (let i = 0; i < 15; i++) {
      line = ((await page.getByTestId(`test-line-${src?.id}`).textContent().catch(() => "")) || "").trim();
      if (!/running|waiting|queued/i.test(line)) break;
      await page.waitForTimeout(2000);
    }
    ctx.writeJson(join(s.dir, "test-DB-pg-tls.json"), { window: { from, to }, db: src, ui: line });
    s.check("db_saved", !!src, { expected: "DB-pg-tls in the DB", observed: src && { id: src.id, status: src.status } });
    ctx.state.tests = { ...(ctx.state.tests || {}), [pg.name]: /fail|error/i.test(line) ? "failed" : "passed" };
    s.check("db_test_passed", !!src && ["passed", "ok", "success"].includes(src.status), { expected: "connection test passed", observed: src && { status: src.status, result: src.result }, evidence: [await s.shot(page, "db-test")] });
    s.check("db_test_ui_eq_db", !!src && line.toLowerCase().includes(src.status === "passed" ? "pass" : String(src.status).toLowerCase()), { expected: src?.status, observed: line.slice(0, 200) });
    // O-8 positive control: the server's own log shows the TLS login of the reader
    const pgC = (ctx.lab.targets || []).find((t) => t.address === pg.address)?.container;
    const log = pgC ? spawnSync("docker", ["logs", "--since", from, pgC], { encoding: "utf8" }) : { stdout: "", stderr: "" };
    const text = `${log.stdout || ""}${log.stderr || ""}`;
    writeFileSync(join(s.dir, "pg.log"), text.split(password).join("<redacted>"));
    const authed = text.split("\n").filter((l) => /connection authorized: user=cbom_reader/.test(l));
    s.check("pg_log_tls_login", authed.some((l) => /SSL enabled/.test(l)), { expected: "a 'connection authorized: user=cbom_reader ... SSL enabled' line", observed: authed.slice(0, 3), evidence: [`steps/G6/pg.log`] });
  });
}

// ------------------------------------------------------------------------------------------------ G7 cloud & identity
export async function g7(ctx) {
  await ctx.step("G7", ctx.A.ctx, async (s) => {
    const { page } = ctx.A;
    const settings = await ctx.apiGet(ctx.A, `/${ctx.A.team}/cbom/sources/settings`);
    ctx.writeJson(join(ctx.RUN, "api", "settings-g7.json"), settings.body);
    await openTab(ctx, "Cloud & Identity");
    await page.getByTestId("cloud-provider-aws").click().catch(() => {});
    const awsConfigured = settings.body?.aws_collection_configured ?? settings.body?.settings?.aws_collection_configured;
    const banner = ((await page.getByTestId("aws-not-configured").textContent({ timeout: 5000 }).catch(() => null)) || "").trim();
    if (awsConfigured === false) {
      s.check("aws_banner_eq_staging", banner === AWS_NOT_CONFIGURED_TEXT, { expected: AWS_NOT_CONFIGURED_TEXT, observed: banner || null, evidence: [await s.shot(page, "aws")] });
    } else {
      s.check("aws_banner_eq_staging", false, { expected: "a deployment without AWS collection, as staging (owner snapshot)", observed: { aws_collection_configured: awsConfigured, banner }, reason: "precondition" });
    }
    for (const p of ["azure", "gcp"]) {
      await page.getByTestId(`cloud-provider-${p}`).click();
      await page.waitForTimeout(800);
      const card = `${(await page.locator("#cbom-cloud-connect").textContent().catch(() => "")) || ""} ${(await page.getByTestId("cloud-validation").textContent().catch(() => "")) || ""}`;
      s.check(`${p}_not_available`, /not available/i.test(card), { expected: `the ${p} form says collection is not available (OA-7c)`, observed: card.replace(/\s+/g, " ").slice(0, 240),
        subject: { check: "cloud_not_available", provider: p }, evidence: [await s.shot(page, p)] });
    }
    // Certificate Transparency: the customer adds one domain; the page says CT is not queried
    const domain = "z01.lab";
    await page.fill("#cert-domain-input", domain);
    await page.getByTestId("cloud-cert-domain-add").click();
    await page.waitForTimeout(1500);
    const [[domains] = []] = ctx.db(`SELECT cert_domains::text FROM cbomcollectionsettings WHERE team_id = ${ctx.A.team}`);
    const chips = ((await page.getByTestId("cloud-cert-domains").textContent().catch(() => "")) || "");
    s.check("cert_domain_ui_eq_db", chips.includes(domain) && String(domains || "").includes(domain), { expected: domain, observed: { ui: chips.slice(0, 120), db: domains } });
    const body = (await page.locator("body").textContent()) || "";
    s.check("ct_not_queried", /does not query Certificate Transparency/i.test(body), { expected: "'does not query Certificate Transparency' shown", observed: /Certificate Transparency/i.test(body) ? "other wording" : "absent" });
    // identity providers: the lab IdP (.42) is deferred by CB-02
    if (!notRunDeferred(ctx, s, "idp")) s.notRun("idp_keys_eq_jwks", "no lab IdP in lab.json", { check: "idp_keys_eq_jwks" });
    // OA-7b: the Zeek ssl.log option is hidden until a reader exists
    await openTab(ctx, "Network TLS");
    const zeek = await page.getByTestId("network-zeek").count();
    const zeekText = await page.getByText(/zeek/i).count();
    s.check("zeek_option_absent", zeek === 0 && zeekText === 0, { expected: "no Zeek option", observed: { testid: zeek, text_hits: zeekText }, subject: { check: "zeek_option_absent" }, evidence: [await s.shot(page, "zeek")] });
  });
}

// ------------------------------------------------------------------------------------------------ G8 evidence
async function answerArea(page, areaKey, { confidenceLabel, evidenceDate, owner }) {
  await page.getByTestId(`evidence-answer-${areaKey}`).click();
  const dlg = page.getByRole("dialog");
  await dlg.waitFor({ timeout: 15000 });
  await page.fill("#evidence-owner", owner);
  // answer every question once: the first radio of each group, "e2e" in each text box
  for (const g of await dlg.getByRole("radiogroup").all()) await g.getByRole("radio").first().check().catch(() => {});
  for (const t of await dlg.locator("textarea, input[type=text]").all()) {
    const id = (await t.getAttribute("id")) || "";
    if (/evidence-(owner|title|url)/.test(id)) continue;
    if (!(await t.inputValue().catch(() => ""))) await t.fill("cbom-e2e answer").catch(() => {});
  }
  await page.getByTestId("evidence-confidence").click();
  await page.getByRole("option", { name: new RegExp(confidenceLabel, "i") }).first().click();
  await page.fill("#evidence-title", "cbom-e2e evidence");
  await page.fill("#evidence-url", "https://evidence.lab/doc.pdf");
  await page.fill("#evidence-date", evidenceDate);
  await page.getByTestId("evidence-save").click();
  await dlg.waitFor({ state: "hidden", timeout: 20000 });
}

export async function g8(ctx) {
  await ctx.step("G8", ctx.A.ctx, async (s) => {
    const { page } = ctx.A;
    await openTab(ctx, "Evidence");
    const now = new Date();
    const old = dateOnly(new Date(now.getTime() - 400 * DAY));
    // key hierarchy: documented, but the evidence is 400 days old (> 365): E0 with a Q0 gap (§2.3 rule)
    await answerArea(page, "key_hierarchy", { confidenceLabel: "Documented", evidenceDate: old, owner: "Key custodian" });
    // escrow: self-attested today: E1
    await answerArea(page, "escrow_recovery", { confidenceLabel: "Self-attested", evidenceDate: dateOnly(now), owner: "Treasury ops" });
    await page.reload({ waitUntil: "networkidle" });
    const ev = await ctx.apiGet(ctx.A, `/${ctx.A.team}/cbom/sources/evidence`);
    ctx.writeJson(join(ctx.RUN, "api", "evidence-g8.json"), ev.body);
    const areas = Object.fromEntries((ev.body?.areas || []).map((a) => [a.area_key, a]));
    const rowText = async (k) => ((await page.getByTestId(`evidence-area-${k}`).textContent().catch(() => "")) || "").replace(/\s+/g, " ");
    const kh = await rowText("key_hierarchy");
    const es = await rowText("escrow_recovery");
    ctx.writeJson(join(s.dir, "areas-ui.json"), { key_hierarchy: kh, escrow_recovery: es });
    // the stale area: E0 Unknown with a visible "Q0 gap" (the risk register's gap, §2.3); today the product says "Q0"
    s.check("evidence_effective_label_stale", /\bE0\b/.test(kh) && /Q0 gap/i.test(kh), { expected: "E0 + 'Q0 gap' badge", observed: { ui: kh.slice(0, 200), api: areas.key_hierarchy?.effective_confidence },
      subject: { check: "evidence_effective_label_stale" }, evidence: [await s.shot(page, "evidence")] });
    s.check("evidence_effective_label_fresh", /\bE1\b/.test(es), { expected: "E1 (self-attested, today)", observed: { ui: es.slice(0, 200), api: areas.escrow_recovery?.effective_confidence },
      subject: { check: "evidence_effective_label_fresh" } });
    // self-consistency: whatever the product calls it, the stale area is the lowest level and the fresh one is not
    const [[khDb, khDate] = []] = ctx.db(`SELECT confidence, evidence_date FROM cbomevidencearea WHERE team_id = ${ctx.A.team} AND area_key = 'key_hierarchy'`);
    s.check("evidence_saved_eq_db", khDb && khDate === old, { expected: { evidence_date: old }, observed: { confidence: khDb, evidence_date: khDate } });
    s.check("evidence_stale_is_unknown", ["Q0", "E0"].includes(areas.key_hierarchy?.effective_confidence), { expected: "the lowest level (unknown) for evidence > 365 days", observed: areas.key_hierarchy?.effective_confidence });
    // vendor link: created by A, answered by the vendor in a second context that never signed in, then used again
    await page.getByTestId("vendor-add").click();
    await page.fill("#vendor-name", "cbom-e2e vendor");
    await page.fill("#vendor-email", "vendor@vendor.lab");
    await page.getByTestId("vendor-save").click();
    await page.waitForTimeout(1500);
    const [[vid] = []] = ctx.db(`SELECT id FROM cbomevidencevendor WHERE team_id = ${ctx.A.team} ORDER BY id DESC LIMIT 1`);
    await page.getByTestId(`vendor-create-link-${vid}`).click();
    const url = ((await page.getByTestId("vendor-link-url").textContent({ timeout: 20000 })) || (await page.getByTestId("vendor-link-url").inputValue().catch(() => ""))).trim();
    ctx.remember(url, url.split("/").pop());
    s.check("vendor_link_shown", /^https:\/\/[^/]+\/q\/[A-Za-z0-9_-]{16,}$/.test(url), { expected: "https://<ui>/q/<token>", observed: url ? "a link (redacted)" : "none" });
    await page.keyboard.press("Escape");
    const vctx = await ctx.browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
    await vctx.tracing.start({ screenshots: true, snapshots: true });
    try {
      const vp = await vctx.newPage();
      await vp.goto(url, { waitUntil: "networkidle" });
      await vp.getByRole("button", { name: /send answers|submit/i }).first().waitFor({ timeout: 20000 });
      await vp.locator("textarea, [role=radiogroup]").first().waitFor({ timeout: 20000 });
      for (const g of await vp.getByRole("radiogroup").all()) await g.getByRole("radio").first().check().catch(() => {});
      for (const t of await vp.locator("textarea").all()) await t.fill("cbom-e2e vendor answer");
      await vp.getByRole("button", { name: /send answers|submit/i }).first().click();
      const thanks = await vp.getByText(/thank you/i).first().waitFor({ timeout: 20000 }).then(() => true).catch(() => false);
      await vp.screenshot({ path: join(s.dir, "vendor-answered.png") }).catch(() => {});
      s.check("vendor_answered_ui", thanks, { expected: "Thank you", observed: thanks ? "shown" : "absent" });
      const [[answeredAt] = []] = ctx.db(`SELECT answered_at FROM cbomevidencevendor WHERE id = ${Number(vid)}`);
      s.check("vendor_answered_db", !!answeredAt, { expected: "answered_at set", observed: answeredAt || null });
      // the same link again: gone (UI) and 404 (API, the page's own request)
      const vp2 = await vctx.newPage();
      const resp = vp2.waitForResponse((r) => r.url().includes("/cbom/vendor-questionnaire/"), { timeout: 20000 }).catch(() => null);
      await vp2.goto(url, { waitUntil: "networkidle" });
      const r2 = await resp;
      const gone = await vp2.getByText(/not valid any more/i).first().isVisible().catch(() => false);
      await vp2.screenshot({ path: join(s.dir, "vendor-reused.png") }).catch(() => {});
      s.check("vendor_link_second_use_404", r2?.status() === 404 && gone, { expected: { api: 404, ui: "link not valid any more" }, observed: { api: r2?.status() ?? null, ui: gone } });
    } finally {
      await vctx.tracing.stop({ path: join(s.dir, "trace-vendor.zip") }).catch(() => {});
      await vctx.close().catch(() => {});
    }
    ctx.state.evidence = { stale_area: "key_hierarchy", fresh_area: "escrow_recovery", vendor_id: Number(vid) };
  });
}

// ------------------------------------------------------------------------------------------------ G9 / G10 / G11 additions
/** The sources the customer configured, as typed (CB-01's plannedCharge input). */
function configuredSources(ctx) {
  return ctx.db(`SELECT kind, name, config::text FROM cbomcollectionsource WHERE team_id = ${ctx.A.team} AND enabled`)
    .map(([kind, name, cfg]) => ({ kind, name, config: JSON.parse(cfg || "{}") }));
}
function failedTests(ctx) { return Object.entries(ctx.state.tests || {}).filter(([, v]) => v === "failed").map(([k]) => k); }

/** G9 (CB-05 part; the estimate itself is CB-01's `estimate_eq_rates`): the Review page's skipped list names exactly
 * the sources whose connection test the customer saw fail, which is why they are not charged. */
export async function g9Skipped(ctx, s, plan) {
  const failed = (plan?.lines || []).filter((l) => l.queued === false).map((l) => l.name);
  const skippedText = ((await ctx.A.page.getByTestId("review-skipped").textContent().catch(() => "")) || "");
  const named = failed.filter((n) => skippedText.includes(n));
  s.check("review_skipped_eq_failed_tests", named.length === failed.length, { expected: failed, observed: skippedText.replace(/\s+/g, " ").slice(0, 300),
    subject: { check: "review_skipped" } });
}

/** G10 (OA-10b): final charge = estimate - rate x the CHARGED targets skipped at run time (ranges pro rata by
 * address). A never-scan address the planner already left out was never charged, so it owes nothing. */
export async function g10Charge(ctx, s) {
  const runId = ctx.state.runs?.[0];
  if (!runId) { s.notRun("charge_after_runtime_skips", "no run", { check: "charge_after_runtime_skips" }); return; }
  const r = await ctx.apiGet(ctx.A, `/${ctx.A.team}/cbom/sources/runs/${runId}/assets?page=1&page_size=1`);
  const jobs = r.body?.targets || [];
  const srcRows = Object.fromEntries(ctx.db(`SELECT id, kind, config::text FROM cbomcollectionsource WHERE team_id = ${ctx.A.team}`).map(([id, kind, cfg]) => [Number(id), { kind, cfg: JSON.parse(cfg || "{}") }]));
  const never = new Set(ctx.state.never_scan_g5 || []);
  const plan = plannedCharge(configuredSources(ctx), ctx.state.never_scan_g5 || [], failedTests(ctx));
  let refund = 0, charged = 0;
  const lines = [];
  for (const j of jobs) {
    const src = srcRows[j.source_id] || {};
    const skipped = (j.targets || []).filter((t) => RUNTIME_SKIPS.has(t.status));
    const chargedSkips = skipped.filter((t) => !(src.kind === "network_range" && never.has(String(t.target).split(":")[0])));
    if (!skipped.length) continue;
    let owed = 0;
    if (src.kind === "network_range") {
      // pro rata: the network charge spread over every charged address
      const addrs = new Set(chargedSkips.map((t) => String(t.target).split(":")[0]));
      owed = plan.network.addresses ? Math.round(plan.network.credits_c * addrs.size / plan.network.addresses) : 0;
      charged += addrs.size;
    } else if (["linux_servers", "windows_servers"].includes(src.kind)) { owed = RATES_C[src.kind] * chargedSkips.length; charged += chargedSkips.length; }
    else if (chargedSkips.length) { owed = RATES_C[src.kind] ?? 0; charged += 1; }
    refund += owed;
    lines.push({ job: j.job_id, source: j.source_name, kind: src.kind, skipped: skipped.map((t) => `${t.target}:${t.status}`), charged_skips: chargedSkips.length, refund_c: owed });
  }
  const [[chargedC, refunded] = []] = ctx.db(`SELECT credits_charged_c, credits_refunded_c FROM cbomcollectionrun WHERE id = ${runId}`);
  const final = Number(chargedC) - Number(refunded);
  const want = Math.round((ctx.state.estimate || 0) * 100) - refund;
  ctx.writeJson(join(s.dir, "charge-oracle.json"), { rule: "OA-10b DA default", estimate_c: Math.round((ctx.state.estimate || 0) * 100), lines, refund_c: refund, expected_final_c: want,
    db: { charged_c: Number(chargedC), refunded_c: Number(refunded) } });
  if (!charged) {
    s.notRun("charge_after_runtime_skips", "not exercised: no charged target was skipped at run time (never-scan addresses are left out at planning; sources whose test failed are not queued)",
      { check: "charge_after_runtime_skips" });
  } else {
    s.check("charge_after_runtime_skips", final === want, { expected: want / 100, observed: final / 100, subject: { check: "charge_after_runtime_skips" } });
  }
  for (const j of jobs) {
    for (const t of j.targets || []) {
      if (never.has(String(t.target).split(":")[0])) s.check(`run_target_${t.target}_${j.job_id}_skipped`, t.status === "skipped_never_scan", { expected: "skipped_never_scan", observed: t.status, subject: { check: "never_scan_target_status", never_scan_by: "address" } });
    }
  }
}

/** G11: Mosca X/Y/Z set by the customer; posture/Q-grade; calendar certificates vs the oracle. */
export async function g11Posture(ctx, s, k = "1") {
  const runId = ctx.state.runs?.[Number(k) - 1];
  const { page } = ctx.A;
  if (!runId) return;
  const want = { data_shelf_life_years: 10, migration_years: 5, threat_years: 12 };
  try {
    await page.getByTestId("mosca-edit").click({ timeout: 10000 });
    for (const [key, v] of Object.entries(want)) await page.getByTestId(`mosca-${key}`).fill(String(v));
    await page.getByTestId("mosca-save").click();
    await page.waitForTimeout(2000);
    const [[rm] = []] = ctx.db(`SELECT risk_model::text FROM cbomcollectionsettings WHERE team_id = ${ctx.A.team}`);
    const got = JSON.parse(rm || "{}");
    s.check("mosca_ui_eq_db", Object.entries(want).every(([key, v]) => got[key] === v), { expected: want, observed: got });
    const card = ((await page.getByTestId("posture-mosca").textContent().catch(() => "")) || "").replace(/\s+/g, " ");
    const atRisk = want.data_shelf_life_years + want.migration_years > want.threat_years;
    s.check("mosca_verdict", (atRisk ? /at risk/i : /inside window/i).test(card) && card.includes("X 10 + Y 5 vs Z 12"), { expected: `${atRisk ? "At risk" : "Inside window"}, X 10 + Y 5 vs Z 12`, observed: card.slice(0, 160),
      evidence: [await s.shot(page, "mosca")] });
  } catch (e) {
    s.check("mosca_ui_eq_db", false, { expected: "Mosca X/Y/Z saved through the posture card", observed: String(e.message || e).split("\n")[0].slice(0, 200), reason: "step-error" });
  }
  // OA-10a: every asset carries a Q-grade (Q0 Unknown .. Q4 Low); KF-10 until CB-18/CB-19
  const items = ctx.readJson(join(ctx.RUN, "api", `assets-run${k}.json`))?.items || [];
  const graded = items.filter((i) => /^Q[0-4]$/.test(String(i.q_grade ?? i.risk_grade ?? "")));
  s.check("q_grade_present", items.length > 0 && graded.length === items.length, { expected: `${items.length} assets with a Q-grade`, observed: graded.length, subject: { check: "q_grade_present" } });
  // calendar: every certificate the oracle plants in scope (closed world) appears with its not_after
  const heat = await ctx.apiGet(ctx.A, `/${ctx.A.team}/cbom/sources/runs/${runId}/heatmap?by=source`);
  ctx.writeJson(join(ctx.RUN, "api", `heatmap-run${k}.json`), heat.body);
  const oracle = ctx.readJson(join(ctx.RUN, "oracle", `run${k}.json`));
  const scope = ctx.state.scope || {};
  const inScope = (t) => (scope.sources || []).includes(t.source) || (scope.ranges || []).some((r) => { try { return ctx.inCidr(t.address, r); } catch { return false; } });
  const certs = (oracle?.targets || []).filter((t) => t.world !== "open" && inScope(t) && !t.known_fail).flatMap((t) => (t.assets || []).filter((a) => a.asset_type === "certificate" && a.expect?.not_after && !a.known_fail)
    .map((a) => ({ id: a.oracle_id, not_after: a.expect.not_after }))).filter((c) => Date.parse(c.not_after) > Date.now());
  const normTime = (v) => { let x = String(v).replace(/\.\d+/, "").replace(/\+00:00$/, "Z").replace(" ", "T"); if (!/(Z|[+-]\d\d:\d\d)$/.test(x)) x += "Z"; return x; };
  const cal = (heat.body?.certificates || []).map((c) => normTime(c.not_after));
  const missing = certs.filter((c) => !cal.includes(c.not_after));
  s.check(`calendar_run${k}_has_oracle_certs`, certs.length > 0 && missing.length === 0, { expected: certs, observed: { missing, calendar: cal.slice(0, 20) }, subject: { check: "calendar_certs", run: k } });
  const cells = (heat.body?.cells || []).reduce((n, c) => n + (c.count || 0), 0);
  const collected = items.filter((i) => i.type !== "coverage").length;
  s.check(`heatmap_run${k}_total_eq_assets`, cells === collected, { expected: `${collected} (assets that are not coverage gaps)`, observed: cells, subject: { check: "heatmap_total", run: k } });
}

// ------------------------------------------------------------------------------------------------ G12 additions
/** G12: schema validation (CycloneDX 1.6 JSON + XML, OSCAL structure), engine version, VEX states (OA-10c). */
export function g12Validate(ctx, s, k = "1", { vex = true, gap = true } = {}) {
  const dir = join(ctx.HERE, "..", "validate");
  // uv needs the outbound proxy the browser must not use: run-gate.sh keeps it in CBOM_E2E_*_PROXY
  const env = { ...process.env };
  if (process.env.CBOM_E2E_HTTPS_PROXY) env.HTTPS_PROXY = env.https_proxy = process.env.CBOM_E2E_HTTPS_PROXY;
  if (process.env.CBOM_E2E_HTTP_PROXY) env.HTTP_PROXY = env.http_proxy = process.env.CBOM_E2E_HTTP_PROXY;
  const out = spawnSync("uv", ["run", "-q", "--no-project", "--with-requirements", join(dir, "requirements.txt"), "python3", "-I", join(dir, "validate_exports.py"),
    "--run-dir", ctx.RUN, "--run", k], { encoding: "utf8", timeout: 600000, env });
  let res = null;
  try { res = JSON.parse(out.stdout); } catch { /* reported below */ }
  writeFileSync(join(s.dir, `validate-run${k}.json`), (out.stdout || "") + (out.stderr ? `\n/* stderr */\n${out.stderr}` : ""));
  if (!res) { s.check(`schema_validation_run${k}`, false, { expected: "validator output", observed: (out.stderr || "").slice(-300), reason: "validator-error", subject: { check: "schema_validation" } }); return; }
  for (const r of res.results) s.check(`${r.name}_run${k}`, r.ok, { expected: r.expected, observed: r.observed, reason: r.reason || "mismatch", subject: { check: r.check, file: r.file, run: k } });
  if (!vex) return;
  // VEX states per OA-10c
  const doc = ctx.readJson(join(ctx.RUN, "exports", `run${k}.cdx.json`));
  const vulns = doc?.vulnerabilities || [];
  const bad = [];
  for (const v of vulns) {
    const code = String(v.id || "").replace(/^ZS-CBOM-/, "").replace(/^zs:/, "");
    const want = VEX_FUTURE_RISK.has(code) ? "in_triage" : "exploitable";
    const got = v.analysis?.state ?? null;
    if (got !== want) bad.push({ id: v.id, want, got });
  }
  ctx.writeJson(join(s.dir, `vex-run${k}.json`), { rule: "OA-10c DA default", vulnerabilities: vulns.length, mismatches: bad });
  s.check(`vex_states_run${k}`, vulns.length > 0 && bad.length === 0, { expected: "observed weakness -> exploitable; QUANTUM_VULNERABLE / NO_PQ_KEX / SSH_NO_PQ_KEX -> in_triage",
    observed: { vulnerabilities: vulns.length, mismatches: bad.length, examples: bad.slice(0, 5) }, subject: { check: "vex_states", run: k } });
  // G8's gap snapshot: the run and its export carry the evidence gaps (key_hierarchy stale -> Q0 gap) (KF-14)
  if (gap && ctx.state.evidence) {
    const run = ctx.readJson(join(ctx.RUN, "api", `run-${ctx.state.runs?.[Number(k) - 1]}.json`)) || {};
    const area = ctx.state.evidence.stale_area;
    const inRun = JSON.stringify(run).includes(area);
    const inExport = JSON.stringify(doc || {}).includes(area);
    s.check(`evidence_gap_snapshot_run${k}`, inRun && inExport, { expected: `run and export name the Q0 gap ${area}`, observed: { run: inRun, export: inExport },
      subject: { check: "evidence_gap_snapshot", step: "G8", run: k } });
  }
}

// ------------------------------------------------------------------------------------------------ CB-38 results page
/** A run's results are a page since CB-38 (PLAN §11): /{team}/cbom/runs/{run}/results. ``via: "review"`` clicks the
 * Review & Run "Results" button (a link to that page), ``via: "direct"`` opens the URL. Either way the URL is judged,
 * and the table is switched to "All assets" (the judge compares every API item, coverage rows included). */
export async function openRunResults(ctx, s, runId, { via = "review", tag = "" } = {}) {
  const { page } = ctx.A;
  const want = `/${ctx.A.team}/cbom/runs/${runId}/results`;
  if (via === "direct") {
    await page.goto(`${ctx.UI}${want}`, { waitUntil: "networkidle" });
  } else {
    await page.goto(`${ctx.UI}/${ctx.A.team}/cbom/sources?tab=review`, { waitUntil: "networkidle" });
    await page.getByTestId(`review-run-details-${runId}`).click();
    await page.waitForURL((u) => u.pathname === want, { timeout: 30000 }).catch(() => {});
  }
  await page.getByTestId("run-results").waitFor({ timeout: 30000 });
  const path = new URL(page.url()).pathname;
  s.check(`results_url_${via}${tag}`, path === want, { expected: want, observed: path, subject: { check: "results_url", via, run: runId } });
  // one id per opening (G11 opens the page twice: the judge rejects a repeated check id)
  const id = `results_view_all_${via}${tag}`;
  const all = page.getByTestId("run-results-view-all");
  if (!(await all.count())) {
    s.check(id, false, { expected: "All assets view", observed: "no Findings / All assets toggle", subject: { check: "results_view_all", via, run: runId } });
    return path;
  }
  if ((await all.getAttribute("aria-pressed")) !== "true" && !(await all.isDisabled())) {
    await all.click();
    await page.waitForLoadState("networkidle"); await page.waitForTimeout(500);
  }
  const pressed = (await all.getAttribute("aria-pressed")) === "true";
  s.check(id, pressed, { expected: "All assets view", observed: pressed ? "all" : "findings", subject: { check: "results_view_all", via, run: runId } });
  return path;
}

/** PQC class labels as the posture card prints them (RunPosture.tsx CLASS_LABEL). PRODUCT COPY, read-only: G11u
 * reads the card's text with them; it never feeds an oracle value. */
export const POSTURE_CLASS_LABEL = { "quantum-vulnerable": "Quantum-vulnerable", hybrid: "Hybrid PQC", "quantum-safe": "Quantum-safe",
  "grover-weakened": "Grover-weakened", "not-applicable": "Not applicable" };

/** G11u (PLAN §11, Rule P): the results page prints the run posture's figures, never its own recount. Readiness on
 * the posture card and on the dashboard's "Quantum ready" card == /posture pqc_readiness_pct; class chips ==
 * pqc_classes; "Critical / High" == impacts; per row data-q-grade / data-fix-class == the /assets item of that id.
 * ``texts``: the innerText (line breaks kept) of {posture: run-posture, readiness: posture-readiness, dashboard:
 * run-section-dashboard, or null when that section is not on the page}. Pure (no browser), so it is unit-tested. */
export function g11uRuleP(s, k, postureBody, texts, rows, items) {
  const p = postureBody?.posture ?? postureBody ?? {};
  const pct = p.pqc_readiness_pct;
  const subject = (check) => ({ check, run: k });
  const readiness = String(texts.readiness || "").replace(/\s+/g, " ");
  const wantCard = pct == null ? "—" : `${pct}%`;
  s.check(`g11u_posture_readiness_run${k}`, readiness.includes(wantCard),
    { expected: wantCard, observed: readiness.slice(0, 120), subject: subject("g11u_posture_readiness") });
  if (texts.dashboard == null) {
    s.notRun(`g11u_dashboard_readiness_run${k}`, "the dashboard section (run results summary) is not on the page", subject("g11u_dashboard_readiness"));
  } else {
    const m = String(texts.dashboard).replace(/\s+/g, " ").match(/Quantum ready\s*([0-9.]+%|n\/a)/);
    const want = pct == null ? "n/a" : `${pct}%`;
    s.check(`g11u_dashboard_readiness_run${k}`, !!m && m[1] === want, { expected: want, observed: m ? m[1] : "no Quantum ready card", subject: subject("g11u_dashboard_readiness") });
  }
  const card = String(texts.posture || "").replace(/\s+/g, " ");
  const classes = p.pqc_classes || {};
  const wrong = Object.entries(POSTURE_CLASS_LABEL).filter(([c, label]) => (classes[c] || 0) > 0 && !card.includes(`${label} ${classes[c]}`))
    .map(([c]) => ({ class: c, api: classes[c] }));
  s.check(`g11u_classes_run${k}`, Object.keys(classes).length > 0 && wrong.length === 0, { expected: classes, observed: { not_on_card: wrong }, subject: subject("g11u_classes") });
  const im = p.impacts || {};
  const sev = card.match(/Critical \/ High\s*(\d+) \/ (\d+)/);
  s.check(`g11u_critical_high_run${k}`, !!sev && Number(sev[1]) === (im.Critical || 0) && Number(sev[2]) === (im.High || 0),
    { expected: { Critical: im.Critical || 0, High: im.High || 0 }, observed: sev ? { Critical: Number(sev[1]), High: Number(sev[2]) } : "not on the card", subject: subject("g11u_critical_high") });
  const byId = new Map((items || []).map((i) => [i.id, i]));
  const off = [];
  for (const r of rows || []) {
    if (r.reader !== "data-attributes") continue;
    const api = byId.get(r.id);
    if (!api) continue;
    for (const [field, key] of [["q_grade", "q_grade"], ["fix_class", "fix_class"]]) {
      const ui = r[key] ?? null, want = api[field] ?? null;
      if (ui !== want) off.push({ id: r.id, field, ui, api: want });
    }
  }
  const attrRows = (rows || []).filter((r) => r.reader === "data-attributes").length;
  s.check(`g11u_row_grades_run${k}`, attrRows > 0 && off.length === 0, { expected: "data-q-grade / data-fix-class == the /assets item", observed: { rows: attrRows, mismatches: off.slice(0, 20) }, subject: subject("g11u_row_grades") });
}

/** true when the path is the unified results page (whose rows must carry data attributes). */
export function isResultsPage(path) {
  return /^\/\d+\/cbom\/runs\/\d+\/results$/.test(String(path || ""));
}

/** Rows of the results table as the customer's DOM holds them. The unified page carries each row's values as
 * data-* attributes (read raw; the judge renders them, fieldmap.ui_from_attrs); the old run dialog's rows are read by
 * cell position. An attribute the page does not set is left out (the judge reports it missing). On the unified page
 * (``opts.attrsOnly``) a row is never read by position: a row without attributes is all missing. Self-contained: it
 * runs in the browser (page.$$eval(selector, readRunRows, opts)). */
export function readRunRows(trs, opts) {
  const attrsOnly = !!(opts && opts.attrsOnly);
  return trs.filter((tr) => /^run-asset-\d+$/.test(tr.dataset.testid)).map((tr) => {
    const id = Number(tr.dataset.testid.slice(10));
    if (attrsOnly || tr.hasAttribute("data-impact")) {
      const d = tr.dataset;
      const row = { id, reader: "data-attributes" };
      for (const [key, attr] of [["impact", "impact"], ["type", "type"], ["location", "location"], ["target", "target"],
        ["algorithm", "algorithm"], ["key_size", "keySize"], ["finding", "finding"], ["quantum", "quantum"],
        ["status", "status"], ["q_grade", "qGrade"], ["fix_class", "fixClass"]]) {
        if (attr in d) row[key] = d[attr];
      }
      return row;
    }
    const td = [...tr.querySelectorAll("td")];
    const where = td[4] ? [...td[4].querySelectorAll("span")].map((x) => x.textContent.trim()) : [];
    return { id, impact: td[2]?.textContent.trim(), type: td[3]?.textContent.trim(),
      location: where[0] ?? null, target: where[1] ?? null, algorithm: td[5]?.textContent.trim(), finding: td[6]?.textContent.trim(), quantum: td[7]?.textContent.trim() };
  });
}

// ------------------------------------------------------------------------------------------------ G13 / G13b drift
/** The run's results as the customer sees them (DOM rows of every page) and the API pages with the same token. */
export async function captureRun(ctx, s, k, runId) {
  const { page } = ctx.A;
  const path = await openRunResults(ctx, s, runId, { via: "direct", tag: `_run${k}` });
  const items = []; let first = null;
  for (let p = 1; p < 500; p++) {
    const r = await ctx.apiGet(ctx.A, `/${ctx.A.team}/cbom/sources/runs/${runId}/assets?page=${p}&page_size=200`);
    if (r.status !== 200) { s.check(`api_assets_200_run${k}`, false, { expected: 200, observed: r.status }); break; }
    first = first || r.body;
    items.push(...r.body.items);
    if (!r.body.items.length || p * 200 >= (r.body.total || 0)) break;
  }
  ctx.writeJson(join(ctx.RUN, "api", `assets-run${k}.json`), { run_id: runId, total: first?.total, all_total: first?.all_total, facets: first?.facets, targets: first?.targets, items });
  ctx.writeJson(join(ctx.RUN, "api", `run-${runId}.json`), (await ctx.apiGet(ctx.A, `/${ctx.A.team}/cbom/sources/runs/${runId}`)).body);
  ctx.writeJson(join(ctx.RUN, "api", `posture-run${k}.json`), (await ctx.apiGet(ctx.A, `/${ctx.A.team}/cbom/sources/runs/${runId}/posture`)).body);
  const rows = [];
  let prevIds = null, stuck = false;
  for (let p = 1; p < 200; p++) {
    const got = await page.$$eval('[data-testid^="run-asset-"]', readRunRows, { attrsOnly: isResultsPage(path) });
    const ids = got.map((r) => r.id).join(",");
    if (prevIds !== null && ids === prevIds) { stuck = true; break; }
    prevIds = ids;
    rows.push(...got);
    if (!got.length) break;
    if (!(await page.getByTestId("run-results-page").count())) break;
    const next = page.getByTestId("run-results").getByRole("button", { name: "Next", exact: true });
    if (!(await next.count()) || (await next.isDisabled())) break;
    await next.click(); await page.waitForLoadState("networkidle"); await page.waitForTimeout(500);
  }
  ctx.writeJson(join(ctx.RUN, "ui", `assets-run${k}.json`), { run_id: runId, total_text: ((await page.getByTestId("run-results-total").textContent().catch(() => "")) || "").trim(), rows });
  s.check(`dom_rows_eq_api_run${k}`, rows.length === items.length && !stuck, { expected: items.length, observed: { rows: rows.length, paging_stuck: stuck } });
  // downloads (sha256 == the HAR body of the same request)
  const bodies = {};
  const onResp = async (r) => { if (r.url().includes(`/runs/${runId}/`) && r.status() === 200) { try { bodies[r.url()] = await r.body(); } catch { /* streamed */ } } };
  page.on("response", onResp);
  for (const [tid, name] of [["run-results-download", `run${k}.cdx.json`], ["run-results-download-xml", `run${k}.cdx.xml`], ["run-results-download-oscal", `run${k}.oscal.json`]]) {
    const btn = page.getByTestId(tid);
    if (!(await btn.count())) { s.check(`download_${name}`, false, { expected: `button ${tid}`, observed: "absent" }); continue; }
    const [dl] = await Promise.all([page.waitForEvent("download", { timeout: 60000 }), btn.click()]);
    const p = join(ctx.RUN, "exports", name);
    await dl.saveAs(p);
    await page.waitForTimeout(800);
    const file = readFileSync(p);
    const match = Object.values(bodies).some((b) => b && ctx.sha256(b) === ctx.sha256(file));
    s.check(`download_${name}_eq_har_body`, match, { expected: ctx.sha256(file), observed: Object.keys(bodies).length, subject: { file: name } });
    writeFileSync(`${p}.sha256`, `${ctx.sha256(file)}  ${name}\n`);
  }
  page.off("response", onResp);
  return items;
}

async function waitRun(ctx, runId, maxMs = 15 * 60000) {
  const t0 = Date.now();
  let jobs = [];
  while (Date.now() - t0 < maxMs) {
    jobs = ctx.db(`SELECT id, status, outcome, source_id FROM cbomcollectionjob WHERE run_id = ${runId} ORDER BY id`);
    if (jobs.length && jobs.every((j) => ctx.TERMINAL.includes(j[1]))) return { jobs, done: true };
    await ctx.sleep(5000);
  }
  return { jobs, done: false };
}

export async function g13(ctx) {
  let diff = null, changes = null, runId = null;
  await ctx.step("G13", ctx.A.ctx, async (s) => {
    if (!ctx.state.runs?.[0]) { s.check("run1_exists", false, { expected: "run 1 from G9", observed: null }); return; }
    // the lab administrator changes the estate between the runs (z02 TLS 1.0 off, z04 re-issued, a key file removed,
    // z08 started, the control listener replaced by a TLS endpoint), and the run-2 oracle is frozen before Start (O-5)
    const gen = join(ctx.LAB_DIR, "e2e", "cbom", "lab", "gen.py");
    const m = spawnSync("python3", [gen, "mutate", "--run-dir", ctx.RUN, "--step", "run2"], { encoding: "utf8", timeout: 600000 });
    writeFileSync(join(s.dir, "mutate.log"), `${m.stdout || ""}${m.stderr || ""}`);
    customerSide(ctx, "G13", { what: "gen.py mutate --step run2 (the lab's servers change between runs)", exit: m.status });
    if (m.status !== 0) { s.check("lab_mutated", false, { expected: "gen.py mutate exit 0", observed: m.status, reason: "lab" }); return; }
    // run 1's self-check stays lab/selfcheck.json (the judge's O-3 record for run 1); run 2's goes to selfcheck-run2.json
    const scPath = join(ctx.RUN, "lab", "selfcheck.json");
    const run1sc = existsSync(scPath) ? readFileSync(scPath) : null;
    const sc = spawnSync("python3", [gen, "selfcheck", "--run-dir", ctx.RUN], { encoding: "utf8", timeout: 600000 });
    writeFileSync(join(s.dir, "selfcheck.log"), `${sc.stdout || ""}${sc.stderr || ""}`);
    const run2sc = ctx.readJson(scPath) || {};
    ctx.writeJson(join(ctx.RUN, "lab", "selfcheck-run2.json"), run2sc);
    if (run1sc) writeFileSync(scPath, run1sc);
    // "no connection before the scan" (canary listeners) is a pre-scan row: after run 1 it reports what run 1 did,
    // which G4/G5b/G10 judge; every other disagreement is a lab bug
    const bad = (run2sc.targets || []).flatMap((x) => (x.checks || []).filter((c) => c.agree === false && c.key !== "no connection before the scan").map((c) => `${x.target_id}:${c.key}`));
    s.check("lab_selfcheck_run2", sc.status === 0 || (run2sc.targets && bad.length === 0), { expected: "the run-2 lab agrees with its oracle (O-3), pre-scan canary rows aside", observed: { exit: sc.status, disagree: bad }, reason: "lab" });
    // O-5 per run: keep run 1's frozen hash, then freeze the run-2 oracle before the customer starts run 2
    const manPath = join(ctx.RUN, "MANIFEST.json");
    const man = ctx.readJson(manPath) || {};
    if (man.oracle && !man.oracle_run1) { man.oracle_run1 = man.oracle; ctx.writeJson(manPath, man); }
    const fr = spawnSync("python3", ["-m", "harness.gate", "freeze-oracle", ctx.RUN], { cwd: join(ctx.HERE, ".."), encoding: "utf8" });
    s.check("oracle_run2_frozen_before_start", fr.status === 0, { expected: "freeze-oracle exit 0 before Start (O-5)", observed: fr.status, reason: "lab" });
    // the customer: Review & Run, estimate, acknowledge, Start (a plain click this time)
    const { page } = ctx.A;
    await openTab(ctx, "Review & Run");
    await s.shot(page, "review-run2");
    await page.getByTestId("review-estimate").click();
    await page.getByTestId("review-credits-required").waitFor({ timeout: 30000 });
    const ack = page.locator("#review-soc-ack");
    if (await ack.count()) await ack.check();
    const before = new Set(ctx.db(`SELECT id FROM cbomcollectionrun WHERE team_id = ${ctx.A.team}`).map((r) => r[0]));
    await page.getByTestId("review-start").click();
    let fresh = [];
    for (let i = 0; i < 20 && !fresh.length; i++) { await ctx.sleep(1000); fresh = ctx.db(`SELECT id FROM cbomcollectionrun WHERE team_id = ${ctx.A.team} ORDER BY id`).filter((r) => !before.has(r[0])); }
    s.check("run2_started", fresh.length === 1, { expected: 1, observed: fresh.length });
    if (!fresh.length) return;
    runId = Number(fresh[0][0]);
    ctx.state.runs = [...(ctx.state.runs || []).slice(0, 1), runId];
    const w = await waitRun(ctx, runId);
    s.check("run2_finished_15min", w.done, { expected: "every job finished within 15 min", observed: w.jobs.map((j) => `${j[0]}:${j[1]}/${j[2]}`) });
    ctx.state.jobs2 = w.jobs.map(([id, status, outcome, source]) => ({ id: Number(id), status, outcome, source_id: Number(source) }));
    await captureRun(ctx, s, "2", runId);
    g12Validate(ctx, s, "2", { vex: false, gap: false });
    changes = await ctx.apiGet(ctx.A, `/${ctx.A.team}/cbom/sources/runs/${runId}/changes`);
    diff = await ctx.apiGet(ctx.A, `/${ctx.A.team}/cbom/sources/runs/${runId}/diff`);
    ctx.writeJson(join(ctx.RUN, "api", "changes-run2.json"), changes.body);
    ctx.writeJson(join(ctx.RUN, "api", "diff-run2.json"), diff.body);
    const oracle = ctx.readJson(join(ctx.RUN, "oracle", "run2.json"));
    const drift = (oracle?.drift || []).filter((d) => !String(d.location).startsWith((ctx.lab.listeners || []).find((l) => l.role === "control")?.address || "\u0000"));
    const events = changes.body?.events || [];
    const host = (loc) => String(loc || "").split(":")[0];
    const matchEvent = (d) => events.find((e) => {
      const label = String(e.asset_label || "") + " " + JSON.stringify(e.detail || {});
      const kind = d.change === "resolved" ? "resolved" : d.change;
      if (e.kind !== kind) return false;
      if (d.code && e.code !== d.code) return false;
      return label.includes(d.location) || (d.path && label.includes(d.path)) || (d.change !== "resolved" && label.includes(host(d.location)));
    });
    const inDiff = (d) => {
      const list = { resolved: diff.body?.resolved, cert_renewed: diff.body?.changed, removed_asset: diff.body?.removed, new_asset: diff.body?.added }[d.change] || [];
      return list.some((a) => (!d.code || a.code === d.code || (a.finding_codes || []).includes(d.code)) && (String(a.label).includes(d.location) || (d.path && String(a.label).includes(d.path)) || String(a.label).includes(host(d.location))));
    };
    for (const d of drift) {
      const id = `${d.change}_${d.code || d.asset_type || ""}_${d.location}`.replace(/[^\w.:-]/g, "_");
      const ev = matchEvent(d);
      const sub = { change: d.change, location: d.location, ...(d.asset_type ? { asset_type: d.asset_type } : {}), ...(d.code ? { code: d.code } : {}) };
      s.check(`drift_${id}_changes`, !!ev, { expected: d, observed: ev || `no ${d.change} event`, subject: { check: "drift_changes", ...sub } });
      s.check(`drift_${id}_diff`, inDiff(d), { expected: d, observed: inDiff(d) ? "listed" : "absent", subject: { check: "drift_diff", ...sub } });
    }
    // the Changes list the customer sees == the API's events (kind + code), in the run's details
    await page.getByTestId("run-changes").waitFor({ timeout: 20000 }).catch(() => {});
    const uiKinds = await page.locator('[data-testid^="drift-"]').evaluateAll((els) => els.map((e) => e.dataset.testid.slice(6))).catch(() => []);
    const apiKinds = events.slice(0, 25).map((e) => e.kind);
    s.check("changes_ui_eq_api", JSON.stringify([...uiKinds].sort()) === JSON.stringify([...apiKinds].sort()), { expected: apiKinds, observed: uiKinds, evidence: [await s.shot(page, "changes")] });
    // webhook receiver (.43): deferred by CB-02
    if (!notRunDeferred(ctx, s, "receiver")) s.notRun("receiver_events", "no lab receiver in lab.json", { check: "receiver_events" });
  });
  await ctx.step("G13b", ctx.A.ctx, async (s) => {
    if (!runId || !diff) { s.check("run2_exists", false, { expected: "run 2 from G13", observed: null }); return; }
    const control = (ctx.lab.listeners || []).find((l) => l.role === "control");
    const ranges = (ctx.lab.sources || []).filter((x) => x.kind === "network" && (x.ranges || []).some((r) => control && ctx.inCidr(control.address, r)));
    const rangeIds = ctx.db(`SELECT id, name, config->>'cidr' FROM cbomcollectionsource WHERE team_id = ${ctx.A.team} AND kind = 'network_range'`)
      .filter(([, , cidr]) => ranges.some((x) => (x.ranges || []).includes(cidr)));
    const sources = diff.body?.sources || [];
    for (const [id, name, cidr] of rangeIds) {
      // by the source's name only (source_ref is a uid: matching an id as a substring of it found S-host once)
      const row = sources.find((x) => x.name === name);
      s.check(`range_${cidr}_compared`, row?.status === "compared", { expected: "compared", observed: row || "not in /diff sources", subject: { check: "range_with_never_scan_compared", cidr } });
    }
    const loc = `${control?.address}:443`;
    const ev = (changes.body?.events || []).find((e) => e.kind === "new_asset" && String(e.asset_label || "").includes(loc));
    s.check("range_change_recorded", !!ev, { expected: `new_asset ${loc} (control replaced by a TLS endpoint)`, observed: ev || "absent", subject: { check: "range_with_never_scan_compared", what: "change recorded" } });
  });
}

/** The G7/G13 lab parts this run cannot cover are reported by the steps; this lists what CB-05 configured. */
export function summary(ctx) {
  return { configured: ctx.state.configured || [], scope: ctx.state.scope || null };
}
