// CBOM Tier-L gate: the customer user flow in real Chromium (DEVILS-ADVOCATE.md §4.3), writing evidence into a run
// directory that `python3 -m harness.gate judge` then judges. One customer (A) signs up, adds a scan node, configures
// the lab sources, starts a run, reads its results and downloads its exports; a second customer (B) checks tenancy.
//
//   env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy PLAYWRIGHT_BROWSERS_PATH=$R6/local/pw/browsers \
//     node e2e/cbom/flow/gate.mjs --run-dir <RUN> --sha <40-hex> [--steps G1,G2,...] [--node-image IMAGE]
//
// Rules it keeps (§4.1): every state change goes through the UI as a fresh customer; API use is limited to reads with
// the same customer token (paging), the operator top-up (dss.py topup) and team-B negative checks; the node command
// is copied from the DOM and run with the allowed diff only (anything more is recorded and fails G3).
// Each step writes steps/<G>/step.json (checks), steps/<G>/trace.zip and screenshots. Never prints a secret.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { allowedDiff, splitCommand } from "./command.mjs";

const R6 = process.env.R6 || "/home/claude/round6";
const { chromium } = createRequire(process.env.CBOM_E2E_PW || `${R6}/local/pw/`)("playwright");

// ------------------------------------------------------------------------------------------------ arguments
const args = Object.fromEntries(process.argv.slice(2).reduce((acc, v, i, a) => {
  if (v.startsWith("--")) acc.push([v.slice(2), a[i + 1] && !a[i + 1].startsWith("--") ? a[i + 1] : "1"]);
  return acc;
}, []));
const RUN = args["run-dir"];
if (!RUN || !existsSync(RUN)) { console.error("--run-dir <existing run directory> is required"); process.exit(2); }
const SHA = args.sha || "";
const UI = args.ui || "https://devsec.dss.test";
const API = args.api || "https://api.dss.test";
const MAIL = args.mail || "http://127.0.0.1:8025";
const PG = args.pg || "dss-staging-postgres-1";
const CA = args.ca || `${R6}/local/ca/ca.pem`;
const TOPUP = Number(args.topup || 50);
const ALL = ["G1", "G2", "G3", "G4", "G5", "G5b", "G6", "G7", "G8", "G9", "G10", "G11", "G12", "G13", "G13b", "G14"];
const STEPS = new Set(args.steps ? args.steps.split(",") : ALL);
const SECRETS_FILE = args["secrets-file"] || `/tmp/cbom-e2e-secrets-${process.pid}.json`;
const lab = readJson(join(RUN, "lab", "lab.json"));
const stateFile = join(RUN, "flow-state.json");
const state = readJson(stateFile) || { started: iso() };
const secrets = [];

function iso(d = new Date()) { return d.toISOString().replace(/\.\d{3}Z$/, "Z"); }
function readJson(p) { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } }
function writeJson(p, d) { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(d, null, 2) + "\n"); }
function saveState() { writeJson(stateFile, state); }
function remember(...values) {
  for (const v of values) if (v && String(v).length >= 6) secrets.push(String(v));
  writeFileSync(SECRETS_FILE, JSON.stringify(secrets)); chmodSync(SECRETS_FILE, 0o600);
}
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------------------------------------ database (read-only)
function db(sql) {
  const out = execFileSync("docker", ["exec", "-i", PG, "sh", "-c",
    'exec psql -X -q -At -F "\t" -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
    { input: `BEGIN READ ONLY;\n${sql};\nCOMMIT;\n`, encoding: "utf8", timeout: 60000 });
  return out.trim() ? out.trim().split("\n").map((l) => l.split("\t")) : [];
}

// ------------------------------------------------------------------------------------------------ mail catcher
async function mailedCode(email, sinceMs) {
  for (let i = 0; i < 40; i++) {
    const r = await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:"${email}"`)}&limit=10`);
    const msgs = ((await r.json()).messages || []).filter((m) => Date.parse(m.Created) >= sinceMs - 1000);
    msgs.sort((a, b) => Date.parse(b.Created) - Date.parse(a.Created));
    if (msgs.length) {
      const full = await (await fetch(`${MAIL}/api/v1/message/${msgs[0].ID}`)).json();
      const text = (full.HTML || full.Text || "").replace(/<(style|script|head)\b[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ");
      const m = text.match(/(?<!\d)(\d{6})(?!\d)/);
      if (m) return m[1];
    }
    await sleep(1500);
  }
  throw new Error(`no code mailed to the new customer`);
}

// ------------------------------------------------------------------------------------------------ steps
class Step {
  constructor(gate) { this.gate = gate; this.checks = []; this.t0 = Date.now(); this.dir = join(RUN, "steps", gate); mkdirSync(this.dir, { recursive: true }); }
  check(name, ok, { expected = null, observed = null, subject = {}, reason = "mismatch", evidence = [] } = {}) {
    this.checks.push({ id: `${this.gate}/${name}`, gate: this.gate, kind: "flow", verdict: ok ? "PASS" : "FAIL",
      subject: { check: name, ...subject }, reason: ok ? "" : reason, expected, observed, evidence });
    console.log(`  ${ok ? "PASS" : "FAIL"} ${this.gate}/${name}${ok ? "" : `: expected ${JSON.stringify(expected)?.slice(0, 120)} observed ${JSON.stringify(observed)?.slice(0, 160)}`}`);
    return ok;
  }
  notRun(name, note, subject = {}) {
    this.checks.push({ id: `${this.gate}/${name}`, gate: this.gate, kind: "flow", verdict: "NOT-RUN", subject: { check: name, ...subject },
      reason: note, expected: null, observed: null, evidence: [] });
    console.log(`  NOT-RUN ${this.gate}/${name}: ${note}`);
  }
  async shot(page, name) {
    const p = join(this.dir, `${name}.png`);
    await page.screenshot({ path: p, fullPage: false }).catch(() => {});
    return `steps/${this.gate}/${name}.png`;
  }
  write(status = "ran", note = "") {
    writeJson(join(this.dir, "step.json"), { gate: this.gate, status, note, started: iso(new Date(this.t0)), ended: iso(),
      seconds: Math.round((Date.now() - this.t0) / 100) / 10, checks: this.checks });
  }
}

function notRun(gate, note) {
  const s = new Step(gate);
  s.write("not-run", note);
  console.log(`- ${gate}: not run (${note})`);
}

async function step(gate, ctx, fn) {
  if (!STEPS.has(gate)) return;
  const s = new Step(gate);
  console.log(`- ${gate}`);
  if (ctx) await ctx.tracing.startChunk({ title: gate }).catch(() => {});
  try {
    await fn(s);
    s.write("ran");
  } catch (e) {
    s.check("completed", false, { expected: "the step finishes", observed: String(e.message || e).split("\n")[0].slice(0, 300), reason: "step-error" });
    if (ctx) for (const p of ctx.pages()) await s.shot(p, "error");
    s.write("ran", "step raised");
  } finally {
    if (ctx) await ctx.tracing.stopChunk({ path: join(s.dir, "trace.zip") }).catch(() => {});
    saveState();
  }
}

// ------------------------------------------------------------------------------------------------ browser helpers
async function newCustomer(browser, name) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 },
    recordHar: { path: join(RUN, "har", `${name}.har`), content: "embed" }, acceptDownloads: true });
  await ctx.tracing.start({ screenshots: true, snapshots: true, sources: false });
  const page = await ctx.newPage();
  const who = { name, ctx, page, token: null, console: [], failed: [] };
  page.on("request", (req) => {
    const a = req.headers()["authorization"];
    if (a && a.startsWith("Bearer ") && req.url().startsWith(API)) { who.token = a.slice(7); if (!secrets.includes(who.token)) remember(who.token); }
  });
  page.on("console", (m) => { if (m.type() === "error") who.console.push(m.text().slice(0, 200)); });
  page.on("response", (r) => { if (r.status() >= 500) who.failed.push(`${r.status()} ${r.request().method()} ${r.url()}`); });
  return who;
}

async function apiGet(who, path) {
  const r = await who.ctx.request.get(`${API}${path}`, { headers: { Authorization: `Bearer ${who.token}`, Origin: UI } });
  let body = null;
  try { body = await r.json(); } catch { body = await r.text().catch(() => null); }
  return { status: r.status(), body };
}

async function signUp(browser, label, s) {
  const who = await newCustomer(browser, label);
  const stamp = iso().replace(/[-:TZ]/g, "").slice(0, 14);
  who.email = `cbom-e2e-${label.slice(-1).toLowerCase()}-${stamp}@agents.dss.test`;
  const password = `E2e-${randomBytes(12).toString("base64url")}!9`;
  remember(password);
  const { page } = who;
  await page.goto(`${UI}/register`, { waitUntil: "networkidle" });
  await page.fill("#email", who.email);
  await page.fill("#password", password);
  if (await page.locator("#re_password").count()) await page.fill("#re_password", password);
  if (await page.locator("#first_name").count()) await page.fill("#first_name", "Cbom");
  if (await page.locator("#last_name").count()) await page.fill("#last_name", `E2e ${label}`);
  const since = Date.now();
  await page.getByRole("button", { name: /send verification code/i }).click();
  const code = await mailedCode(who.email, since);
  remember(code);
  await page.fill("#verification_code", code);
  await page.getByRole("button", { name: /^register$/i }).click();
  await page.waitForURL(/\/home/, { timeout: 45000 });
  await page.waitForLoadState("networkidle");
  const row = page.getByRole("row", { name: /default team/i }).first();
  await row.waitFor({ timeout: 30000 });
  await s.shot(page, `${label}-home`);
  await row.click();
  await page.waitForURL(/\/\d+(\/|$)/, { timeout: 30000 });
  who.team = Number(new URL(page.url()).pathname.split("/")[1]);
  return who;
}

async function sourcesTab(page, team, tab) {
  const t = page.getByRole("tab", { name: new RegExp(`^${tab}$`, "i") });
  if (await t.count()) { await t.first().click(); } else { await page.goto(`${UI}/${team}/cbom/sources?tab=${tab}`); }
  await page.waitForLoadState("networkidle");
}

// G17: both customers sign out through the UI (user menu > Sign out); proven by the login page and a 401 afterwards
async function signOut(who) {
  try {
    const { page } = who;
    await page.goto(`${UI}/${who.team}/cbom/sources`, { waitUntil: "networkidle" });
    await page.getByRole("button", { name: new RegExp(who.email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")) }).first().click();
    await page.getByRole("menuitem", { name: /sign out/i }).first().click();
    await page.waitForURL(/\/login/, { timeout: 20000 });
    const after = await apiGet(who, `/${who.team}/cbom/sources/runs`);
    return after.status === 401 || after.status === 403;
  } catch {
    return false;
  }
}

async function overflow(page) {
  return page.evaluate(() => ({ scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth }));
}

// ------------------------------------------------------------------------------------------------ the flow
const browser = await chromium.launch({ args: ["--no-proxy-server"] });
let A = null, B = null;
const node = {};
const tStart = Date.now();
try {
  // G1 sign-up --------------------------------------------------------------------------------------------
  await step("G1", null, async (s) => {
    A = await signUp(browser, "customerA", s);
    state.teams = { ...(state.teams || {}), A: A.team };
    s.check("signed_up", Number.isInteger(A.team), { expected: "a new team id", observed: A.team });
    execFileSync("python3", [`${R6}/local/bin/dss.py`, "topup", String(A.team), String(TOPUP)], { stdio: "ignore", timeout: 120000 });
    await A.page.reload({ waitUntil: "networkidle" });
    const text = await A.page.getByText(/\d+(\.\d+)? credits/).first().textContent({ timeout: 20000 }).catch(() => "");
    const shown = Number((text.match(/([\d.]+) credits/) || [])[1]);
    const [[dbBalance] = []] = db(`SELECT credit_balance FROM team WHERE id = ${A.team}`);
    s.check("credits_ui_eq_db", shown === Number(dbBalance) && shown === TOPUP, { expected: { ui: TOPUP, db: TOPUP },
      observed: { ui: shown, db: Number(dbBalance) }, evidence: [await s.shot(A.page, "credits")] });
  });
  if (!A) throw new Error("customer A could not sign up; nothing else can run");
  await A.ctx.tracing.stop().catch(() => {});
  await A.ctx.tracing.start({ screenshots: true, snapshots: true });

  // G2 navigation -------------------------------------------------------------------------------------------
  await step("G2", A.ctx, async (s) => {
    const { page } = A;
    const nav = page.getByRole("link", { name: /^CBOM$/ }).first();
    let viaSidebar = false;
    if (await nav.count()) {
      await nav.click(); await page.waitForURL(/\/cbom/, { timeout: 30000 });
      const sources = page.locator(`a[href*="/${A.team}/cbom/sources"]`).first();
      if (await sources.count()) { await sources.click(); viaSidebar = true; }
    }
    if (!viaSidebar) await page.goto(`${UI}/${A.team}/cbom/sources`);
    await page.waitForURL(/\/cbom\/sources/, { timeout: 30000 });
    await page.waitForLoadState("networkidle");
    s.check("sidebar_to_sources", viaSidebar, { expected: "Sidebar > CBOM > a link to CBOM Sources", observed: viaSidebar ? "clicked" : "no link found; opened the URL", reason: "navigation" });
    const tabs = await page.getByRole("tab").allTextContents();
    s.check("tabs_present", tabs.length >= 7, { expected: ">= 7 tabs", observed: tabs });
    for (const [label, value] of [["Servers", "servers"], ["Network TLS", "network"], ["Evidence", "evidence"], ["Review & Run", "review"]]) {
      await page.getByRole("tab", { name: label }).first().click();
      await page.waitForFunction((v) => location.search.includes(`tab=${v}`), value, { timeout: 10000 }).catch(() => {});
      const urlOk = new URL(page.url()).searchParams.get("tab") === value;
      await page.reload({ waitUntil: "networkidle" });
      const sel = await page.getByRole("tab", { selected: true }).first().textContent().catch(() => "");
      s.check(`tab_${value}_survives_refresh`, urlOk && sel.trim() === label, { expected: { url: value, selected: label }, observed: { url: new URL(page.url()).searchParams.get("tab"), selected: sel.trim() } });
    }
    await page.goBack({ waitUntil: "networkidle" });
    const back = new URL(page.url()).searchParams.get("tab");
    await page.goForward({ waitUntil: "networkidle" });
    const fwd = new URL(page.url()).searchParams.get("tab");
    s.check("tab_back_forward", back === "evidence" && fwd === "review", { expected: { back: "evidence", forward: "review" }, observed: { back, forward: fwd } });
    for (const width of [1440, 820, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await page.waitForTimeout(500);
      const o = await overflow(page);
      s.check(`no_overflow_${width}`, o.scrollWidth <= o.innerWidth, { expected: `scrollWidth <= ${width}`, observed: o, evidence: [await s.shot(page, `review-${width}`)] });
    }
    await page.setViewportSize({ width: 1440, height: 900 });
  });

  // G3 scan node --------------------------------------------------------------------------------------------
  await step("G3", A.ctx, async (s) => {
    const { page } = A;
    await page.goto(`${UI}/${A.team}/cbom/sources?tab=scan-nodes`, { waitUntil: "networkidle" });
    await page.getByRole("button", { name: /add (your first )?scan node/i }).first().click();
    await page.fill("#node-name", "e2e-node-1");
    await page.fill("#node-segment", "lab");
    await page.getByRole("button", { name: /create node and show install command/i }).click();
    const pre = page.locator("#scan-node-wizard pre").first();
    await pre.waitFor({ timeout: 30000 });
    const command = (await pre.textContent()).trim();
    const token = (command.match(/ZS_REGISTRATION_TOKEN='?([^'\s\\]+)/) || [])[1];
    remember(token);
    writeFileSync(join(s.dir, "command-ui.txt"), command + "\n");
    await s.shot(page, "command");
    // the token is shown once: after a reload the wizard and the command are gone
    await page.reload({ waitUntil: "networkidle" });
    const again = await page.locator("#scan-node-wizard pre").count();
    const body = await page.content();
    s.check("token_shown_once", again === 0 && token && !body.includes(token), { expected: "no command or token after a reload", observed: { command_blocks: again, token_in_page: !!(token && body.includes(token)) } });
    // run it: the UI's command, token for token, plus only the allowed diff (DA §4.1)
    const plan = allowedDiff(command, { lab, image: args["node-image"], ca: CA });
    writeFileSync(join(s.dir, "command-run.txt"), plan.argv.map((a) => (a.includes(token) ? a.replace(token, "<token>") : a)).join(" ") + "\n");
    writeJson(join(s.dir, "command-diff.json"), { allowed: plan.allowed, extra: plan.extra, removed: plan.removed });
    s.check("allowed_diff", plan.extra.length === 0 && plan.removed.length === 0, { expected: "UI command + allowed diff only", observed: { extra: plan.extra, removed: plan.removed }, reason: "command-diff" });
    s.check("node_image_served", plan.imageServed, { expected: "the image the UI prints exists on this stack", observed: plan.imageNote, reason: "precondition" });
    spawnSync("docker", ["rm", "-f", plan.container], { stdio: "ignore" });
    const runRes = spawnSync("docker", plan.argv.slice(1), { encoding: "utf8", timeout: 120000 });
    s.check("node_started", runRes.status === 0, { expected: "docker run exit 0", observed: (runRes.stderr || runRes.stdout || "").slice(0, 300).replace(token || "\u0000", "<token>") });
    node.container = plan.container; node.volume = plan.volume; state.node = { container: plan.container, volume: plan.volume };
    const t0 = Date.now();
    let online = false, row = null;
    while (Date.now() - t0 < 90000 && !online) {
      await sleep(3000);
      row = db(`SELECT id, node_version, hostname, source_ips, last_heartbeat_at FROM cbomscannode WHERE team_id = ${A.team} AND name = 'e2e-node-1'`)[0];
      online = !!(row && row[4]);
    }
    const secs = Math.round((Date.now() - t0) / 1000);
    s.check("node_online_60s", online && secs <= 60, { expected: "heartbeat <= 60 s after start", observed: { online, seconds: secs } });
    if (row) { node.id = Number(row[0]); state.node.id = node.id; }
    await page.reload({ waitUntil: "networkidle" });
    const uiRow = page.getByRole("row", { name: /e2e-node-1/ }).first();
    const rowText = (await uiRow.textContent().catch(() => "")) || "";
    s.check("ui_shows_online", /online/i.test(rowText), { expected: "Online", observed: rowText.slice(0, 200), evidence: [await s.shot(page, "nodes")] });
    s.check("ui_version_eq_db", !!row && rowText.includes(row[1]), { expected: row && row[1], observed: rowText.slice(0, 200) });
    const logs = spawnSync("docker", ["logs", "--timestamps", plan.container], { encoding: "utf8" });
    writeFileSync(join(s.dir, "node.log"), ((logs.stdout || "") + (logs.stderr || "")).split(token || "\u0000").join("<token>"));
  });

  // G4 servers, G5b IDNA, G6 database, G7 cloud & identity, G8 evidence: CB-05 writes these specs
  for (const [g, why] of [["G4", "Servers sources (S-ubuntu, S-canary) are CB-05's spec"], ["G5b", "IDNA source is CB-05's spec (KF-7)"],
    ["G6", "Database source is CB-05's spec"], ["G7", "Cloud & identity is CB-05's spec"], ["G8", "Evidence + vendor link is CB-05's spec"]]) {
    if (STEPS.has(g)) notRun(g, why);
  }

  // G5 network ----------------------------------------------------------------------------------------------
  await step("G5", A.ctx, async (s) => {
    const nets = (lab?.sources || []).filter((x) => x.kind === "network");
    if (!nets.length) { s.check("lab_network_sources", false, { expected: "lab.json sources of kind network", observed: lab ? "none" : "no lab.json", reason: "no-lab" }); return; }
    const { page } = A;
    state.scope = { sources: nets.map((n) => n.name), ranges: nets.flatMap((n) => n.ranges || []) };
    await sourcesTab(page, A.team, "Network TLS");
    for (const src of nets) {
      for (const cidr of src.ranges || []) {
        await page.getByTestId("network-add-range").first().click().catch(async () => {
          await page.getByRole("button", { name: /add (a )?range/i }).first().click();
        });
        await page.getByTestId("network-range-cidr").fill(cidr);
        await page.getByTestId("network-range-node").locator("button, [role=combobox]").first().click();
        await page.getByRole("option", { name: /e2e-node-1/ }).first().click();
        await page.getByTestId("network-range-save").click();
        await page.getByTestId("network-ranges-table").getByText(cidr).first().waitFor({ timeout: 20000 });
        s.check(`range_saved_${cidr}`, true, { expected: cidr, observed: "listed" });
      }
    }
    const sni = [...new Set(nets.flatMap((n) => n.sni || []))];
    if (sni.length) {
      await page.getByTestId("network-sni-edit").click();
      await page.getByTestId("network-sni-text").fill(sni.join("\n"));
      await page.getByTestId("network-sni-save").click();
      await page.waitForTimeout(1000);
      const body = await page.content();
      s.check("sni_names_saved", sni.every((n) => body.includes(n)), { expected: sni, observed: sni.filter((n) => body.includes(n)) });
    }
    for (const ex of lab.never_scan || []) {
      await page.getByTestId("network-exclusion-cidr").fill(ex);
      await page.getByTestId("network-exclusion-reason").fill("cbom-e2e canary");
      await page.getByTestId("network-exclusion-add").click();
      const listed = await page.getByTestId("network-exclusions-table").getByText(ex).count().catch(() => 0);
      s.check(`never_scan_${ex}`, listed > 0, { expected: `${ex} listed under never scan`, observed: listed ? "listed" : "refused or absent", evidence: [await s.shot(page, "never-scan")] });
    }
    await page.getByRole("button", { name: /^every hour$/i }).first().click();
    await page.getByTestId("network-soc-email").fill("soc@agents.dss.test");
    await page.getByTestId("network-emergency").fill("+91 00000 00000 (lab)");
    await page.getByTestId("network-save").click();
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1500);
    await s.shot(page, "network-saved");
    const [[cfg] = []] = db(`SELECT row_to_json(s)::text FROM cbomcollectionsettings s WHERE team_id = ${A.team}`);
    s.check("settings_saved_db", !!cfg && (nets[0].ranges || []).every((r) => cfg.includes(r)), { expected: nets.flatMap((n) => n.ranges), observed: cfg ? "ranges in cbomcollectionsettings" : "no settings row" });
    // canary / control accept counts from the lab listeners (O-8 positive control) after the save
    for (const l of lab.listeners || []) {
      const p = join(RUN, l.log || "");
      const n = existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean).length : -1;
      state[`accepts_${l.name}_g5`] = n;
    }
  });

  // G9 review & run -----------------------------------------------------------------------------------------
  await step("G9", A.ctx, async (s) => {
    const { page } = A;
    await sourcesTab(page, A.team, "Review & Run");
    await page.getByTestId("review-estimate").click();
    const req = page.getByTestId("review-credits-required");
    await req.waitFor({ timeout: 30000 });
    const estimate = Number(((await req.textContent()) || "").replace(/[^\d.]/g, ""));
    state.estimate = estimate;
    const ack = page.locator("#review-soc-ack");
    if (await ack.count()) await ack.check();
    await s.shot(page, "review");
    const before = db(`SELECT count(*) FROM cbomcollectionrun WHERE team_id = ${A.team}`)[0][0];
    await page.getByTestId("review-start").dblclick();
    let runs = [];
    for (let i = 0; i < 20 && runs.length === 0; i++) { await sleep(1000); runs = db(`SELECT id, credits_charged_c FROM cbomcollectionrun WHERE team_id = ${A.team} ORDER BY id`); }
    await sleep(2500);
    runs = db(`SELECT id, credits_charged_c FROM cbomcollectionrun WHERE team_id = ${A.team} ORDER BY id`);
    s.check("one_run_for_double_click", runs.length - Number(before) === 1, { expected: 1, observed: runs.length - Number(before) });
    if (runs.length) {
      state.runs = [Number(runs[runs.length - 1][0])];
      const charged = Number(runs[runs.length - 1][1]) / 100;
      s.check("estimate_eq_charge", charged === estimate, { expected: estimate, observed: charged, reason: "estimate-vs-charge" });
    }
  });

  // G10 watch -----------------------------------------------------------------------------------------------
  await step("G10", A.ctx, async (s) => {
    const runId = state.runs?.[0];
    if (!runId) { s.check("run_exists", false, { expected: "a run from G9", observed: null }); return; }
    const t0 = Date.now();
    let jobs = [];
    while (Date.now() - t0 < 15 * 60000) {
      jobs = db(`SELECT id, status, outcome, asset_count FROM cbomcollectionjob WHERE run_id = ${runId} ORDER BY id`);
      if (jobs.length && jobs.every((j) => ["success", "failure", "cancelled", "expired"].includes(j[1]))) break;
      await sleep(5000);
    }
    const done = jobs.length && jobs.every((j) => ["success", "failure", "cancelled", "expired"].includes(j[1]));
    s.check("run_finished_15min", !!done, { expected: "every job finished within 15 min", observed: jobs.map((j) => `${j[0]}:${j[1]}/${j[2]}`) });
    const { page } = A;
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForTimeout(2000);
    const label = { ok: "All targets read", partial: "Partly read", failed: "Nothing read" };
    for (const [id, status, outcome] of jobs) {
      const row = page.getByTestId(`review-job-${id}`);
      const text = (await row.textContent().catch(() => "")) || "";
      const want = status === "success" ? label[outcome] || outcome : status;
      s.check(`job_${id}_ui_eq_db`, !!want && text.toLowerCase().includes(String(want).toLowerCase()), { expected: { status, outcome, label: want }, observed: text.slice(0, 200), subject: { job: id } });
    }
    await s.shot(page, "watch");
    s.notRun("charge_after_runtime_skips", "the final charge after runtime skips follows OA-10b; CB-05 adds the check (KF-8)");
    const listeners = lab?.listeners || [];
    const count = (l) => { const p = join(RUN, l.log || ""); return existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean).length : null; };
    const byName = (lab?.never_scan || []).some((n) => !/^[\d.:/]+$/.test(n));
    for (const l of listeners.filter((x) => x.role === "canary")) {
      const n = count(l);
      s.check(`canary_accepts_${l.name}`, n === 0, { expected: 0, observed: n, reason: n === null ? "listener-log-missing" : "never-scan-reached",
        subject: { check: "canary_accepts", never_scan_by: byName ? "name" : "address", listener: l.name }, evidence: [l.log] });
    }
    for (const l of listeners.filter((x) => x.role === "control")) {
      const n = count(l);
      s.check(`control_accepts_${l.name}`, n !== null && n >= 1, { expected: ">= 1 (positive control)", observed: n, reason: "control-not-reached",
        subject: { check: "control_accepts", listener: l.name }, evidence: [l.log] });
    }
  });

  // G11 results (DOM + API pages with the same token), G12 exports -------------------------------------------
  await step("G11", A.ctx, async (s) => {
    const runId = state.runs?.[0];
    if (!runId) { s.check("run_exists", false, { expected: "a run", observed: null }); return; }
    const { page } = A;
    await page.goto(`${UI}/${A.team}/cbom/sources?tab=review`, { waitUntil: "networkidle" });
    await page.getByTestId(`review-run-details-${runId}`).click();
    await page.getByTestId("run-results").waitFor({ timeout: 30000 });
    // every page of the API with the customer's own token
    const items = []; let first = null;
    for (let p = 1; p < 500; p++) {
      const r = await apiGet(A, `/${A.team}/cbom/sources/runs/${runId}/assets?page=${p}&page_size=200`);
      if (r.status !== 200) { s.check("api_assets_200", false, { expected: 200, observed: r.status }); break; }
      first = first || r.body;
      items.push(...r.body.items);
      if (items.length >= r.body.total || !r.body.items.length) break;
    }
    writeJson(join(RUN, "api", "assets-run1.json"), { run_id: runId, total: first?.total, all_total: first?.all_total, facets: first?.facets, targets: first?.targets, pages: Math.ceil(items.length / 200), items });
    const run = await apiGet(A, `/${A.team}/cbom/sources/runs/${runId}`);
    writeJson(join(RUN, "api", `run-${runId}.json`), run.body);
    const posture = await apiGet(A, `/${A.team}/cbom/sources/runs/${runId}/posture`);
    writeJson(join(RUN, "api", "posture-run1.json"), posture.body);
    // the DOM: every row of every page of the Results table
    const rows = [];
    for (let p = 1; p < 200; p++) {
      const got = await page.$$eval('[data-testid^="run-asset-"]', (trs) => trs.filter((tr) => /^run-asset-\d+$/.test(tr.dataset.testid)).map((tr) => {
        const td = [...tr.querySelectorAll("td")];
        const where = td[4] ? [...td[4].querySelectorAll("span")].map((x) => x.textContent.trim()) : [];
        return { id: Number(tr.dataset.testid.slice(10)), impact: td[2]?.textContent.trim(), type: td[3]?.textContent.trim(),
          location: where[0] ?? null, target: where[1] ?? null, algorithm: td[5]?.textContent.trim(), finding: td[6]?.textContent.trim(), quantum: td[7]?.textContent.trim() };
      }));
      rows.push(...got);
      const next = page.getByRole("button", { name: /next/i }).first();
      if (!(await next.count()) || (await next.isDisabled())) break;
      await next.click(); await page.waitForLoadState("networkidle"); await page.waitForTimeout(500);
    }
    const totalText = (await page.getByTestId("run-results-total").textContent().catch(() => "")) || "";
    writeJson(join(RUN, "ui", "assets-run1.json"), { run_id: runId, total_text: totalText.trim(), rows });
    s.check("dom_rows_eq_api", rows.length === items.length, { expected: items.length, observed: rows.length });
    await s.shot(page, "results");
    // drill-down of the first row (detail panel opens)
    if (rows[0]) {
      await page.getByTestId(`run-asset-${rows[0].id}`).click().catch(() => {});
      await page.waitForTimeout(1000);
      await s.shot(page, "drilldown");
    }
  });

  await step("G12", A.ctx, async (s) => {
    const runId = state.runs?.[0];
    if (!runId) { s.check("run_exists", false, { expected: "a run", observed: null }); return; }
    const { page } = A;
    const bodies = {};
    const onResp = async (r) => {
      const u = r.url();
      if (u.includes(`/runs/${runId}/`) && r.status() === 200 && /cbom|oscal/.test(u)) {
        try { bodies[u] = await r.body(); } catch { /* streamed */ }
      }
    };
    page.on("response", onResp);
    for (const [tid, name] of [["run-results-download", "run1.cdx.json"], ["run-results-download-xml", "run1.cdx.xml"], ["run-results-download-oscal", "run1.oscal.json"]]) {
      const btn = page.getByTestId(tid);
      if (!(await btn.count())) { s.check(`download_${name}`, false, { expected: `button ${tid}`, observed: "absent" }); continue; }
      const [dl] = await Promise.all([page.waitForEvent("download", { timeout: 60000 }), btn.click()]);
      const p = join(RUN, "exports", name);
      await dl.saveAs(p);
      await page.waitForTimeout(800);
      const file = readFileSync(p);
      const match = Object.entries(bodies).find(([, b]) => b && sha256(b) === sha256(file));
      s.check(`download_${name}_eq_har_body`, !!match, { expected: sha256(file), observed: Object.fromEntries(Object.entries(bodies).map(([u, b]) => [u.replace(API, ""), b ? sha256(b) : null])), subject: { file: name } });
      if (name.endsWith(".json")) {
        let doc = null; try { doc = JSON.parse(file.toString("utf8")); } catch { /* checked below */ }
        s.check(`${name}_parses`, !!doc, { expected: "valid JSON", observed: doc ? "ok" : "parse error", subject: { file: name } });
        if (doc && name.startsWith("run1.cdx")) s.check("cdx_spec", doc.bomFormat === "CycloneDX" && doc.specVersion === "1.6", { expected: "CycloneDX 1.6", observed: `${doc.bomFormat} ${doc.specVersion}` });
      } else {
        const xml = file.toString("utf8");
        s.check(`${name}_well_formed`, xml.startsWith("<?xml") && xml.includes("<bom"), { expected: "an XML bom document", observed: xml.slice(0, 80), subject: { file: name } });
      }
      writeFileSync(`${p}.sha256`, `${sha256(file)}  ${name}\n`);
    }
    page.off("response", onResp);
    s.notRun("schema_validation", "JSON schema + cyclonedx-python-lib strict, XML against the vendored XSD and the OSCAL validator are CB-05's G12 spec");
    s.notRun("vex_states", "VEX states per OA-10c are judged once CB-22 defines them (KF-11)");
  });

  for (const [g, why] of [["G13", "drift (lab mutate + Run again) is CB-05's spec"], ["G13b", "drift with a never-scan in range is CB-05's spec (KF-12)"]]) {
    if (STEPS.has(g)) notRun(g, why);
  }

  // G14 tenancy ---------------------------------------------------------------------------------------------
  await step("G14", null, async (s) => {
    B = await signUp(browser, "customerB", s);
    state.teams = { ...(state.teams || {}), B: B.team };
    const ids = { node: state.node?.id, run: state.runs?.[0] };
    const assets = readJson(join(RUN, "api", "assets-run1.json"))?.items || [];
    const probes = [
      ["node", ids.node && `/${A.team}/cbom/sources/nodes/${ids.node}`],
      ["run", ids.run && `/${A.team}/cbom/sources/runs/${ids.run}`],
      ["run_assets", ids.run && `/${A.team}/cbom/sources/runs/${ids.run}/assets`],
      ["run_cbom", ids.run && `/${A.team}/cbom/sources/runs/${ids.run}/cbom`],
      ["asset", assets[0] && `/${A.team}/cbom/sources/assets/${assets[0].id}`],
      ["run_in_own_team", ids.run && `/${B.team}/cbom/sources/runs/${ids.run}`],
      ["asset_in_own_team", assets[0] && `/${B.team}/cbom/sources/assets/${assets[0].id}`],
    ];
    for (const [name, path] of probes) {
      if (!path) continue;
      const r = await apiGet(B, path);
      s.check(`b_gets_404_${name}`, r.status === 404, { expected: 404, observed: r.status, subject: { probe: name } });
    }
    await B.page.goto(`${UI}/${A.team}/cbom/sources?tab=review`, { waitUntil: "networkidle" });
    await B.page.waitForTimeout(1500);
    const still = await apiGet(B, `/${B.team}/cbom/sources/runs`);
    s.check("b_not_logged_out", still.status === 200 && !/\/login/.test(B.page.url()), { expected: "B still signed in", observed: { status: still.status, url: new URL(B.page.url()).pathname }, evidence: [await s.shot(B.page, "b-on-a-url")] });
  });
} catch (e) {
  console.error(`flow stopped: ${String(e.message || e).split("\n")[0]}`);
} finally {
  state.finished = iso();
  state.seconds = Math.round((Date.now() - tStart) / 1000);
  state.console_errors = { A: A?.console.length ?? null, B: B?.console.length ?? null };
  state.http_5xx = { A: A?.failed ?? [], B: B?.failed ?? [] };
  state.logged_out = {};
  for (const [k, who] of [["A", A], ["B", B]]) if (who?.team) state.logged_out[k] = await signOut(who);
  saveState();
  for (const who of [A, B]) if (who) { await who.ctx.tracing.stop().catch(() => {}); await who.ctx.close().catch(() => {}); }
  await browser.close();
}
console.log(`flow done in ${state.seconds}s; secrets for redaction in ${SECRETS_FILE}`);
