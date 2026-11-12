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
import * as cb05 from "./cb05.mjs";

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
const TERMINAL = ["success", "failure", "failed", "cancelled", "expired"];
const ALL = ["G1", "G2", "G3", "G4", "G5", "G5b", "G6", "G7", "G8", "G9", "G10", "G11", "G12", "G13", "G13b", "G14"];
const STEPS = new Set(args.steps ? args.steps.split(",") : ALL);
const SECRETS_FILE = args["secrets-file"] || `/tmp/cbom-e2e-secrets-${process.pid}.json`;
const HERE = dirname(fileURLToPath(import.meta.url));
const LAB_DIR = args["lab-dir"] || join(HERE, "..", "..", "..");
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
    'exec psql -X -q -At -z -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
    { input: `BEGIN READ ONLY;\n${sql};\nCOMMIT;\n`, encoding: "utf8", timeout: 60000 });
  return out.trim() ? out.trim().split("\n").map((l) => l.split("\0")) : [];
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
  ctx.setDefaultTimeout(30000);
  ctx.setDefaultNavigationTimeout(60000);
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

function inCidr(ip, cidr) {
  const [net, bits = "32"] = cidr.split("/");
  const n = (a) => a.split(".").reduce((x, o) => x * 256 + Number(o), 0);
  const size = 2 ** (32 - Number(bits));
  return Math.floor(n(ip) / size) === Math.floor(n(net) / size);
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
    execFileSync("python3", [`${R6}/local/bin/dss.py`, "topup", String(A.team), String(TOPUP)], { stdio: "ignore", timeout: 300000 });
    await A.page.reload({ waitUntil: "networkidle" });
    const text = await A.page.getByText(/\d+(\.\d+)? credits/).first().textContent({ timeout: 20000 }).catch(() => "");
    const shown = Number((text.match(/([\d.]+) credits/) || [])[1]);
    const [[dbBalance] = []] = db(`SELECT credit_balance FROM team WHERE id = ${A.team}`);
    s.check("credits_ui_eq_db", shown === Number(dbBalance) && shown === TOPUP, { expected: { ui: TOPUP, db: TOPUP },
      observed: { ui: shown, db: Number(dbBalance) }, evidence: [await s.shot(A.page, "credits")] });
  });
  if (!A) throw new Error("customer A could not sign up; nothing else can run");
  await A.ctx.tracing.stop({ path: join(RUN, "steps", "G1", "trace.zip") }).catch(() => {});
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
    // the code block renders a light and a dark copy; the customer sees (and copies) the visible one
    const pre = page.locator("#scan-node-wizard pre").filter({ visible: true }).first();
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

  // CB-05 steps (cb05.mjs; INTERFACES.md v5): one context object for them
  const ctx = { RUN, R6, UI, API, SHA, HERE, LAB_DIR, TERMINAL, lab, state, browser, node, get A() { return A; }, get B() { return B; },
    step: (g, c, fn) => (STEPS.has(g) ? step(g, c, fn) : undefined), db, apiGet, sourcesTab, remember, inCidr, sleep, iso, writeJson, readJson, sha256 };
  // G4 servers (CB-05)
  await cb05.g4(ctx);

  // G5 network ----------------------------------------------------------------------------------------------
  await step("G5", A.ctx, async (s) => {
    const nets = (lab?.sources || []).filter((x) => x.kind === "network");
    if (!nets.length) { s.check("lab_network_sources", false, { expected: "lab.json sources of kind network", observed: lab ? "none" : "no lab.json", reason: "no-lab" }); return; }
    const { page } = A;
    state.scope = { sources: nets.map((n) => n.name), ranges: nets.flatMap((n) => n.ranges || []) };
    await sourcesTab(page, A.team, "Network TLS");
    for (const src of nets) {
      for (const cidr of src.ranges || []) {
        if (await page.getByTestId("network-add-range").count()) await page.getByTestId("network-add-range").first().click();
        else await page.getByRole("button", { name: /add (a |your first )?(network )?range/i }).first().click();
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
    }
    // the network never-scan list takes addresses and ranges (the UI refuses a host name there; never-scan by name is
    // entered on Servers in G4): the canary listener's address, so the R-canary range keeps the control reachable
    const canaries = (lab.listeners || []).filter((l) => l.role === "canary" && (state.scope.ranges || []).some((r) => inCidr(l.address, r)));
    for (const l of canaries) {
      await page.getByTestId("network-exclusion-cidr").fill(l.address);
      await page.getByTestId("network-exclusion-reason").fill("cbom-e2e canary");
      await page.getByTestId("network-exclusion-add").click();
      const listed = await page.getByTestId("network-exclusions-table").getByText(l.address).count().catch(() => 0);
      s.check(`never_scan_${l.name}`, listed > 0, { expected: `${l.address} listed under never scan`, observed: listed ? "listed" : "refused or absent", evidence: [await s.shot(page, "never-scan")] });
    }
    state.never_scan_g5 = canaries.map((l) => l.address);
    await page.getByRole("button", { name: /^every hour$/i }).first().click();
    await page.getByTestId("network-soc-email").fill("soc@agents.dss.test");
    await page.getByTestId("network-emergency").fill("+91 00000 00000");
    await page.getByTestId("network-save").click();
    const toast = await Promise.race([
      page.getByText("Fix the highlighted fields before saving").first().waitFor({ timeout: 15000 }).then(() => "refused"),
      page.getByText(/settings saved|network scope saved/i).last().waitFor({ timeout: 15000 }).then(() => "saved"),
    ]).catch(() => "no toast");
    await page.waitForLoadState("networkidle");
    await s.shot(page, "network-saved");
    s.check("network_scope_saved", toast === "saved", { expected: "saved", observed: toast });
    const [row] = db(`SELECT sni_hostnames::text, network_exclusions::text, soc_email, (SELECT bool_and(c::boolean) FROM json_array_elements(scan_window) r, json_array_elements_text(r) c(c)) FROM cbomcollectionsettings WHERE team_id = ${A.team}`);
    const ranges = db(`SELECT config->>'cidr' FROM cbomcollectionsource WHERE team_id = ${A.team} AND kind = 'network_range'`).map((r) => r[0]);
    const want = nets.flatMap((n) => n.ranges || []);
    s.check("ranges_eq_db", want.every((r) => ranges.includes(r)) && ranges.length === want.length, { expected: want, observed: ranges });
    s.check("sni_eq_db", !!row && sni.every((n) => row[0].includes(n)), { expected: sni, observed: row && row[0] });
    s.check("never_scan_eq_db", !!row && canaries.every((l) => row[1].includes(l.address)), { expected: canaries.map((l) => l.address), observed: row && row[1] });
    s.check("soc_and_window_eq_db", !!row && row[2] === "soc@agents.dss.test" && row[3] === "t", { expected: { soc_email: "soc@agents.dss.test", every_hour: true }, observed: row && { soc_email: row[2], every_hour: row[3] } });
    // canary / control accept counts from the lab listeners (O-8 positive control) after the save
    for (const l of lab.listeners || []) {
      const p = join(RUN, l.log || "");
      const n = existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean).length : -1;
      state[`accepts_${l.name}_g5`] = n;
    }
  });

  // G5b IDNA, G6 database, G7 cloud & identity, G8 evidence (CB-05)
  await cb05.g5b(ctx);
  await cb05.g6(ctx);
  await cb05.g7(ctx);
  await cb05.g8(ctx);

  // G9 review & run -----------------------------------------------------------------------------------------
  await step("G9", A.ctx, async (s) => {
    const { page } = A;
    await sourcesTab(page, A.team, "Review & Run");
    await page.getByTestId("review-estimate").click();
    const req = page.getByTestId("review-credits-required");
    await req.waitFor({ timeout: 30000 });
    const estimate = Number(((await req.textContent()) || "").replace(/[^\d.]/g, ""));
    state.estimate = estimate;
    await cb05.g9Rates(ctx, s, estimate);
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
      if (jobs.length && jobs.every((j) => TERMINAL.includes(j[1]))) break;
      await sleep(5000);
    }
    const done = jobs.length && jobs.every((j) => TERMINAL.includes(j[1]));
    s.check("run_finished_15min", !!done, { expected: "every job finished within 15 min", observed: jobs.map((j) => `${j[0]}:${j[1]}/${j[2]}`) });
    state.jobs = jobs.map(([id, status, outcome]) => ({ id: Number(id), status, outcome }));
    const { page } = A;
    await page.reload({ waitUntil: "networkidle" });
    await s.shot(page, "watch");
    // charge after runtime skips (OA-10b) and the never-scan listeners over the run's window, by path (CB-05)
    await cb05.g10(ctx, s);
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
    const seen = new Set();
    for (let p = 1; p < 200; p++) {
      const got = await page.$$eval('[data-testid^="run-asset-"]', (trs) => trs.filter((tr) => /^run-asset-\d+$/.test(tr.dataset.testid)).map((tr) => {
        const td = [...tr.querySelectorAll("td")];
        const where = td[4] ? [...td[4].querySelectorAll("span")].map((x) => x.textContent.trim()) : [];
        return { id: Number(tr.dataset.testid.slice(10)), impact: td[2]?.textContent.trim(), type: td[3]?.textContent.trim(),
          location: where[0] ?? null, target: where[1] ?? null, algorithm: td[5]?.textContent.trim(), finding: td[6]?.textContent.trim(), quantum: td[7]?.textContent.trim() };
      }));
      const fresh = got.filter((r) => !seen.has(r.id));
      fresh.forEach((r) => seen.add(r.id));
      rows.push(...fresh);
      if (!fresh.length || rows.length >= items.length) break;
      const next = page.getByTestId("run-results").getByRole("button", { name: /next/i }).first();
      if (!(await next.count()) || (await next.isDisabled())) break;
      await next.click(); await page.waitForLoadState("networkidle"); await page.waitForTimeout(500);
    }
    const totalText = (await page.getByTestId("run-results-total").textContent().catch(() => "")) || "";
    writeJson(join(RUN, "ui", "assets-run1.json"), { run_id: runId, total_text: totalText.trim(), rows });
    // per job: the results page's label = the DB (status, outcome) (G10's mapping, read where the customer sees it)
    const label = { ok: "All targets read", partial: "Partly read", failed: "Nothing read" };
    for (const j of state.jobs || []) {
      const text = ((await page.getByTestId(`run-results-job-${j.id}`).textContent().catch(() => "")) || "").trim();
      const want = j.status === "success" ? label[j.outcome] || j.outcome : j.status;
      s.check(`job_${j.id}_label_eq_db`, !!want && text.toLowerCase().includes(String(want).toLowerCase()), { expected: { status: j.status, outcome: j.outcome, label: want }, observed: text.slice(0, 200), subject: { job: j.id } });
    }
    s.check("dom_rows_eq_api", rows.length === items.length, { expected: items.length, observed: rows.length });
    await s.shot(page, "results");
    // drill-down of the first row (detail panel opens)
    if (rows[0]) {
      await page.getByTestId(`run-asset-${rows[0].id}`).click().catch(() => {});
      await page.waitForTimeout(1000);
      await s.shot(page, "drilldown");
    }
    // posture: Mosca X/Y/Z, Q-grade, calendar and heat-map against the oracle (CB-05)
    await cb05.g11Posture(ctx, s, "1");
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
    // schema validation, engine version, VEX states (OA-10c) and G8's gap snapshot (CB-05)
    cb05.g12Validate(ctx, s, "1");
  });

  // G13 drift and G13b drift with a never-scan entry in range (CB-05)
  await cb05.g13(ctx);

  // G14 tenancy ---------------------------------------------------------------------------------------------
  await step("G14", null, async (s) => {
    B = await signUp(browser, "customerB", s);
    state.teams = { ...(state.teams || {}), B: B.team };
    await B.ctx.tracing.stop({ path: join(RUN, "steps", "G14", "trace-signup-b.zip") }).catch(() => {});
    const ids = { node: state.node?.id, run: state.runs?.[0] };
    const assets = readJson(join(RUN, "api", "assets-run1.json"))?.items || [];
    // B asks for A's objects under B's own team: 404, nothing about A (no existence oracle by id)
    const own = [["run", ids.run && `/${B.team}/cbom/sources/runs/${ids.run}`],
      ["run_assets", ids.run && `/${B.team}/cbom/sources/runs/${ids.run}/assets`],
      ["run_cbom", ids.run && `/${B.team}/cbom/sources/runs/${ids.run}/cbom`],
      ["node", ids.node && `/${B.team}/cbom/sources/nodes/${ids.node}`],
      ["asset", assets[0] && `/${B.team}/cbom/sources/assets/${assets[0].id}`]];
    for (const [name, path] of own) {
      if (!path) continue;
      const r = await apiGet(B, path);
      s.check(`b_own_team_404_${name}`, r.status === 404, { expected: 404, observed: r.status, subject: { probe: name } });
    }
    // B asks under A's team: refused before any lookup, so an existing id and a missing one get the same answer
    const foreign = [["run", ids.run && `/${A.team}/cbom/sources/runs/${ids.run}`, `/${A.team}/cbom/sources/runs/2147483000`],
      ["node", ids.node && `/${A.team}/cbom/sources/nodes/${ids.node}`, `/${A.team}/cbom/sources/nodes/2147483000`],
      ["asset", assets[0] && `/${A.team}/cbom/sources/assets/${assets[0].id}`, `/${A.team}/cbom/sources/assets/2147483000`],
      ["run_cbom", ids.run && `/${A.team}/cbom/sources/runs/${ids.run}/cbom`, `/${A.team}/cbom/sources/runs/2147483000/cbom`]];
    const leakTerms = [A.email, ...assets.slice(0, 5).map((a) => a.location)].filter(Boolean);
    for (const [name, path, missing] of foreign) {
      if (!path) continue;
      const hit = await apiGet(B, path);
      const miss = await apiGet(B, missing);
      const body = JSON.stringify(hit.body || "");
      s.check(`b_foreign_team_refused_${name}`, [403, 404].includes(hit.status) && hit.status === miss.status && !leakTerms.some((t) => body.includes(t)),
        { expected: "403 or 404, the same for a missing id, no data of A", observed: { existing: hit.status, missing: miss.status, body: body.slice(0, 160) }, subject: { probe: name } });
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
