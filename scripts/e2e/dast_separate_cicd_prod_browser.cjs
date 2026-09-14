#!/usr/bin/env node
/**
 * Prod E2E: separate DAST vs SAST CI/CD integrations.
 *
 * Env:
 *   DAST_TOKENS_FILE  JSON {access, refresh, team_id, dast_integration_id?, sast_integration_id?}
 *   FRONTEND_BASE     default https://devsecshield.zeroshield.ai
 *   DAST_PROOF_DIR
 *   CREATE_DAST_TITLE / CREATE_SAST_TITLE  optional; if set, creates from the modal
 *   KEYS_OUT_DIR      directory to write cicd keys (never under proof dir)
 */
const fs = require("fs");
const path = require("path");

function loadPlaywright() {
  const candidates = [
    "/home/contact_cyberultron_com/.npm/_npx/361ceb562f3b3235/node_modules/playwright",
    path.join(__dirname, "../../frontend/node_modules/playwright"),
    "/tmp/dast-pw/node_modules/playwright",
  ];
  for (const c of candidates) {
    try {
      return require(c);
    } catch (_e) {
      /* try next */
    }
  }
  return require("playwright");
}

function loadTokens() {
  const file = process.env.DAST_TOKENS_FILE || "/tmp/dast_sep_tokens.json";
  const t = JSON.parse(fs.readFileSync(file, "utf8"));
  return {
    access: t.access || t.access_token,
    refresh: t.refresh || t.refresh_token || t.access,
    teamId: String(t.team_id || t.teamId || process.env.TEAM_ID || "1"),
    dastIntegrationId: t.dast_integration_id || process.env.DAST_INTEGRATION_ID || "",
    sastIntegrationId: t.sast_integration_id || process.env.SAST_INTEGRATION_ID || "",
  };
}

(async () => {
  const { chromium } = loadPlaywright();
  const tokens = loadTokens();
  const base = process.env.FRONTEND_BASE || "https://devsecshield.zeroshield.ai";
  const proofDir =
    process.env.DAST_PROOF_DIR ||
    path.join(__dirname, "../../.skill-workspace/dast-separate-cicd-proofs");
  const videoDir = path.join(proofDir, "video-raw");
  const keysDir = process.env.KEYS_OUT_DIR || "/tmp/dast-sep-keys";
  fs.mkdirSync(proofDir, { recursive: true });
  fs.mkdirSync(videoDir, { recursive: true });
  fs.mkdirSync(keysDir, { recursive: true, mode: 0o700 });

  const out = {
    team_id: tokens.teamId,
    ok: false,
    errors: [],
    shots: [],
    dastTabOnSastGuide: false,
    ghaOnDastGuide: false,
    scanSettingsHasProfiles: false,
    createModalHasDast: false,
  };

  let browser;
  let page;
  const fail = async (msg) => {
    out.errors.push(msg);
    try {
      if (page) await page.screenshot({ path: path.join(proofDir, "FAIL.png"), fullPage: true });
    } catch (_e) {
      /* ignore */
    }
    fs.writeFileSync(path.join(proofDir, "browser.json"), JSON.stringify(out, null, 2));
    console.error(JSON.stringify(out, null, 2));
    process.exit(1);
  };

  const created = {};
  try {
    browser = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });
  } catch (_e) {
    browser = await chromium.launch({
      channel: "chrome",
      headless: true,
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });
  }

  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 960 },
    recordVideo: { dir: videoDir, size: { width: 1440, height: 960 } },
  });
  await ctx.addInitScript((t) => {
    localStorage.setItem("access_token", t.access);
    localStorage.setItem("refresh_token", t.refresh);
  }, tokens);

  page = await ctx.newPage();
  page.on("response", async (res) => {
    const url = res.url();
    if (!url.includes("/cicd/integration") || res.request().method() !== "POST") return;
    if (url.includes("/cicd/integrations")) return;
    try {
      const body = await res.json();
      if (body && body.integration_id && body.api_key) {
        created.last = body;
      }
    } catch (_e) {
      /* ignore */
    }
  });

  const shot = async (name) => {
    const dest = path.join(proofDir, `${name}.png`);
    await page.screenshot({ path: dest, fullPage: true });
    out.shots.push(name);
  };

  const writeKey = (kind, payload) => {
    const dest = path.join(keysDir, `${kind}.json`);
    fs.writeFileSync(
      dest,
      JSON.stringify({ integration_id: payload.integration_id, api_key: payload.api_key }),
      { mode: 0o600 },
    );
    fs.writeFileSync(path.join(keysDir, `${kind}.key`), String(payload.api_key), { mode: 0o600 });
  };

  await page.goto(`${base}/login`, { waitUntil: "domcontentloaded", timeout: 60000 });
  const listStatus = await page.goto(`${base}/${tokens.teamId}/ci_cd`, {
    waitUntil: "networkidle",
    timeout: 90000,
  });
  out.cicdListStatus = listStatus && listStatus.status();
  if (!listStatus || listStatus.status() >= 400) await fail(`CI/CD list HTTP ${out.cicdListStatus}`);
  await page.getByRole("heading", { name: /CI\/CD Integrations/i }).waitFor({ timeout: 20000 });
  await shot("01_cicd_list");

  const openCreateModal = async () => {
    await page.getByRole("button", { name: "Create Integration" }).click({ timeout: 20000 });
    await page.locator("#title").waitFor({ timeout: 15000 });
  };

  await openCreateModal();
  await page.locator("#scan_type").click({ timeout: 10000 });
  await page.getByRole("option", { name: "DAST" }).waitFor({ timeout: 10000 });
  await page.getByRole("option", { name: "SAST" }).waitFor({ timeout: 10000 });
  out.createModalHasDast = true;
  await shot("02_create_modal_dast_option");

  const createFromModal = async (title, scanType, kind, alreadyOpen) => {
    created.last = null;
    if (!alreadyOpen) {
      await page.goto(`${base}/${tokens.teamId}/ci_cd`, { waitUntil: "networkidle", timeout: 90000 });
      await openCreateModal();
      await page.locator("#scan_type").click({ timeout: 10000 });
    }
    await page.getByRole("option", { name: scanType === "dast" ? "DAST" : "SAST" }).click();
    await page.locator("#title").fill(title);
    await page.getByRole("button", { name: "Create" }).click();
    await page.waitForURL(new RegExp(`/ci_cd/\\d+`), { timeout: 30000 });
    if (!created.last) await fail(`Create ${kind} did not return api_key`);
    writeKey(kind, created.last);
    out[`${kind}_integration_id`] = created.last.integration_id;
    return created.last.integration_id;
  };

  const dastTitle = process.env.CREATE_DAST_TITLE || "";
  const sastTitle = process.env.CREATE_SAST_TITLE || "";
  let dastId = tokens.dastIntegrationId;
  let sastId = tokens.sastIntegrationId;

  if (dastTitle) {
    dastId = String(await createFromModal(dastTitle, "dast", "dast", true));
    await shot("03_dast_detail_after_create");
  } else if (dastId) {
    await page.goto(`${base}/${tokens.teamId}/ci_cd/${dastId}`, {
      waitUntil: "networkidle",
      timeout: 90000,
    });
  } else {
    await fail("No DAST integration id and CREATE_DAST_TITLE unset");
  }

  await page.getByText("Scan settings", { exact: false }).first().click({ timeout: 15000 });
  await page.getByText(/New DAST profile|Saved profiles/i).first().waitFor({ timeout: 20000 });
  out.scanSettingsHasProfiles = true;
  const settingsText = await page.locator("body").innerText();
  out.istLabelCount = (settingsText.match(/\bIST\b/g) || []).length;
  await shot("04_dast_scan_settings_profiles");

  await page.getByText("Integration Guide", { exact: false }).first().click({ timeout: 15000 });
  await page.getByText(/Jenkins DAST after deploy|DAST Jenkinsfile/i).first().waitFor({
    timeout: 20000,
  });
  const dastGuide = await page.locator("body").innerText();
  out.ghaOnDastGuide = /GitHub Actions/i.test(dastGuide) && /Atlassian Bamboo/i.test(dastGuide);
  if (out.ghaOnDastGuide) await fail("DAST guide still shows GHA/Bamboo subtabs");
  if (/^SAST$/m.test(dastGuide) && /DAST tab/i.test(dastGuide)) {
    await fail("DAST page still has SAST|DAST flavor tabs");
  }
  await shot("05_dast_jenkins_only_guide");

  await page.getByText("Dashboard", { exact: false }).first().click({ timeout: 10000 }).catch(() => {});
  await shot("06_dast_dashboard");

  if (sastTitle) {
    sastId = String(await createFromModal(sastTitle, "sast", "sast", false));
  } else if (sastId) {
    await page.goto(`${base}/${tokens.teamId}/ci_cd/${sastId}`, {
      waitUntil: "networkidle",
      timeout: 90000,
    });
  } else {
    await fail("No SAST integration id and CREATE_SAST_TITLE unset");
  }

  await page.getByText("Integration Guide", { exact: false }).first().click({ timeout: 15000 });
  await page.getByRole("button", { name: /^Jenkins$/i }).click({ timeout: 10000 }).catch(() => {});
  await page.getByText(/Jenkins Integration/i).first().waitFor({ timeout: 20000 });
  const sastGuide = await page.locator("body").innerText();
  out.dastTabOnSastGuide = /\bDAST\b/.test(sastGuide) && /Jenkins DAST after deploy/i.test(sastGuide);
  if (out.dastTabOnSastGuide) await fail("SAST Jenkins guide still has DAST tab");
  await shot("07_sast_jenkins_no_dast_tab");

  if (process.env.CICD_SCAN_ID) {
    await page.goto(`${base}/${tokens.teamId}/ci_cd/${dastId}`, {
      waitUntil: "networkidle",
      timeout: 90000,
    });
    await shot("08_dast_dashboard_after_scan");
    await page.goto(`${base}/${tokens.teamId}/dast`, { waitUntil: "networkidle", timeout: 90000 });
    await page.getByRole("tab", { name: /Table/i }).click({ timeout: 15000 });
    await page.waitForTimeout(1500);
    await shot("09_dast_table");
  }

  out.ok = true;
  fs.writeFileSync(path.join(proofDir, "browser.json"), JSON.stringify(out, null, 2));
  const idsOut = {
    dast_integration_id: Number(dastId),
    sast_integration_id: Number(sastId),
  };
  fs.writeFileSync(path.join(keysDir, "ids.json"), JSON.stringify(idsOut));
  fs.writeFileSync(path.join(proofDir, "00_ids.json"), JSON.stringify(idsOut, null, 2) + "\n");
  console.log(JSON.stringify({ ...out, keys: "written to KEYS_OUT_DIR not proofs" }, null, 2));

  await ctx.close();
  await browser.close();
  const videos = fs.existsSync(videoDir)
    ? fs.readdirSync(videoDir).filter((f) => f.endsWith(".webm"))
    : [];
  if (videos.length) {
    fs.copyFileSync(path.join(videoDir, videos[0]), path.join(proofDir, "prod-e2e-recording.webm"));
  }
  process.exit(0);
})().catch(async (err) => {
  const proofDir =
    process.env.DAST_PROOF_DIR ||
    path.join(__dirname, "../../.skill-workspace/dast-separate-cicd-proofs");
  fs.mkdirSync(proofDir, { recursive: true });
  fs.writeFileSync(path.join(proofDir, "browser_error.txt"), String(err && err.stack ? err.stack : err));
  console.error(err);
  process.exit(1);
});
