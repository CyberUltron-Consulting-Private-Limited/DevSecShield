#!/usr/bin/env node
/**
 * Prod E2E recording: DAST IST schedules + Jenkins DAST guide + CI logs + DAST table.
 *
 * Env:
 *   DAST_TOKENS_FILE  JSON {access, refresh, team_id, integration_id?, cicd_scan_id?}
 *   FRONTEND_BASE     default https://devsecshield.zeroshield.ai
 *   DAST_PROOF_DIR
 */
const fs = require("fs");
const path = require("path");

function loadPlaywright() {
  const candidates = [
    "/home/contact_cyberultron_com/.npm/_npx/361ceb562f3b3235/node_modules/playwright",
    "/opt/homebrew/lib/node_modules/playwright",
    "/usr/lib/node_modules/playwright",
    path.join(__dirname, "../../frontend/node_modules/playwright"),
    path.join("/tmp/dast-pw/node_modules/playwright"),
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
  const file = process.env.DAST_TOKENS_FILE || "/tmp/dast_ist_tokens.json";
  const t = JSON.parse(fs.readFileSync(file, "utf8"));
  return {
    access: t.access || t.access_token,
    refresh: t.refresh || t.refresh_token || t.access,
    teamId: String(t.team_id || t.teamId || process.env.TEAM_ID || "1"),
    integrationId: t.integration_id || process.env.INTEGRATION_ID || "",
    cicdScanId: t.cicd_scan_id || process.env.CICD_SCAN_ID || "",
    profileTitle: t.profile_title || "ist-hourly-two-times-r2",
  };
}

(async () => {
  const { chromium } = loadPlaywright();
  const tokens = loadTokens();
  const base = process.env.FRONTEND_BASE || "https://devsecshield.zeroshield.ai";
  const proofDir = process.env.DAST_PROOF_DIR || path.join(__dirname, "../../.skill-workspace/dast-jenkins-ist-proofs");
  const videoDir = path.join(proofDir, "video-raw");
  fs.mkdirSync(proofDir, { recursive: true });
  fs.mkdirSync(videoDir, { recursive: true });

  const out = {
    team_id: tokens.teamId,
    ok: false,
    errors: [],
    passwordLeaks: 0,
    utcLabelCount: 0,
    istLabelCount: 0,
    jenkinsfileHasProfile: false,
    shots: [],
  };

  let browser;
  let page;
  const fail = async (msg) => {
    out.errors.push(msg);
    try {
      if (page) {
        await page.screenshot({ path: path.join(proofDir, "FAIL.png"), fullPage: true });
      }
    } catch (_e) {
      /* ignore */
    }
    fs.writeFileSync(path.join(proofDir, "browser.json"), JSON.stringify(out, null, 2));
    console.error(JSON.stringify(out, null, 2));
    process.exit(1);
  };

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
  const leaks = [];
  page.on("response", async (res) => {
    const url = res.url();
    if (!url.includes("/dast/profiles") && !url.includes("/dast/scan/")) return;
    if (res.request().method() !== "GET") return;
    try {
      const text = await res.text();
      if (/"password"\s*:/.test(text) || text.includes("demo123")) leaks.push(url);
    } catch (_e) {
      /* ignore */
    }
  });

  const shot = async (name) => {
    const dest = path.join(proofDir, `${name}.png`);
    await page.screenshot({ path: dest, fullPage: true });
    out.shots.push(name);
  };

  await page.goto(`${base}/login`, { waitUntil: "domcontentloaded", timeout: 60000 });
  const dastStatus = await page.goto(`${base}/${tokens.teamId}/dast`, {
    waitUntil: "networkidle",
    timeout: 90000,
  });
  out.dastStatus = dastStatus && dastStatus.status();
  if (!dastStatus || dastStatus.status() >= 400) await fail(`DAST page HTTP ${out.dastStatus}`);

  await page.getByRole("tab", { name: /Profiles/i }).click({ timeout: 30000 });
  await page.getByText(/New DAST profile|Saved profiles/i).first().waitFor({ timeout: 20000 });
  await page.getByText(/ist-hourly-two-times-r2|Times are IST|Next run is shown in IST/i).first().waitFor({ timeout: 30000 });
  await page.getByText(tokens.profileTitle).first().waitFor({ timeout: 30000 });
  await shot("01_profiles_ist");

  const bodyText = await page.locator("body").innerText();
  out.istLabelCount = (bodyText.match(/\bIST\b/g) || []).length;
  out.hasLegacyUtcSchedule = /daily 00:00 UTC|00:00 UTC/.test(bodyText);
  if (out.istLabelCount < 1) await fail("Profiles tab has no IST labels after deploy");
  if (out.hasLegacyUtcSchedule) await fail("Profiles tab still shows UTC schedule labels");

  await page.getByRole("combobox").filter({ hasText: /^Off$/ }).click({ timeout: 15000 });
  await page.getByRole("option", { name: /Hourly \(IST\)/i }).waitFor({ timeout: 10000 });
  await shot("02_schedule_presets_ist");
  await page.getByRole("option", { name: /Custom cron \(IST\)/i }).click();
  await page.getByText(/Visual cron builder \(IST\)/i).first().waitFor({ timeout: 10000 });
  await shot("03_cron_builder_ist");

  const cicdList = await page.goto(`${base}/${tokens.teamId}/ci_cd`, {
    waitUntil: "networkidle",
    timeout: 90000,
  });
  out.cicdListStatus = cicdList && cicdList.status();
  await shot("04_cicd_list");

  let integrationUrl = tokens.integrationId
    ? `${base}/${tokens.teamId}/ci_cd/${tokens.integrationId}`
    : "";
  if (!integrationUrl) {
    const link = page.locator(`a[href*='/${tokens.teamId}/ci_cd/']`).first();
    if (await link.count()) {
      integrationUrl = await link.getAttribute("href");
      if (integrationUrl && integrationUrl.startsWith("/")) integrationUrl = base + integrationUrl;
    }
  }
  if (!integrationUrl) await fail("No CI/CD integration URL");
  await page.goto(integrationUrl, { waitUntil: "networkidle", timeout: 90000 });
  await shot("05_cicd_dashboard_logs");

  const dashText = await page.locator("body").innerText();
  out.dashboardHasDastKind = /DAST/i.test(dashText);
  out.dashboardHasScanId = tokens.cicdScanId ? dashText.includes(`#${tokens.cicdScanId}`) : /#\d+/.test(dashText);

  await page.getByText("Integration Guide", { exact: false }).first().click({ timeout: 15000 });
  await page.getByRole("button", { name: /^Jenkins$/i }).click({ timeout: 10000 }).catch(() => {});
  await page.getByText(/Jenkins DAST after deploy|DAST Jenkinsfile|Saved profile/i).first().waitFor({
    timeout: 20000,
  });
  await shot("06_jenkins_dast_tab");

  const guideText = await page.locator("body").innerText();
  if (!/DAST_PROFILE_ID/.test(guideText) || !/\/cicd\/dast\/scan/.test(guideText)) {
    await fail("Jenkins DAST tab missing profile id or /cicd/dast/scan");
  }
  const pre = await page.locator("pre").first().innerText();
  out.jenkinsfileSnippet = pre.slice(0, 400);
  out.jenkinsfileHasProfile = /DAST_PROFILE_ID = '\d+'/.test(pre);
  if (!out.jenkinsfileHasProfile) await fail("Jenkinsfile did not fill a numeric DAST_PROFILE_ID");

  await page.locator("#dast-cicd-profile").click({ timeout: 10000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shot("07_jenkins_profile_picker");

  await page.goto(`${base}/${tokens.teamId}/dast`, { waitUntil: "networkidle", timeout: 90000 });
  await page.getByRole("tab", { name: /Table/i }).click({ timeout: 15000 });
  await page.waitForTimeout(1500);
  await shot("08_dast_table");
  const tableText = await page.locator("body").innerText();
  out.tableHasCicd = /\(cicd\)/i.test(tableText);
  out.tableHasSchedule = /\(schedule\)/i.test(tableText);
  out.tableHasManual = /\(manual\)/i.test(tableText);

  out.passwordLeaks = leaks.length;
  if (leaks.length) await fail(`password present in GET JSON: ${leaks.join(", ")}`);

  out.ok = true;
  fs.writeFileSync(path.join(proofDir, "browser.json"), JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));

  await ctx.close();
  await browser.close();

  const videos = fs.existsSync(videoDir)
    ? fs.readdirSync(videoDir).filter((f) => f.endsWith(".webm"))
    : [];
  if (videos.length) {
    fs.copyFileSync(path.join(videoDir, videos[0]), path.join(proofDir, "prod-e2e-recording.webm"));
  }
  process.exit(0);
})().catch((err) => {
  const proofDir =
    process.env.DAST_PROOF_DIR ||
    path.join(__dirname, "../../.skill-workspace/dast-jenkins-ist-proofs");
  fs.mkdirSync(proofDir, { recursive: true });
  fs.writeFileSync(path.join(proofDir, "browser_error.txt"), String(err && err.stack ? err.stack : err));
  console.error(err);
  process.exit(1);
});
