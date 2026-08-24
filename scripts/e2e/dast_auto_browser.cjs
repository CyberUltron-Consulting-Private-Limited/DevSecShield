#!/usr/bin/env node
/**
 * Automatic DAST Profiles tab — customer-path browser gate.
 *
 * Inputs:
 *   ACCESS_TOKEN, REFRESH_TOKEN, TEAM_ID (default 1), FRONTEND_BASE
 *   or /tmp/dast_auto_tokens.json { access, refresh, team_id }
 *
 * Asserts: Profiles tab, create/save, no password in GET profile JSON.
 */
const fs = require('fs');
const path = require('path');

function loadPlaywright() {
  const candidates = [
    '/opt/homebrew/lib/node_modules/playwright',
    '/usr/lib/node_modules/playwright',
    path.join(__dirname, '../../frontend/node_modules/playwright'),
  ];
  for (const c of candidates) {
    try {
      return require(c);
    } catch (_e) {
      /* try next */
    }
  }
  return require('playwright');
}

function loadTokens() {
  const file = process.env.DAST_TOKENS_FILE || '/tmp/dast_auto_tokens.json';
  if (fs.existsSync(file)) {
    const t = JSON.parse(fs.readFileSync(file, 'utf8'));
    return {
      access: t.access || t.access_token,
      refresh: t.refresh || t.refresh_token || t.access,
      teamId: String(t.team_id || t.teamId || process.env.TEAM_ID || '1'),
    };
  }
  if (!process.env.ACCESS_TOKEN) {
    console.error('Missing ACCESS_TOKEN or', file);
    process.exit(2);
  }
  return {
    access: process.env.ACCESS_TOKEN,
    refresh: process.env.REFRESH_TOKEN || process.env.ACCESS_TOKEN,
    teamId: String(process.env.TEAM_ID || '1'),
  };
}

(async () => {
  const { chromium } = loadPlaywright();
  const tokens = loadTokens();
  const base = process.env.FRONTEND_BASE || 'http://localhost:3000';
  const proofDir = process.env.DAST_PROOF_DIR || path.join(__dirname, '../../.skill-workspace/dast-auto-proofs');
  fs.mkdirSync(proofDir, { recursive: true });
  const out = { team_id: tokens.teamId, ok: false, errors: [], passwordLeaks: 0 };
  let page;

  const fail = async (msg) => {
    out.errors.push(msg);
    out.ok = false;
    try {
      if (page) {
        await page.screenshot({ path: path.join(proofDir, 'dast_profiles_tab_fail.png'), fullPage: true });
      }
    } catch (_e) { /* ignore */ }
    fs.writeFileSync(path.join(proofDir, 'dast_auto_browser.json'), JSON.stringify(out, null, 2));
    console.error(JSON.stringify(out, null, 2));
    process.exit(1);
  };

  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (_e) {
    browser = await chromium.launch({
      channel: 'chrome',
      headless: true,
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    });
  }
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  await ctx.addInitScript((t) => {
    localStorage.setItem('access_token', t.access);
    localStorage.setItem('refresh_token', t.refresh);
  }, tokens);

  page = await ctx.newPage();
  const leaks = [];
  page.on('response', async (res) => {
    const url = res.url();
    if (!url.includes('/dast/profiles') && !url.includes('/dast/scan/')) return;
    if (res.request().method() === 'GET') {
      try {
        const text = await res.text();
        if (/"password"\s*:/.test(text) || text.includes('demo123')) {
          leaks.push(url);
        }
      } catch (_e) {
        /* ignore */
      }
    }
  });

  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  const dastUrl = `${base}/${tokens.teamId}/dast`;
  const status = await page.goto(dastUrl, { waitUntil: 'networkidle', timeout: 90000 });
  if (!status || status.status() === 404) {
    await fail(`DAST route ${dastUrl} returned ${status && status.status()}`);
  }
  out.dastStatus = status && status.status();
  out.finalUrl = page.url();
  const profilesTab = page.getByRole('tab', { name: /Profiles/i }).or(page.getByText('Profiles', { exact: true }));
  await profilesTab.first().click({ timeout: 30000 });
  await page.getByText(/New DAST profile|Saved profiles/i).first().waitFor({ timeout: 20000 });

  await page.locator('#dast-profile-title').fill('playwright-testfire');
  await page.locator('#dast-profile-target').fill('https://demo.testfire.net/index.jsp');
  await page.locator('#dast-profile-login').fill('https://demo.testfire.net/login.jsp');
  await page.locator('#dast-profile-user').fill('jsmith');
  await page.locator('#dast-profile-password').fill('demo123');
  await page.locator('#dast-profile-user-xpath').fill('/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input');
  await page.locator('#dast-profile-pass-xpath').fill('/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input');
  await page.locator('#dast-profile-submit-xpath').fill('/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[3]/td[2]/input');
  await page.getByText(/I confirm this target is authorized/i).click();
  await page.getByRole('button', { name: /Save profile/i }).click();
  await page.getByText('playwright-testfire').first().waitFor({ timeout: 20000 });

  await page.screenshot({ path: path.join(proofDir, 'dast_profiles_tab.png'), fullPage: true });
  out.passwordLeaks = leaks.length;
  if (leaks.length) await fail(`password present in GET JSON: ${leaks.join(', ')}`);

  out.ok = true;
  fs.writeFileSync(path.join(proofDir, 'dast_auto_browser.json'), JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
  await browser.close();
  process.exit(0);
})().catch(async (err) => {
  console.error(err);
  try {
    const fs = require('fs');
    const path = require('path');
    const proofDir = process.env.DAST_PROOF_DIR || path.join(__dirname, '../../.skill-workspace/dast-auto-proofs');
    fs.mkdirSync(proofDir, { recursive: true });
    fs.writeFileSync(path.join(proofDir, 'dast_auto_browser_error.txt'), String(err && err.stack || err));
  } catch (_e) { /* ignore */ }
  process.exit(1);
});
