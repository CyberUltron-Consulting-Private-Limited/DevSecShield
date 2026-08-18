#!/usr/bin/env node
/**
 * CERT-In Phase 2 — durable browser gate (AI BOM customer path).
 *
 * Asserts AI BOM results: CERT-In AIBOM bar, All + India chips (All default),
 * India filter, T10 + 9.4.1 drilldown, no QBOM, hard-refresh persistence.
 *
 * Inputs:
 *   - /tmp/certin_phase2_tokens.json  { access, refresh?, scan_id, team_id? }
 *   - env ACCESS_TOKEN, SCAN_ID, TEAM_ID (default 1), FRONTEND_BASE
 *
 * Usage: node scripts/e2e/certin_phase2_browser.cjs
 */
const fs = require('fs');

function loadTokens() {
  const file = process.env.CERTIN_TOKENS_FILE || '/tmp/certin_phase2_tokens.json';
  if (fs.existsSync(file)) {
    const t = JSON.parse(fs.readFileSync(file, 'utf8'));
    return {
      access: t.access || t.access_token,
      refresh: t.refresh || t.refresh_token || t.access,
      scanId: String(t.scan_id || t.scanId || process.env.SCAN_ID || ''),
      teamId: String(t.team_id || t.teamId || process.env.TEAM_ID || '1'),
    };
  }
  if (!process.env.ACCESS_TOKEN || !process.env.SCAN_ID) {
    console.error('Missing tokens: set ACCESS_TOKEN+SCAN_ID or write', file);
    process.exit(2);
  }
  return {
    access: process.env.ACCESS_TOKEN,
    refresh: process.env.REFRESH_TOKEN || process.env.ACCESS_TOKEN,
    scanId: String(process.env.SCAN_ID),
    teamId: String(process.env.TEAM_ID || '1'),
  };
}

(async () => {
  const { chromium } = require('/opt/homebrew/lib/node_modules/playwright');
  const tokens = loadTokens();
  const base = process.env.FRONTEND_BASE || 'http://localhost:3000';
  const out = { scan_id: tokens.scanId, team_id: tokens.teamId, ok: false, errors: [] };

  const fail = (msg) => {
    out.errors.push(msg);
    out.ok = false;
    fs.writeFileSync('/tmp/certin_phase2_browser.json', JSON.stringify(out, null, 2));
    console.error(JSON.stringify(out, null, 2));
    process.exit(1);
  };

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  await ctx.addInitScript((t) => {
    localStorage.setItem('access_token', t.access);
    localStorage.setItem('refresh_token', t.refresh);
  }, tokens);

  const page = await ctx.newPage();
  const consoleErrors = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => consoleErrors.push(String(err)));

  const resultsUrl = `${base}/${tokens.teamId}/ai_bom/${tokens.scanId}/results`;
  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.goto(resultsUrl, { waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForTimeout(5000);
  await page
    .getByText(/Regulatory Compliance Readiness|CERT-In AIBOM|India \/ CERT-In/i)
    .first()
    .waitFor({ timeout: 45000 })
    .catch(() => {});

  let body = await page.evaluate(() => document.body.innerText);
  if (/\bQBOM\b/.test(body)) fail('QBOM text present in product UI');

  const chipTexts = await page.locator('button').evaluateAll((els) =>
    els.map((e) => (e.textContent || '').trim()).filter(Boolean)
  );
  out.chips = chipTexts.filter((t) => /^(All|India \/ CERT-In)$/.test(t));
  if (!chipTexts.includes('All')) fail('All chip missing');
  if (!chipTexts.includes('India / CERT-In')) fail('India / CERT-In chip missing');
  if (!/CERT-In AIBOM/i.test(body)) fail('CERT-In AIBOM label/bar missing');

  const indiaBtn = page.getByRole('button', { name: 'India / CERT-In' });
  if (!(await indiaBtn.count())) fail('India button not found');
  await indiaBtn.click();
  await page.waitForTimeout(1000);
  body = await page.evaluate(() => document.body.innerText);
  if (!/CERT-In AIBOM/i.test(body)) fail('CERT-In disappeared after India filter');
  if (/NIST AI RMF/i.test(body)) fail('NIST still visible after India filter');

  let drill = { hasT10: false, has941: false, reqTitle: false };
  const certLabel = page.getByText('CERT-In AIBOM (Guidelines v2.0)', { exact: false }).first();
  if (await certLabel.count()) {
    await certLabel.click({ force: true }).catch(() => {});
    await page.waitForTimeout(800);
  }
  const paths = page.locator('.recharts-bar-rectangle path, .recharts-rectangle');
  const n = await paths.count();
  for (let i = 0; i < Math.min(n, 50); i++) {
    const box = await paths.nth(i).boundingBox();
    if (box && box.width >= 6) {
      await paths.nth(i).click({ force: true }).catch(() => {});
      await page.waitForTimeout(500);
      const t = await page.evaluate(() => document.body.innerText);
      if (/T10-|9\.4\.1\.|— requirements/i.test(t)) break;
    }
  }
  body = await page.evaluate(() => document.body.innerText);
  drill.hasT10 = /T10-/.test(body);
  drill.has941 = /9\.4\.1\./.test(body);
  drill.reqTitle = /— requirements/i.test(body);
  out.drilldown = drill;
  if (!drill.hasT10) fail('T10- requirements not visible in drilldown');
  if (!drill.has941) fail('9.4.1. manuals not visible in drilldown');

  await page.reload({ waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForTimeout(4000);
  const after = await page.evaluate(() => document.body.innerText);
  if (!/Regulatory Compliance Readiness|CERT-In AIBOM|India \/ CERT-In/i.test(after)) {
    fail('compliance matrix missing after hard refresh');
  }
  if (/\bQBOM\b/.test(after)) fail('QBOM after refresh');

  out.ok = true;
  out.consoleErrors = consoleErrors
    .filter((e) => !/favicon|HMR|websocket|Download the React DevTools/i.test(e))
    .slice(0, 10);
  out.refreshOk = true;
  fs.writeFileSync('/tmp/certin_phase2_browser.json', JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
  await browser.close();
  if (out.errors.length) process.exit(1);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
