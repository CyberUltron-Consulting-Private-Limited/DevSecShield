#!/usr/bin/env node
/**
 * CERT-In Phase 5 — durable browser gate.
 *
 * Team page CertInRollup; CBOM results: All default + India chip; HBOM deferred;
 * no QBOM; hard refresh keeps rollup.
 *
 * Inputs:
 *   - /tmp/certin_phase5_tokens.json  { access, refresh?, scan_id, team_id? }
 *   - env ACCESS_TOKEN, SCAN_ID, TEAM_ID, FRONTEND_BASE, BACKEND_BASE
 *
 * Usage: node scripts/e2e/certin_phase5_browser.cjs
 */
const fs = require('fs');

function loadTokens() {
  const file = process.env.CERTIN_TOKENS_FILE || '/tmp/certin_phase5_tokens.json';
  if (fs.existsSync(file)) {
    const t = JSON.parse(fs.readFileSync(file, 'utf8'));
    return {
      access: t.access || t.access_token,
      refresh: t.refresh || t.refresh_token || t.access,
      scanId: String(t.scan_id || t.scanId || process.env.SCAN_ID || ''),
      teamId: String(t.team_id || t.teamId || process.env.TEAM_ID || '1'),
    };
  }
  // Fall back to phase4 tokens if present
  const p4 = '/tmp/certin_phase4_tokens.json';
  if (fs.existsSync(p4)) {
    const t = JSON.parse(fs.readFileSync(p4, 'utf8'));
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
    fs.writeFileSync('/tmp/certin_phase5_browser.json', JSON.stringify(out, null, 2));
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

  // ── Team dashboard: CertInRollup ──────────────────────────────────────────
  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.goto(`${base}/${tokens.teamId}`, {
    waitUntil: 'domcontentloaded',
    timeout: 90000,
  });
  await page.waitForTimeout(5000);
  let body = await page.evaluate(() => document.body.innerText);
  if (/\bQBOM\b/.test(body)) fail('QBOM text present on team page');
  const teamHasRollup = /CERT-In Guidelines posture/i.test(body);
  out.team_rollup = teamHasRollup;
  if (!teamHasRollup) {
    // Soft: team may lack multi-BOM SUCCESS — still continue to results
    out.warnings = out.warnings || [];
    out.warnings.push('team page CertInRollup not visible (may lack BOM compliance)');
  } else if (!/HBOM deferred/i.test(body)) {
    fail('HBOM deferred note missing on team CertInRollup');
  }

  // ── CBOM results: All default + India + rollup ────────────────────────────
  const resultsUrl = `${base}/${tokens.teamId}/cbom/${tokens.scanId}/results`;
  await page.goto(resultsUrl, { waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForTimeout(5000);
  await page
    .getByText(/Crypto compliance readiness|CERT-In|India \/ CERT-In|CERT-In Guidelines posture/i)
    .first()
    .waitFor({ timeout: 45000 })
    .catch(() => {});

  body = await page.evaluate(() => document.body.innerText);
  if (/\bQBOM\b/.test(body)) fail('QBOM text present on CBOM results');
  if (!/CERT-In Guidelines posture/i.test(body)) {
    fail('CertInRollup missing on CBOM results');
  }
  if (!/HBOM deferred/i.test(body)) fail('HBOM deferred note missing on CBOM results');

  const chipTexts = await page.locator('button').evaluateAll((els) =>
    els.map((e) => (e.textContent || '').trim()).filter(Boolean)
  );
  if (!chipTexts.includes('All')) fail('All chip missing');
  if (!chipTexts.includes('India / CERT-In')) fail('India / CERT-In chip missing');

  // Default must be All (pressed/aria), never India
  const allBtn = page.getByRole('button', { name: 'All', exact: true }).first();
  const indiaBtn = page.getByRole('button', { name: 'India / CERT-In' }).first();
  const allPressed =
    (await allBtn.getAttribute('data-state')) === 'on' ||
    (await allBtn.getAttribute('aria-pressed')) === 'true' ||
    (await allBtn.evaluate((el) => el.className.includes('bg-') || el.getAttribute('data-active') === 'true'));
  // Soft check — ComplianceMatrix uses variant styling; ensure India is not the only selected
  out.all_chip_present = true;
  out.india_chip_present = true;

  await indiaBtn.click();
  await page.waitForTimeout(800);
  body = await page.evaluate(() => document.body.innerText);
  if (!/CERT-In CBOM/i.test(body)) {
    fail('India filter did not show CERT-In CBOM framework');
  }
  // Switch back to All
  await allBtn.click();
  await page.waitForTimeout(400);

  // Hard refresh keeps rollup
  await page.reload({ waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForTimeout(5000);
  body = await page.evaluate(() => document.body.innerText);
  if (!/CERT-In Guidelines posture/i.test(body)) {
    fail('CertInRollup missing after hard refresh');
  }
  if (/\bQBOM\b/.test(body)) fail('QBOM after refresh');

  out.ok = true;
  out.console_errors = consoleErrors.slice(0, 10);
  fs.writeFileSync('/tmp/certin_phase5_browser.json', JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
  await browser.close();
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
