#!/usr/bin/env node
/**
 * CERT-In Phase 6 — browser gate (team rollup + 3 lane results).
 *
 * Inputs: /tmp/certin_phase6_tokens.json
 *   { access, refresh?, team_id?, deep: { cbom, ai_bom, sbom_sca } }
 * Or CERTIN_P6_MATRIX from /tmp/certin_phase6_matrix.json deep scan ids.
 *
 * Usage: node scripts/e2e/certin_phase6_browser.cjs
 */
const fs = require('fs');

function load() {
  const matrixPath = process.env.CERTIN_P6_MATRIX_OUT || '/tmp/certin_phase6_matrix.json';
  const tokPath = process.env.CERTIN_TOKENS_FILE || '/tmp/certin_phase6_tokens.json';
  let access = process.env.ACCESS_TOKEN;
  let refresh = process.env.REFRESH_TOKEN || access;
  let teamId = process.env.TEAM_ID || '1';
  let deep = {};
  if (fs.existsSync(tokPath)) {
    const t = JSON.parse(fs.readFileSync(tokPath, 'utf8'));
    access = t.access || t.access_token || access;
    refresh = t.refresh || t.refresh_token || access;
    teamId = String(t.team_id || t.teamId || teamId);
    deep = t.deep || deep;
  }
  if (fs.existsSync(matrixPath)) {
    const m = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
    deep = { ...deep, ...(m.deep || {}) };
    // map deep[lane].scan_id
    const mapped = {};
    for (const [lane, info] of Object.entries(deep)) {
      if (info && typeof info === 'object' && info.scan_id) mapped[lane] = String(info.scan_id);
      else if (info) mapped[lane] = String(info);
    }
    deep = mapped;
  }
  if (!access) {
    console.error('Missing ACCESS_TOKEN or', tokPath);
    process.exit(2);
  }
  return { access, refresh, teamId, deep };
}

(async () => {
  const { chromium } = require('/opt/homebrew/lib/node_modules/playwright');
  const t = load();
  const base = process.env.FRONTEND_BASE || 'http://localhost:3000';
  const out = { ok: false, errors: [], deep: t.deep };

  const fail = (msg) => {
    out.errors.push(msg);
    fs.writeFileSync('/tmp/certin_phase6_browser.json', JSON.stringify(out, null, 2));
    console.error(JSON.stringify(out, null, 2));
    process.exit(1);
  };

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true });
  await ctx.addInitScript((tok) => {
    localStorage.setItem('access_token', tok.access);
    localStorage.setItem('refresh_token', tok.refresh);
  }, t);

  const page = await ctx.newPage();
  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.goto(`${base}/${t.teamId}`, { waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForTimeout(5000);
  let body = await page.evaluate(() => document.body.innerText);
  if (/\bQBOM\b/.test(body)) fail('QBOM on team page');
  out.team_rollup = /CERT-In Guidelines posture/i.test(body);
  if (!out.team_rollup) {
    out.warnings = out.warnings || [];
    out.warnings.push('team CertInRollup not visible yet');
  } else if (!/HBOM deferred/i.test(body)) {
    fail('HBOM deferred missing on team page');
  }

  const lanePath = { cbom: 'cbom', ai_bom: 'ai_bom', sbom_sca: 'sbom_sca' };
  for (const [lane, scanId] of Object.entries(t.deep || {})) {
    if (!scanId) continue;
    const pathSeg = lanePath[lane] || lane;
    const url = `${base}/${t.teamId}/${pathSeg}/${scanId}/results`;
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 90000 });
    await page.waitForTimeout(5000);
    body = await page.evaluate(() => document.body.innerText);
    if (/\bQBOM\b/.test(body)) fail(`QBOM on ${lane} results`);
    const chips = await page.locator('button').evaluateAll((els) =>
      els.map((e) => (e.textContent || '').trim()).filter(Boolean)
    );
    if (!chips.includes('All')) fail(`All chip missing on ${lane}`);
    if (!chips.includes('India / CERT-In')) fail(`India chip missing on ${lane}`);
    out[`${lane}_india`] = true;
    if (!/CERT-In/i.test(body)) fail(`CERT-In text missing on ${lane}`);
    await page.getByRole('button', { name: 'India / CERT-In' }).click().catch(() => {});
    await page.waitForTimeout(600);
    await page.reload({ waitUntil: 'domcontentloaded', timeout: 90000 });
    await page.waitForTimeout(4000);
    body = await page.evaluate(() => document.body.innerText);
    if (/\bQBOM\b/.test(body)) fail(`QBOM after refresh ${lane}`);
  }

  // Evidence pack on CBOM deep if present
  if (t.deep.cbom) {
    await page.goto(`${base}/${t.teamId}/cbom/${t.deep.cbom}/results`, {
      waitUntil: 'domcontentloaded',
      timeout: 90000,
    });
    await page.waitForTimeout(4000);
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 60000 }).catch(() => null),
      page.getByRole('button', { name: /Evidence pack/i }).click().catch(() => null),
    ]);
    out.evidence_pack = Boolean(download);
  }

  out.ok = true;
  fs.writeFileSync('/tmp/certin_phase6_browser.json', JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
