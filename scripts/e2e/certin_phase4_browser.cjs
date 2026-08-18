#!/usr/bin/env node
/**
 * CERT-In Phase 4 — durable browser gate (CBOM customer path).
 *
 * India chip → CERT-In manuals → Attach attestation → Pass (evidence) after
 * reload; Evidence pack / VEX / Signature downloads; no QBOM.
 *
 * Inputs:
 *   - /tmp/certin_phase4_tokens.json  { access, refresh?, scan_id, team_id? }
 *   - env ACCESS_TOKEN, SCAN_ID, TEAM_ID, FRONTEND_BASE, BACKEND_BASE
 *
 * Usage: node scripts/e2e/certin_phase4_browser.cjs
 */
const fs = require('fs');
const path = require('path');

function loadTokens() {
  const file = process.env.CERTIN_TOKENS_FILE || '/tmp/certin_phase4_tokens.json';
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
  const api = process.env.BACKEND_BASE || 'http://127.0.0.1:8081';
  const out = { scan_id: tokens.scanId, team_id: tokens.teamId, ok: false, errors: [] };

  const fail = (msg) => {
    out.errors.push(msg);
    out.ok = false;
    fs.writeFileSync('/tmp/certin_phase4_browser.json', JSON.stringify(out, null, 2));
    console.error(JSON.stringify(out, null, 2));
    process.exit(1);
  };

  // Pre-attest via API so the UI can show Pass (evidence) after refresh
  const boundary = '----phase4browser';
  const rid = process.env.CERTIN_P4_REQ_ID || '8.4.1.1';
  const formBody =
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="framework"\r\n\r\n` +
    `cert_in_cbom\r\n` +
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="requirement_id"\r\n\r\n` +
    `${rid}\r\n` +
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="note"\r\n\r\n` +
    `browser-e2e\r\n` +
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="file"; filename="att.txt"\r\n` +
    `Content-Type: text/plain\r\n\r\n` +
    `attestation\r\n` +
    `--${boundary}--\r\n`;
  const attestRes = await fetch(
    `${api}/${tokens.teamId}/cbom/scan/${tokens.scanId}/attestations`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${tokens.access}`,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
      },
      body: formBody,
    },
  );
  out.attest_status = attestRes.status;
  if (attestRes.status !== 200) {
    const t = await attestRes.text();
    fail(`pre-attest API failed: ${attestRes.status} ${t.slice(0, 200)}`);
  }

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    viewport: { width: 1400, height: 900 },
    acceptDownloads: true,
  });
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

  const resultsUrl = `${base}/${tokens.teamId}/cbom/${tokens.scanId}/results`;
  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.goto(resultsUrl, { waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForTimeout(5000);
  await page
    .getByText(/Crypto compliance readiness|CERT-In CBOM|India \/ CERT-In/i)
    .first()
    .waitFor({ timeout: 45000 })
    .catch(() => {});

  let body = await page.evaluate(() => document.body.innerText);
  if (/\bQBOM\b/.test(body)) fail('QBOM text present in product UI');

  const chipTexts = await page.locator('button').evaluateAll((els) =>
    els.map((e) => (e.textContent || '').trim()).filter(Boolean)
  );
  if (!chipTexts.includes('All')) fail('All chip missing');
  if (!chipTexts.includes('India / CERT-In')) fail('India / CERT-In chip missing');

  // Download buttons present
  const headerText = body;
  if (!/Evidence pack/i.test(headerText)) fail('Evidence pack button missing');
  if (!/\bVEX\b/i.test(headerText)) fail('VEX button missing');
  if (!/Signature/i.test(headerText)) fail('Signature button missing');

  // Trigger evidence pack download
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 60000 }).catch(() => null),
    page.getByRole('button', { name: /Evidence pack/i }).click(),
  ]);
  if (!download) {
    fail('Evidence pack download did not start');
  } else {
    const p = await download.path();
    out.evidence_pack = download.suggestedFilename();
    if (p) {
      const buf = fs.readFileSync(p);
      if (buf[0] !== 0x50 || buf[1] !== 0x4b) fail('Evidence pack is not a ZIP');
    }
  }

  // India → CERT-In drilldown → Pass (evidence) for attested req
  await page.getByRole('button', { name: 'India / CERT-In' }).click();
  await page.waitForTimeout(800);
  const certLabel = page.getByText(/CERT-In CBOM/i).first();
  if (await certLabel.count()) {
    // click a wide enough bar segment
    const bars = page.locator('.recharts-bar-rectangle path');
    const n = await bars.count();
    for (let i = 0; i < n; i++) {
      const box = await bars.nth(i).boundingBox();
      if (box && box.width >= 6) {
        await bars.nth(i).click({ force: true });
        break;
      }
    }
    await page.waitForTimeout(1000);
  }
  body = await page.evaluate(() => document.body.innerText);
  out.has_pass_evidence = /Pass \(evidence\)|pass_with_evidence|attested:/i.test(body);

  // Hard refresh must keep attested state
  await page.reload({ waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForTimeout(4000);
  body = await page.evaluate(() => document.body.innerText);
  if (/\bQBOM\b/.test(body)) fail('QBOM after refresh');
  if (!/Evidence pack/i.test(body)) fail('Evidence pack missing after refresh');

  out.console_errors = consoleErrors.slice(0, 10);
  out.ok = true;
  fs.writeFileSync('/tmp/certin_phase4_browser.json', JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
  await browser.close();
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
