#!/usr/bin/env node
/**
 * SEBI CSCRF — browser gate (India chip + SEBI rows, no QBOM/certification).
 */
const fs = require('fs');
const path = require('path');

function loadTokens() {
  const file = process.env.SEBI_TOKENS_FILE || '/tmp/sebi_tokens.json';
  const t = JSON.parse(fs.readFileSync(file, 'utf8'));
  return {
    access: t.access || t.access_token,
    refresh: t.refresh || t.refresh_token || t.access,
    teamId: String(t.team_id || 1),
    cbom: String(t.cbom || ''),
    aibom: String(t.ai_bom || ''),
    sbom: String(t.sbom_sca || ''),
  };
}

async function main() {
  const pw = require('/opt/homebrew/lib/node_modules/playwright');
  const tokens = loadTokens();
  const base = process.env.FRONTEND_BASE || 'http://127.0.0.1:3000';
  const browser = await pw.chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctx.addInitScript(({ access, refresh }) => {
    localStorage.setItem('access_token', access);
    localStorage.setItem('refresh_token', refresh);
  }, { access: tokens.access, refresh: tokens.refresh });

  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded' });

  const routes = [
    { name: 'cbom', url: `/${tokens.teamId}/cbom/${tokens.cbom}/results`, chipKeys: ['sebi_cscrf_cbom'] },
    { name: 'aibom', url: `/${tokens.teamId}/ai_bom/${tokens.aibom}/results`, chipKeys: ['sebi_cscrf_aibom'] },
    { name: 'sbom', url: `/${tokens.teamId}/sbom_sca/${tokens.sbom}/results`, chipKeys: ['sebi_cscrf_sbom'] },
  ];

  const report = { qbom: false, certificationClaim: false, lanes: {} };

  for (const r of routes) {
    const code = await page.goto(`${base}${r.url}`, { waitUntil: 'networkidle', timeout: 120000 }).then(
      (resp) => (resp ? resp.status() : 0),
      () => 0,
    );
    await page.waitForTimeout(2500);
    const body = await page.locator('body').innerText();
    if (/\bQBOM\b/.test(body)) report.qbom = true;
    if (/SEBI certification|certified by SEBI/i.test(body)) report.certificationClaim = true;

    const indiaChip = page.getByRole('button', { name: /India\s*\/\s*CERT-In\s*\/\s*SEBI/i });
    const indiaVisible = await indiaChip.count().then((n) => n > 0);
    let sebiRow = false;
    if (indiaVisible) {
      await indiaChip.first().click();
      await page.waitForTimeout(800);
      const text = await page.locator('body').innerText();
      sebiRow = /SEBI CSCRF/i.test(text);
    } else {
      // Compliance may still show SEBI under All
      sebiRow = /SEBI CSCRF/i.test(body);
    }
    report.lanes[r.name] = {
      http: code,
      indiaChip: indiaVisible,
      sebiRow,
      bodyHasSebi: /SEBI CSCRF/i.test(body),
    };
  }

  report.consoleErrors = errors.slice(0, 10);
  report.ok =
    !report.qbom &&
    !report.certificationClaim &&
    Object.values(report.lanes).every((l) => l.http === 200 && (l.sebiRow || l.bodyHasSebi));

  fs.writeFileSync('/tmp/sebi_browser_report.json', JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
  await browser.close();
  if (!report.ok) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
