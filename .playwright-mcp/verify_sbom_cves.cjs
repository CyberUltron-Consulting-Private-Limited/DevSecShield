
const { chromium } = require('/opt/homebrew/lib/node_modules/playwright/index.js');
const fs = require('fs');
const body = fs.readFileSync('/home/contact_cyberultron_com/DevSecShield/.playwright-mcp/fixed_chunk.js', 'utf8');
(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  // copy tokens from a login bootstrap if needed - use env
  const access = process.env.ACCESS_TOKEN;
  const refresh = process.env.REFRESH_TOKEN;
  await ctx.route('**/_next/static/chunks/14ab96qg3p25c.js*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/javascript; charset=utf-8',
      body,
      headers: { 'cache-control': 'no-store' },
    });
  });
  await ctx.addInitScript((tokens) => {
    if (tokens.access) localStorage.setItem('access_token', tokens.access);
    if (tokens.refresh) localStorage.setItem('refresh_token', tokens.refresh);
  }, { access, refresh });
  const page = await ctx.newPage();
  await page.goto('https://devsecshield.zeroshield.ai/login', { waitUntil: 'domcontentloaded' });
  await page.goto('https://devsecshield.zeroshield.ai/1/sbom_sca/367/results?v=cjs1', { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForTimeout(8000);
  const info = await page.evaluate(() => {
    const card = document.querySelector('[data-testid="sbom-bill-of-materials"]');
    if (!card) return { err: 'no card', text: document.body.innerText.slice(0, 500) };
    const rows = [...card.querySelectorAll('tbody tr')].slice(0, 10).map(tr => {
      const tds = [...tr.querySelectorAll('td')].map(td => td.textContent.trim().slice(0, 90));
      return { name: tds[0], ver: tds[2], cves: tds[9] };
    });
    const all = [...card.querySelectorAll('tbody tr')].map(tr => tr.querySelectorAll('td')[9]?.textContent?.trim());
    const counts = { NA: 0, None: 0, CVE: 0, other: 0 };
    for (const c of all) {
      if (c === 'N/A') counts.NA++;
      else if (c === 'None') counts.None++;
      else if (c && /CVE|GHSA|PYSEC/.test(c)) counts.CVE++;
      else counts.other++;
    }
    return { rows, counts, total: all.length };
  });
  console.log(JSON.stringify(info, null, 2));
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
