/**
 * 17 - the new documents look like the existing CBOM report ("styling as existing", user decision L-1).
 *
 *   npx playwright test specs/17-style-parity.spec.ts
 *
 * Downloads the EXISTING single-scan "PDF Report" of scan #2 through the UI (results page, "PDF Report"
 * button) and the six new team-wide PDFs, then
 *   - builds a contact sheet of their first pages (existing report first) and shows it in the recorded page;
 *   - requires the font set of every new PDF to be a subset of the existing report's (`pdffonts`): the new
 *     documents introduce no font the platform does not already ship;
 *   - requires the shared brand header on page 1 of both families (ZERO SHIELD, zeroshield.ai, CONFIDENTIAL).
 */
import * as fs from 'node:fs';
import { pathToFileURL } from 'node:url';

import { expect, test } from '../fixtures';
import { apiGet } from '../lib/api';
import { contactSheet, pdfFonts, pdfInfo, pdfPageTexts, pdfText, pdfToPng, saveDownload, writeLog } from '../lib/evidence';
import { loadExpected } from '../lib/expected';
import { evidencePath } from '../lib/paths';
import { SLUGS } from '../lib/world';

test('17 style parity: new deliverables vs the existing single-scan CBOM report', async ({
  authedPage: page,
  kit,
  seed,
  request,
  personaTokens,
}) => {
  test.setTimeout(240_000);
  const exp = loadExpected();
  const teamId = seed.teams.demo!.id;
  const scanId = exp.style_parity.existing_scan as number;

  // --- the existing report, through the UI ---
  const existingPath = await test.step('download the existing report: results page -> "PDF Report"', async () => {
    await page.goto(`/${teamId}/cbom/${scanId}/results`);
    const button = page.getByRole('button', { name: 'PDF Report' });
    await expect(button).toBeVisible({ timeout: 60_000 });
    await kit.shot(page, 'existing-results-page');
    const [download] = await Promise.all([page.waitForEvent('download', { timeout: 90_000 }), button.click()]);
    await expect(page.getByText('Report downloaded').first()).toBeVisible();
    expect(download.suggestedFilename()).toBe(`cbom-report-${scanId}.pdf`);
    const saved = await saveDownload(download, `17-existing-cbom-report-scan${scanId}.pdf`);
    await kit.shot(page, 'existing-report-toast');
    return saved.path;
  });

  // --- the six new documents (API; the UI path is proven by specs 01-16) ---
  const tokens = await personaTokens('admin');
  const newPaths: Record<string, string> = {};
  await test.step('download the six new deliverables', async () => {
    for (const slug of SLUGS) {
      const res = await apiGet(request, `/${teamId}/cbom/deliverables/${slug}`, { token: tokens.access });
      expect(res.status, slug).toBe(200);
      const file = evidencePath('downloads', `17-new-${slug}.pdf`);
      fs.writeFileSync(file, res.body);
      newPaths[slug] = file;
      await page.waitForTimeout(1500); // the route allows 30 requests per minute per token
    }
  });

  // --- fonts: new subset of existing ---
  const existingFonts = new Set(pdfFonts(existingPath).fonts.map((f) => f.name));
  const fontTable: Record<string, string[]> = { existing: [...existingFonts].sort() };
  for (const slug of SLUGS) {
    const names = [...new Set(pdfFonts(newPaths[slug]).fonts.map((f) => f.name))].sort();
    fontTable[slug] = names;
    expect(names.length, `${slug} uses fonts`).toBeGreaterThan(0);
    expect(names.filter((name) => !existingFonts.has(name)), `${slug}: fonts that the existing report does not use`).toEqual([]);
  }
  writeLog('17-pdffonts-comparison.txt', Object.entries(fontTable).map(([k, v]) => `${k.padEnd(34)} ${v.join(', ')}`).join('\n') + '\n');
  kit.log('style-parity.json', { fonts: fontTable, existing_info: pdfInfo(existingPath).title });

  // --- brand header on page 1 of both families ---
  const brand = ['ZERO SHIELD', 'zeroshield.ai', 'CONFIDENTIAL'];
  const existingFirst = pdfPageTexts(existingPath)[0];
  for (const token of brand) expect(existingFirst, `existing report page 1 has "${token}"`).toContain(token);
  for (const slug of SLUGS) {
    const first = pdfPageTexts(newPaths[slug])[0];
    for (const token of brand) expect(first, `${slug} page 1 has the same brand "${token}"`).toContain(token);
    expect(pdfText(newPaths[slug]), `${slug} is not the AIBOM / SAST header`).not.toContain('SAST Report');
  }

  // --- contact sheet of the first pages, shown in the recorded page ---
  await test.step('contact sheet: existing report next to the six new documents (page 1 each)', async () => {
    const cells = [{ src: pdfToPng(existingPath, '17-existing', 90, true)[0], caption: `EXISTING single-scan CBOM report (scan #${scanId})` }];
    for (const slug of SLUGS) {
      cells.push({ src: pdfToPng(newPaths[slug], `17-new-${slug}`, 90, true)[0], caption: `NEW #${exp.documents[slug].number} ${exp.documents[slug].title}` });
    }
    const sheet = contactSheet(cells, 'style-parity-existing-vs-new.html', {
      title: 'Style parity: existing CBOM report vs the six team-wide deliverables (page 1)',
      subtitle: `fonts of every new PDF ⊆ {${[...existingFonts].sort().join(', ')}}`,
      columns: 4,
    });
    await page.goto(pathToFileURL(sheet).href);
    await page.waitForFunction(() => [...document.images].every((img) => img.complete && img.naturalWidth > 0));
    await page.waitForTimeout(1500);
    await kit.shot(page, 'contact-sheet');
    await page.screenshot({ path: evidencePath('pdf-pages', 'style-parity-existing-vs-new.png'), fullPage: true });
    await page.evaluate(() => window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' }));
    await page.waitForTimeout(1500);
    await kit.shot(page, 'contact-sheet-scrolled');
  });
});
