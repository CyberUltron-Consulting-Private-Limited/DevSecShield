/**
 * The end-to-end flow every per-deliverable spec runs, so six specs prove the same chain six times:
 *
 *   login (tokens) -> /1/cbom -> Deliverables menu -> click item -> API response + download + toast
 *   -> save the PDF -> poppler (info / text / fonts / page PNGs) -> show the pages IN THE RECORDED PAGE
 *   -> judge the PDF text against fixtures/expected.json (lib/oracle.ts).
 *
 * The oracle verdict is returned, not asserted, so the caller can add its own checks and assert once at
 * the end; the video and screenshots are complete either way.
 */
import { expect, test, type Page } from '@playwright/test';

import { assertPdf, recordPdfEvidence, saveDownload, writeLog, type SavedDownload } from './evidence';
import { loadExpected, type Findings } from './expected';
import type { SpecKit } from './kit';
import { checkDocument } from './oracle';
import type { DocInput } from './oracle-core';
import { WORK_DIR } from './paths';
import { loadSeed } from './seed';
import { clientDateStamp, closeMenu, downloadViaMenu, expectMenu, openLanding, openMenu } from './ui';
import { writeViewer, showPdf } from './viewer';
import { makeWorld } from './world';

export interface FlowOptions {
  page: Page;
  kit: SpecKit;
  slug: string;
  teamId?: number;
  /** Strings whose first page gets a screenshot in the viewer (besides page 1). */
  highlights?: Array<{ label: string; needle: string }>;
}

export interface FlowResult {
  saved: SavedDownload;
  doc: DocInput;
  findings: Findings;
  pngs: string[];
  api: { status: number; headers: Record<string, string>; ms: number };
}

export async function runDeliverableFlow(options: FlowOptions): Promise<FlowResult> {
  const { page, kit, slug } = options;
  const exp = loadExpected();
  const seed = loadSeed();
  const spec = exp.documents[slug];
  const teamId = options.teamId ?? seed.teams.demo!.id;
  const number = String(spec.number).padStart(2, '0');
  expect(kit.number, `spec file number matches deliverable #${spec.number}`).toBe(number);

  await test.step('open the team CBOM page (authenticated by API-login tokens)', async () => {
    const landing = await openLanding(page, teamId);
    expect(landing.manifestStatus, 'GET /{team}/cbom/deliverables').toBe(200);
    await expect(page.getByText(seed.teams.demo!.name).first()).toBeVisible();
    await kit.shot(page, 'landing-dashboard');
    await page.getByRole('tab', { name: 'Table' }).click();
    await expect(page.getByText('payments-service #2').first()).toBeVisible();
    await kit.shot(page, 'landing-scan-table');
  });

  await test.step('open the Deliverables menu: six items, in order, all enabled', async () => {
    await openMenu(page);
    await expectMenu(page, exp);
    await kit.shot(page, 'deliverables-menu-open');
  });

  const { download, api } = await test.step(`click "${spec.menu_label}": API 200 + download + toast`, async () => {
    const result = await downloadViaMenu(page, teamId, slug);
    expect(result.api.status, 'PDF route status').toBe(200);
    const h = result.api.headers;
    expect(h['content-type']).toContain(exp.http.headers_pdf.content_type);
    expect(h['cache-control']).toBe(exp.http.headers_pdf.cache_control);
    expect(h['x-content-type-options']).toBe(exp.http.headers_pdf.nosniff);
    expect(h['x-cbom-scans-included'], 'X-Cbom-Scans-Included').toBe(exp.http.headers_pdf.x_cbom_scans_included);
    expect(h['x-cbom-sources'], 'X-Cbom-Sources').toBe(exp.http.headers_pdf.x_cbom_sources);
    expect(h['x-cbom-fidelity'], 'X-Cbom-Fidelity').toBe(exp.http.headers_pdf.x_cbom_fidelity);
    expect(h['x-cbom-fingerprint'], 'X-Cbom-Fingerprint').toMatch(/^[0-9a-f]{12}$/);
    const name = result.download.suggestedFilename();
    const parts = new RegExp(exp.http.filename_re).exec(name);
    expect(parts, `file name ${name} follows cbom-<slug>-team<id>-<YYYYMMDD>.pdf`).not.toBeNull();
    expect(parts![1]).toBe(slug);
    expect(parts![2]).toBe(String(teamId));
    expect([clientDateStamp(), clientDateStamp(new Date(Date.now() - 86_400_000))], 'file name date is today (UTC)').toContain(parts![3]);
    await expect(page.getByText(`Downloaded ${spec.title}`).first()).toBeVisible();
    await kit.shot(page, 'download-toast');
    return result;
  });

  const saved = await saveDownload(download, `${number}-${slug}.pdf`);
  kit.log('api.json', { slug, ...api, saved: { file: `${number}-${slug}.pdf`, bytes: saved.bytes, sha256: saved.sha256, suggested: saved.suggestedFilename } });

  const evidence = recordPdfEvidence(saved.path, number, slug);
  const doc: DocInput = { slug, raw: evidence.raw, pages: evidence.pages, info: evidence.info, fonts: evidence.fonts };
  // Evidence is recorded first so a PDF that fails these checks still leaves its logs and page images behind.
  assertPdf(saved.path, {
    minPages: spec.min_pages,
    maxPages: spec.max_pages,
    titleIncludes: spec.title,
    orientation: spec.orientation,
  });
  expect(evidence.png.length, 'every page rendered to a PNG').toBe(evidence.info.pages);

  await test.step('show the downloaded PDF in the recorded page, scrolling page by page', async () => {
    await closeMenu(page).catch(() => undefined);
    const viewer = writeViewer({
      number,
      title: `${spec.title} - ${exp.common.team.name}`,
      subtitle: `${number}-${slug}.pdf · ${evidence.info.pages} pages · sha256 ${saved.sha256.slice(0, 16)}… · rendered by poppler (pdftoppm) from the downloaded file`,
      pages: evidence.png,
    });
    const wanted = new Map<number, string>([[1, 'p01-cover']]);
    for (const { label, needle } of options.highlights ?? []) {
      const index = doc.pages.findIndex((text) => text.replace(/\s+/g, '').includes(needle.replace(/\s+/g, '')));
      if (index >= 0 && !wanted.has(index + 1)) wanted.set(index + 1, `p${String(index + 1).padStart(2, '0')}-${label}`);
    }
    const last = evidence.info.pages;
    if (!wanted.has(last)) wanted.set(last, `p${String(last).padStart(2, '0')}-last`);
    await showPdf(page, viewer, {
      stops: [...wanted.keys()].sort((a, b) => a - b),
      onStop: async (n) => {
        await kit.shot(page, `pdf-${wanted.get(n)}`);
      },
    });
  });

  const findings = await test.step('judge the PDF text against fixtures/expected.json', async () => {
    const result = checkDocument(doc, makeWorld({ seed, workDir: WORK_DIR }));
    writeLog(`${number}-oracle.json`, {
      slug,
      passed: result.passed.length,
      failed: result.failures.length,
      failures: result.failures,
      checks: result.passed,
    });
    test.info().annotations.push({ type: 'oracle', description: `${result.passed.length} checks passed, ${result.failures.length} failed` });
    return result;
  });

  return { saved, doc, findings, pngs: evidence.png, api: { status: api.status, headers: api.headers, ms: api.ms } };
}

/** `expect(...)` with the whole failure list in the message. */
export function expectNoFindings(findings: Findings, label: string): void {
  expect(findings.failures, `${label}: ${findings.failures.length} oracle failure(s)\n  - ${findings.failures.join('\n  - ')}`).toEqual([]);
  expect(findings.passed.length, `${label}: the oracle really ran`).toBeGreaterThan(20);
}
