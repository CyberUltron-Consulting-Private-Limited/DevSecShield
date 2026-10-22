/**
 * 90 - what must NOT happen: authentication, tenant isolation, unknown inputs, empty team.
 *
 *   npx playwright test specs/90-negative-isolation.spec.ts
 *
 *   no token / bad token / wrong scheme ........ 401 on the manifest and on all six PDFs
 *   other persona (member of team 2 only) ...... 403 on team 1; 200 on its OWN team 2 with its own canary
 *                                                certificate, and nothing of team 1 inside that PDF
 *   unknown slug / team id 0 / team id "abc" ... 404 {"detail":"Unknown deliverable"} / 422 / 422
 *   the six team-1 PDFs ......................... none contains a canary of the failed, queued, running,
 *                                                success-but-empty, other-team or sbom_sca scans, nor the
 *                                                credentials hidden in a repository URL
 *   empty team 3, through the UI ................ manifest says nothing is available for #7 / #15 / #16:
 *                                                those menu items are disabled with the reason as tooltip and
 *                                                clicking one makes no request; #1 / #3 / #10 download and
 *                                                carry the "NO COMPLETED CBOM SCANS" banner
 *   empty team 3, through the API ............... #7 / #15 / #16 still answer 200 (the frontend signs the user
 *                                                out on a 403, so data conditions are never 4xx) with the
 *                                                banner; the board report says NOT ASSESSED, never a grade
 */
import * as fs from 'node:fs';

import { expect, test } from '../fixtures';
import { apiGet, bodyJson, evidenceHeaders } from '../lib/api';
import { pdfFonts, pdfInfo, pdfPageTexts, pdfText, recordPdfEvidence, saveDownload, writeLog } from '../lib/evidence';
import { loadExpected } from '../lib/expected';
import { switchTokens } from '../lib/kit';
import { checkEmptyDocument } from '../lib/oracle';
import { evidencePath } from '../lib/paths';
import { closeMenu, downloadViaMenu, expectMenu, menuItem, openLanding, openMenu } from '../lib/ui';
import { showPdf, writeViewer } from '../lib/viewer';
import { makeWorld, SLUGS } from '../lib/world';

interface Row {
  actor: string;
  route: string;
  status: number;
  wanted: number;
  note?: string;
}

test('90 negative paths: 401, 403, 404, 422, tenant isolation, canaries, empty team', async ({
  page,
  kit,
  seed,
  request,
  personaTokens,
}) => {
  test.setTimeout(420_000);
  const exp = loadExpected();
  const demo = seed.teams.demo!.id;
  const other = seed.teams.other!.id;
  const empty = seed.teams.empty!.id;
  const rows: Row[] = [];
  const manifest = (team: number): string => `/${team}/cbom/deliverables`;
  const pdfRoute = (team: number, slug: string): string => `/${team}/cbom/deliverables/${slug}`;
  const routes = (team: number): string[] => [manifest(team), ...SLUGS.map((slug) => pdfRoute(team, slug))];

  async function expectStatus(actor: string, route: string, wanted: number, options: Parameters<typeof apiGet>[2], note?: string) {
    const res = await apiGet(request, route, { retryOn429: false, ...options });
    rows.push({ actor, route, status: res.status, wanted, note });
    return res;
  }

  await test.step('no token, a bad token and a wrong scheme are all 401', async () => {
    for (const route of routes(demo)) await expectStatus('anonymous (no Authorization header)', route, 401, { token: null });
    for (const route of [manifest(demo), pdfRoute(demo, SLUGS[2])]) {
      await expectStatus('Bearer not-a-jwt', route, 401, { authorization: 'Bearer not-a-jwt' });
      await expectStatus('Basic scheme', route, 401, { authorization: 'Basic YWRtaW46YWRtaW4=' });
      await expectStatus('Bearer with no token', route, 401, { authorization: 'Bearer' });
    }
  });

  const otherTokens = await personaTokens('other');
  await test.step('another tenant (team 2 member only) is refused on team 1: 403 everywhere', async () => {
    for (const route of routes(demo)) await expectStatus('other persona -> team 1', route, 403, { token: otherTokens.access });
  });

  await test.step('...but gets its OWN data on team 2, with nothing of team 1 in it', async () => {
    const res = await expectStatus('other persona -> own team 2 manifest', manifest(other), 200, { token: otherTokens.access });
    const body = bodyJson(res) as { basis: { eligible: number; sources: number } };
    expect(body.basis, 'team 2 has exactly one completed scan').toMatchObject({ eligible: 1, sources: 1 });
    const pdf = await expectStatus('other persona -> own team 2 certificate register', pdfRoute(other, 'certificate-estate-register'), 200, { token: otherTokens.access });
    const file = evidencePath('downloads', '90-other-team-certificate-estate-register.pdf');
    fs.writeFileSync(file, pdf.body);
    const text = pdfText(file);
    expect(text, 'its own canary certificate is in its register').toContain('other-team-canary.test');
    expect(text).toContain('Team Other Team (ID 2)');
    for (const token of ['E2E Demo Team', 'rsa1024_sha1.pem', 'payments-service', 'synthetic-crypto-app.test', 'identity-gateway']) {
      expect(text, `team 2 PDF holds nothing of team 1: ${token}`).not.toContain(token);
    }
  });

  const admin = await personaTokens('admin');
  await test.step('unknown slug is a 404; a bad team id is a 422', async () => {
    const res = await expectStatus('admin -> unknown slug', pdfRoute(demo, 'not-a-deliverable'), 404, { token: admin.access });
    expect(bodyJson(res)).toEqual({ detail: exp.http.unknown_slug_detail });
    await expectStatus('admin -> team id 0', manifest(0), 422, { token: admin.access });
    await expectStatus('admin -> team id "abc"', '/abc/cbom/deliverables', 422, { token: admin.access });
    await expectStatus('admin -> team id 2147483648', manifest(2147483648), 422, { token: admin.access });
  });

  await test.step('the six team-1 PDFs contain no canary and no credentials from a repository URL', async () => {
    for (const slug of SLUGS) {
      const res = await expectStatus('admin -> team 1', pdfRoute(demo, slug), 200, { token: admin.access });
      const file = evidencePath('downloads', `90-team1-${slug}.pdf`);
      fs.writeFileSync(file, res.body);
      const text = pdfText(file);
      for (const token of exp.forbidden.canaries as string[]) expect(text, `${slug} must not contain ${token}`).not.toContain(token);
      for (const token of ['Other Team', 'Empty Team', 'other-team-canary']) expect(text, `${slug} must not mention ${token}`).not.toContain(token);
    }
    await expectStatus('empty persona -> team 1', manifest(demo), 403, { token: (await personaTokens('empty')).access });
  });

  // ---------------------------------------------------------------- empty team, in the browser
  const emptyTokens = await personaTokens('empty');
  const emptyWorld = makeWorld({ reference: new Date() });
  await test.step('empty team in the UI: #7 / #15 / #16 disabled with the reason, #1 / #3 / #10 enabled', async () => {
    await page.goto('/login'); // any page of the app, to own an origin for localStorage
    await switchTokens(page, emptyTokens);
    const landing = await openLanding(page, empty);
    const basis = (landing.manifest as { basis: { eligible: number; sources: number } }).basis;
    expect(basis).toMatchObject(exp.empty_team.manifest_basis);
    await kit.shot(page, 'empty-team-landing');
    await openMenu(page);
    await expectMenu(page, exp, exp.empty_team.ui_disabled as string[]);
    await kit.shot(page, 'empty-team-menu-three-items-disabled');
    // A disabled item is inert: forcing a click makes no request.
    let pdfRequests = 0;
    page.on('request', (r) => {
      if (r.url().includes('/cbom/deliverables/')) pdfRequests += 1;
    });
    await menuItem(page, 'certificate-estate-register').click({ force: true });
    await page.waitForTimeout(1200);
    expect(pdfRequests, 'clicking a disabled item must not request the PDF').toBe(0);
    await closeMenu(page).catch(() => undefined);
  });

  for (const slug of exp.empty_team.ui_enabled as string[]) {
    await test.step(`empty team in the UI: ${exp.documents[slug].menu_label} downloads a banner-only PDF`, async () => {
      await openMenu(page);
      const { download, api } = await downloadViaMenu(page, empty, slug);
      expect(api.status).toBe(200);
      expect(api.headers['x-cbom-scans-included'], 'no scan folded').toBe('0');
      expect(api.headers['x-cbom-fidelity']).toBe('none');
      const saved = await saveDownload(download, `90-empty-team-${slug}.pdf`);
      const doc = { slug, raw: pdfText(saved.path), pages: pdfPageTexts(saved.path), info: pdfInfo(saved.path), fonts: pdfFonts(saved.path).fonts };
      const verdict = checkEmptyDocument(doc, emptyWorld);
      rows.push({ actor: `empty persona via UI -> ${slug}`, route: pdfRoute(empty, slug), status: api.status, wanted: 200, note: `${verdict.passed.length} checks, ${verdict.failures.length} failed` });
      expect(verdict.failures, `empty-team ${slug}: ${verdict.failures.join(' | ')}`).toEqual([]);
      await page.waitForTimeout(1500);
    });
  }

  await test.step('empty team over the API: #7 / #15 / #16 are 200 with the banner; the board report says NOT ASSESSED', async () => {
    for (const slug of exp.empty_team.ui_disabled as string[]) {
      const res = await expectStatus('empty persona via API', pdfRoute(empty, slug), 200, { token: emptyTokens.access });
      const file = evidencePath('downloads', `90-empty-team-${slug}.pdf`);
      fs.writeFileSync(file, res.body);
      const doc = { slug, raw: pdfText(file), pages: pdfPageTexts(file), info: pdfInfo(file), fonts: pdfFonts(file).fonts };
      const verdict = checkEmptyDocument(doc, emptyWorld);
      expect(verdict.failures, `empty-team ${slug}: ${verdict.failures.join(' | ')}`).toEqual([]);
      writeLog(`90-empty-team-${slug}-headers.json`, evidenceHeaders(res.headers));
    }
  });

  await test.step('show the empty-team board report in the recorded page', async () => {
    const file = evidencePath('downloads', '90-empty-team-board-executive-report.pdf');
    const evidence = recordPdfEvidence(file, '90', 'empty-team-board-executive-report');
    const viewer = writeViewer({
      number: '90',
      title: 'Board report of the EMPTY team - banner and NOT ASSESSED',
      subtitle: `${pdfInfo(file).pages} pages · rendered by poppler from the PDF the API returned for team ${empty}`,
      pages: evidence.png,
    });
    await showPdf(page, viewer, { stops: [1, 2], onStop: async (n) => void (await kit.shot(page, `empty-board-pdf-p${n}`)), goBack: false });
  });

  // ---------------------------------------------------------------- verdict
  kit.log('negative-isolation.json', {
    summary: { requests: rows.length, mismatches: rows.filter((r) => r.status !== r.wanted).length },
    rows,
  });
  writeLog('90-negative-isolation.txt', rows.map((r) => `${r.status === r.wanted ? 'ok  ' : 'FAIL'} ${String(r.status).padEnd(4)} (want ${r.wanted}) ${r.actor.padEnd(52)} ${r.route}${r.note ? `  [${r.note}]` : ''}`).join('\n') + '\n');
  expect(rows.filter((r) => r.status !== r.wanted), 'every request answered with the expected status').toEqual([]);
});
