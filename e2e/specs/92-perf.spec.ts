/**
 * 92 - response times against the plan's budgets (section 4.7).
 *
 *   npx playwright test specs/92-perf.spec.ts
 *
 *   demo team (8 scans, 7 sources) ........ every PDF, three times each, <= 3 s
 *   perf team (200 scans, 40 sources) ..... every PDF <= 10 s            (only when the stack was seeded with `seed.sh --perf`)
 *                                           the certificate register <= 15 s when the team holds more than 2 000
 *                                           unique certificates (the row cap)
 *
 * The time is what the client measures for the whole GET (loopback network + auth + SQL + aggregation + PDF
 * build): the budget is a statement about the route, not about reportlab alone. The numbers are written to
 * logs/92-perf.json and 92-perf.txt, and a one-page report is shown in the recorded browser.
 */
import * as fs from 'node:fs';
import { pathToFileURL } from 'node:url';

import { expect, test } from '../fixtures';
import { apiGet } from '../lib/api';
import { escapeHtml, pdfInfo, pdfText, writeLog } from '../lib/evidence';
import { loadExpected } from '../lib/expected';
import { evidencePath } from '../lib/paths';
import { SLUGS } from '../lib/world';

interface Sample {
  team: string;
  slug: string;
  runs: number[];
  max: number;
  median: number;
  budget: number;
  bytes: number;
  pages: number;
  ok: boolean;
}

const median = (values: number[]): number => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];

test('92 performance: demo team <= 3 s, perf team <= 10 s per PDF', async ({ page, kit, seed, request, personaTokens }) => {
  test.setTimeout(600_000);
  const exp = loadExpected();
  const budgets = exp.perf.budget_ms as { demo: number; perf_team: number; row_cap: number };
  const tokens = await personaTokens('admin');
  const samples: Sample[] = [];
  let perfRegisterKpi: number | null | undefined; // undefined: not measured (perf team not seeded); null: KPI tile not found

  async function measure(teamLabel: string, teamId: number, slug: string, repeat: number, budget: number): Promise<void> {
    const runs: number[] = [];
    let last: Buffer = Buffer.alloc(0);
    for (let i = 0; i < repeat; i++) {
      const res = await apiGet(request, `/${teamId}/cbom/deliverables/${slug}`, { token: tokens.access });
      expect(res.status, `${teamLabel} ${slug}`).toBe(200);
      expect(res.body.subarray(0, 5).toString('latin1'), 'a PDF').toBe('%PDF-');
      runs.push(res.ms);
      last = res.body;
      await page.waitForTimeout(1500); // 30 requests per minute per token
    }
    const file = evidencePath('downloads', `92-${teamLabel}-${slug}.pdf`);
    fs.writeFileSync(file, last);
    const info = pdfInfo(file);
    samples.push({ team: teamLabel, slug, runs, max: Math.max(...runs), median: median(runs), budget, bytes: last.length, pages: info.pages, ok: Math.max(...runs) <= budget });
    if (teamLabel === 'perf' && slug === 'certificate-estate-register') {
      const kpi = /Certificates\s+(\d+)\s+Unique, all sources/.exec(pdfText(file).replace(/\s+/g, ' '));
      perfRegisterKpi = kpi ? Number(kpi[1]) : null;
      kit.log('perf-register-kpi.json', { certificates_kpi: perfRegisterKpi, expected_current_unique: seed.perf?.current_unique_certs ?? null });
    }
  }

  await test.step(`demo team: every deliverable x${exp.perf.repeat} within ${budgets.demo} ms`, async () => {
    for (const slug of SLUGS) await measure('demo', seed.teams.demo!.id, slug, exp.perf.repeat as number, budgets.demo);
  });

  if (seed.perf) {
    const perf = seed.perf;
    await test.step(`perf team (${perf.scans} scans, ${perf.sources} sources): every deliverable within ${budgets.perf_team} ms`, async () => {
      for (const slug of SLUGS) {
        const capped = slug === 'certificate-estate-register' && perf.unique_certs_total > (exp.perf.unique_certs_over_row_cap as number);
        await measure('perf', perf.team_id, slug, 1, capped ? budgets.row_cap : budgets.perf_team);
      }
    });
  } else {
    test.info().annotations.push({ type: 'partial', description: 'perf team not seeded (run scripts/seed.sh --perf): only the demo-team budgets were checked' });
  }

  const rows = samples.map((s) => `${s.ok ? 'ok  ' : 'OVER'} ${s.team.padEnd(5)} ${s.slug.padEnd(32)} runs ${s.runs.join(' / ').padEnd(24)} ms   median ${String(s.median).padStart(5)}   max ${String(s.max).padStart(5)}   budget ${s.budget}   ${s.pages} pages  ${s.bytes} bytes`);
  writeLog('92-perf.txt', `${rows.join('\n')}\n`);
  kit.log('perf.json', { budgets, samples });

  await test.step('show the budget report in the recorded page', async () => {
    const html = evidencePath('pdf-pages', '92-perf-report.html');
    const body = samples
      .map((s) => `<tr class="${s.ok ? 'ok' : 'over'}"><td>${escapeHtml(s.team)}</td><td>${escapeHtml(s.slug)}</td><td>${s.runs.join(' / ')}</td><td>${s.median}</td><td>${s.max}</td><td>${s.budget}</td><td>${s.pages}</td><td>${s.ok ? 'within budget' : 'OVER BUDGET'}</td></tr>`)
      .join('\n');
    fs.writeFileSync(html, `<!doctype html><meta charset="utf-8"><title>CBOM deliverables: response times</title>
<style>body{font:15px Helvetica,Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #334155;padding:7px 10px;text-align:left}th{background:#1e293b}.ok td:last-child{color:#4ade80}.over td{background:#7f1d1d}h1{margin:0 0 6px}p{color:#94a3b8}</style>
<h1>CBOM team deliverables: response times (ms)</h1><p>budgets: demo team ${budgets.demo} ms, perf team ${budgets.perf_team} ms, row cap ${budgets.row_cap} ms (plan 4.7)</p>
<table><tr><th>team</th><th>deliverable</th><th>runs</th><th>median</th><th>max</th><th>budget</th><th>pages</th><th>verdict</th></tr>${body}</table>`);
    await page.goto(pathToFileURL(html).href);
    await page.waitForTimeout(1500);
    await kit.shot(page, 'budget-report');
  });

  expect(samples.filter((s) => !s.ok).map((s) => `${s.team} ${s.slug}: ${s.max} ms > ${s.budget} ms`), 'every deliverable within its budget').toEqual([]);
  if (seed.perf) {
    // Speed is not enough: the big register must also be right. The KPI is the de-duplicated count of the
    // certificates of each source's latest scan, which the seed knows by construction.
    expect(perfRegisterKpi, 'perf team register KPI "Certificates ... Unique, all sources" equals the seeded current unique certificates').toBe(seed.perf.current_unique_certs);
  }
});
