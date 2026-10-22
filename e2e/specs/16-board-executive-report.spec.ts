/**
 * #16 Board / IT Strategy Committee Regulatory & Executive Report
 *
 * Independent proof of ONE deliverable, runnable alone:
 *
 *   npx playwright test specs/16-board-executive-report.spec.ts
 *
 * Authenticated /1/cbom -> Deliverables menu -> "#16 · Board / IT Strategy Committee Regulatory & Executive Report" -> the API answers 200 with the X-Cbom-*
 * headers -> the browser downloads cbom-board-executive-report-team1-<YYYYMMDD>.pdf -> poppler reads it -> the pages are
 * rendered into viewer-16.html and shown in this same recorded page -> every expected string and count of
 * fixtures/expected.json is matched against the PDF TEXT (not the DOM) and the canaries of the failed, queued,
 * running, success-but-empty, other-team and sbom_sca scans must be absent.
 *
 * What this document must show: grade F / score 100 computed from the 29 issue assets only, 68 assets, 7 sources, 8 of 9 scans, 14 unique certificates, readiness 86.5%, the single Critical asset first in the top 10, 13 framework rows pooled over 6 of 7 sources (legacy excluded), remediation priorities, governance actions with live metrics and the blank sign-off block.
 */
import { expect, test } from '../fixtures';
import { expectNoFindings, runDeliverableFlow } from '../lib/flow';

test('#16 Board / IT Strategy Committee Regulatory & Executive Report: menu -> download -> PDF content matches the independent oracle', async ({ authedPage, kit }) => {
  test.setTimeout(240_000);
  const result = await runDeliverableFlow({
    page: authedPage,
    kit,
    slug: 'board-executive-report',
    highlights: [
      { label: 'executive-summary', needle: '1. Executive summary' },
      { label: 'material-risks', needle: '2. Material risks (top 10)' },
      { label: 'regulatory-exposure', needle: '5. Regulatory exposure' },
      { label: 'remediation', needle: '6. Remediation priorities' },
      { label: 'sign-off', needle: '9. Sign-off' },
    ],
  });
  expect(result.saved.bytes, 'PDF size').toBeGreaterThan(20_000);
  expectNoFindings(result.findings, '#16 board-executive-report');
});
