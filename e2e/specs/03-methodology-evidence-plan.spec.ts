/**
 * #3 Cryptographic Discovery Methodology & Evidence Plan
 *
 * Independent proof of ONE deliverable, runnable alone:
 *
 *   npx playwright test specs/03-methodology-evidence-plan.spec.ts
 *
 * Authenticated /1/cbom -> Deliverables menu -> "#3 · Cryptographic Discovery Methodology & Evidence Plan" -> the API answers 200 with the X-Cbom-*
 * headers -> the browser downloads cbom-methodology-evidence-plan-team1-<YYYYMMDD>.pdf -> poppler reads it -> the pages are
 * rendered into viewer-03.html and shown in this same recorded page -> every expected string and count of
 * fixtures/expected.json is matched against the PDF TEXT (not the DOM) and the canaries of the failed, queued,
 * running, success-but-empty, other-team and sbom_sca scans must be absent.
 *
 * What this document must show: live numbers templated into authored text (7 sources, 8 of 9 scans, 68 assets, 14 unique certificates, 13 frameworks pooled over 6 sources), the nine registered scanners in registry order and none of the three removed scanner modules, the 13-framework coverage table with its totals row, and the blank RACI / retention / sign-off tables.
 */
import { expect, test } from '../fixtures';
import { expectNoFindings, runDeliverableFlow } from '../lib/flow';

test('#3 Cryptographic Discovery Methodology & Evidence Plan: menu -> download -> PDF content matches the independent oracle', async ({ authedPage, kit }) => {
  test.setTimeout(240_000);
  const result = await runDeliverableFlow({
    page: authedPage,
    kit,
    slug: 'methodology-evidence-plan',
    highlights: [
      { label: 'scanners', needle: 'Scanner Order Discovers' },
      { label: 'coverage', needle: 'Framework Pass Pass with evidence' },
      { label: 'retention', needle: '9. Evidence retention and versioning' },
      { label: 'scan-list', needle: 'Appendix A. Scans considered' },
    ],
  });
  expect(result.saved.bytes, 'PDF size').toBeGreaterThan(20_000);
  expectNoFindings(result.findings, '#3 methodology-evidence-plan');
});
