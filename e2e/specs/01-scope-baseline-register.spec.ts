/**
 * #1 Scope Baseline & Asset Population Register
 *
 * Independent proof of ONE deliverable, runnable alone:
 *
 *   npx playwright test specs/01-scope-baseline-register.spec.ts
 *
 * Authenticated /1/cbom -> Deliverables menu -> "#1 · Scope Baseline & Asset Population Register" -> the API answers 200 with the X-Cbom-*
 * headers -> the browser downloads cbom-scope-baseline-register-team1-<YYYYMMDD>.pdf -> poppler reads it -> the pages are
 * rendered into viewer-01.html and shown in this same recorded page -> every expected string and count of
 * fixtures/expected.json is matched against the PDF TEXT (not the DOM) and the canaries of the failed, queued,
 * running, success-but-empty, other-team and sbom_sca scans must be absent.
 *
 * What this document must show: 7 sources, 68 current asset occurrences (29 of them carry findings), the 12 / 9 / 8 scan accounting with the failed, queued, running and success-but-empty scans excluded by name, the legacy-format source flagged, the failed-latest note for payments-service, and the blank assessor forms.
 */
import { expect, test } from '../fixtures';
import { expectNoFindings, runDeliverableFlow } from '../lib/flow';

test('#1 Scope Baseline & Asset Population Register: menu -> download -> PDF content matches the independent oracle', async ({ authedPage, kit }) => {
  test.setTimeout(240_000);
  const result = await runDeliverableFlow({
    page: authedPage,
    kit,
    slug: 'scope-baseline-register',
    highlights: [
      { label: 'sources', needle: 'B. Sources assessed' },
      { label: 'population', needle: 'Assets by type and impact' },
      { label: 'exclusions', needle: 'Scans not included' },
      { label: 'outside-visibility', needle: 'E. Outside static visibility' },
    ],
  });
  expect(result.saved.bytes, 'PDF size').toBeGreaterThan(20_000);
  expectNoFindings(result.findings, '#1 scope-baseline-register');
});
