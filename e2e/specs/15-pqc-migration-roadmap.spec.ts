/**
 * #15 PQC Migration Roadmap
 *
 * Independent proof of ONE deliverable, runnable alone:
 *
 *   npx playwright test specs/15-pqc-migration-roadmap.spec.ts
 *
 * Authenticated /1/cbom -> Deliverables menu -> "#15 · PQC Migration Roadmap" -> the API answers 200 with the X-Cbom-*
 * headers -> the browser downloads cbom-pqc-migration-roadmap-team1-<YYYYMMDD>.pdf -> poppler reads it -> the pages are
 * rendered into viewer-15.html and shown in this same recorded page -> every expected string and count of
 * fixtures/expected.json is matched against the PDF TEXT (not the DOM) and the canaries of the failed, queued,
 * running, success-but-empty, other-team and sbom_sca scans must be absent.
 *
 * What this document must show: 5 quantum-vulnerable occurrences (RSA-1024 and RSA-2048 across 3 sources), sized ML-KEM-768 / ML-DSA-65 targets for current-format scans and 'not available - legacy scan' for the legacy one, readiness 86.5% (32 safe / 5 vulnerable), the draft-qualified NIST IR 8547 timeline with its public URLs, and blank wave / date / owner columns.
 */
import { expect, test } from '../fixtures';
import { expectNoFindings, runDeliverableFlow } from '../lib/flow';

test('#15 PQC Migration Roadmap: menu -> download -> PDF content matches the independent oracle', async ({ authedPage, kit }) => {
  test.setTimeout(240_000);
  const result = await runDeliverableFlow({
    page: authedPage,
    kit,
    slug: 'pqc-migration-roadmap',
    highlights: [
      { label: 'timeline', needle: '2 Regulatory timeline' },
      { label: 'per-asset-roadmap', needle: '4 Per-asset roadmap' },
      { label: 'quantum-safe', needle: '5 Already quantum-safe and hybrid' },
      { label: 'notes', needle: '6 Notes' },
    ],
  });
  expect(result.saved.bytes, 'PDF size').toBeGreaterThan(20_000);
  expectNoFindings(result.findings, '#15 pqc-migration-roadmap');
});
