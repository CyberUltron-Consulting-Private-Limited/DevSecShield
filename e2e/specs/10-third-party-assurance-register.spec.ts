/**
 * #10 Third-Party Cryptographic Assurance & Attestation Register
 *
 * Independent proof of ONE deliverable, runnable alone:
 *
 *   npx playwright test specs/10-third-party-assurance-register.spec.ts
 *
 * Authenticated /1/cbom -> Deliverables menu -> "#10 · Third-Party Cryptographic Assurance & Attestation Register" -> the API answers 200 with the X-Cbom-*
 * headers -> the browser downloads cbom-third-party-assurance-register-team1-<YYYYMMDD>.pdf -> poppler reads it -> the pages are
 * rendered into viewer-10.html and shown in this same recorded page -> every expected string and count of
 * fixtures/expected.json is matched against the PDF TEXT (not the DOM) and the canaries of the failed, queued,
 * running, success-but-empty, other-team and sbom_sca scans must be absent.
 *
 * What this document must show: 23 cryptographic libraries (4 used by more than one source), the attestation ledger with one row per control the BOM cannot evidence (48 controls, 207 source-level obligations, all 'Attested 0/n' before any upload), the summary box and the blank vendor register.
 */
import { expect, test } from '../fixtures';
import { expectNoFindings, runDeliverableFlow } from '../lib/flow';

test('#10 Third-Party Cryptographic Assurance & Attestation Register: menu -> download -> PDF content matches the independent oracle', async ({ authedPage, kit }) => {
  test.setTimeout(240_000);
  const result = await runDeliverableFlow({
    page: authedPage,
    kit,
    slug: 'third-party-assurance-register',
    highlights: [
      { label: 'libraries', needle: 'A. Third-party cryptographic components' },
      { label: 'ledger', needle: 'B. Control attestation ledger' },
      { label: 'summary', needle: 'C. Attestation summary' },
      { label: 'vendor-register', needle: 'D. Vendor attestation register' },
    ],
  });
  expect(result.saved.bytes, 'PDF size').toBeGreaterThan(20_000);
  expectNoFindings(result.findings, '#10 third-party-assurance-register');
});
