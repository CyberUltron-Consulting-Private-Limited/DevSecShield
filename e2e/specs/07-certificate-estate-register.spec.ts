/**
 * #7 Certificate Estate Register
 *
 * Independent proof of ONE deliverable, runnable alone:
 *
 *   npx playwright test specs/07-certificate-estate-register.spec.ts
 *
 * Authenticated /1/cbom -> Deliverables menu -> "#7 · Certificate Estate Register" -> the API answers 200 with the X-Cbom-*
 * headers -> the browser downloads cbom-certificate-estate-register-team1-<YYYYMMDD>.pdf -> poppler reads it -> the pages are
 * rendered into viewer-07.html and shown in this same recorded page -> every expected string and count of
 * fixtures/expected.json is matched against the PDF TEXT (not the DOM) and the canaries of the failed, queued,
 * running, success-but-empty, other-team and sbom_sca scans must be absent.
 *
 * What this document must show: 18 certificate occurrences across 17 files de-duplicated to 14 unique certificates (the 4-scan duplicate synthetic-crypto-app.test shown once with 3 locations), 1 EXPIRED, 1 <=30 DAYS, 12 VALID as of the run date computed from the certificate files with openssl, the only Critical certificate (rsa1024_sha1.pem, subject legacy-internal.test) right after the expired and expiring ones, the chain.leaf.test -> chain-root.crt link, and blank Owner / Business system cells.
 */
import { expect, test } from '../fixtures';
import { expectNoFindings, runDeliverableFlow } from '../lib/flow';

test('#7 Certificate Estate Register: menu -> download -> PDF content matches the independent oracle', async ({ authedPage, kit }) => {
  test.setTimeout(240_000);
  const result = await runDeliverableFlow({
    page: authedPage,
    kit,
    slug: 'certificate-estate-register',
    highlights: [
      { label: 'register', needle: '3. Certificate register' },
      { label: 'duplicate-cert', needle: '3 locations' },
      { label: 'chain', needle: 'Signed by chain-root.crt' },
      { label: 'limits', needle: '4. Discovery limits and manual-field guidance' },
    ],
  });
  expect(result.saved.bytes, 'PDF size').toBeGreaterThan(20_000);
  expectNoFindings(result.findings, '#7 certificate-estate-register');
});
