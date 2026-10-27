/**
 * #5 Infrastructure & Cloud Encryption Posture.
 *
 *   npx playwright test specs/05-infrastructure-cloud-encryption-posture.spec.ts
 */
import { expect, test } from '../fixtures';
import { expectNoFindings, runDeliverableFlow } from '../lib/flow';

test('#5 Infrastructure posture: menu download matches the oracle', async ({ authedPage, kit }) => {
  test.setTimeout(240_000);
  const result = await runDeliverableFlow({
    page: authedPage,
    kit,
    slug: 'infrastructure-cloud-encryption-posture',
    highlights: [{ label: 'limit', needle: 'declared configuration is not proof of operation' }],
  });
  expect(result.saved.bytes, 'PDF size').toBeGreaterThan(3_000);
  expectNoFindings(result.findings, '#5 infrastructure posture');
});
