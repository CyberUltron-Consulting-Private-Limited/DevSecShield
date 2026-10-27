/**
 * #6 Network, TLS & Crypto Protocol Assessment.
 *
 *   npx playwright test specs/06-network-tls-protocol-assessment.spec.ts
 */
import { expect, test } from '../fixtures';
import { expectNoFindings, runDeliverableFlow } from '../lib/flow';

test('#6 Network TLS: menu download matches the oracle', async ({ authedPage, kit }) => {
  test.setTimeout(240_000);
  const result = await runDeliverableFlow({
    page: authedPage,
    kit,
    slug: 'network-tls-protocol-assessment',
    highlights: [{ label: 'probe', needle: 'The platform did not probe any endpoint' }],
  });
  expect(result.saved.bytes, 'PDF size').toBeGreaterThan(3_000);
  expectNoFindings(result.findings, '#6 network tls');
});
