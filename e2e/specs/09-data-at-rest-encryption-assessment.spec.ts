/**
 * #9 Data-at-Rest Encryption Assessment.
 *
 *   npx playwright test specs/09-data-at-rest-encryption-assessment.spec.ts
 */
import { expect, test } from '../fixtures';
import { expectNoFindings, runDeliverableFlow } from '../lib/flow';

test('#9 Data at rest: menu download matches the oracle', async ({ authedPage, kit }) => {
  test.setTimeout(240_000);
  const result = await runDeliverableFlow({
    page: authedPage,
    kit,
    slug: 'data-at-rest-encryption-assessment',
    highlights: [{ label: 'stored', needle: 'stored data was not inspected' }],
  });
  expect(result.saved.bytes, 'PDF size').toBeGreaterThan(3_000);
  expectNoFindings(result.findings, '#9 data at rest');
});
