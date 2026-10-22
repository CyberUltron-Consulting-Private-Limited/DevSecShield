/**
 * Playwright fixtures of the dss-e2e specs.
 *
 *   seed          seed.json (ids, personas, scan dates); a test INPUT written by e2e/seed/seed_team.py
 *   kit           numbered screenshots / logs named after the spec file (`07-...`)
 *   personaTokens API-login tokens per persona (cached on disk, see lib/api.ts)
 *   authedPage    the page of the admin persona: tokens from an API login are put into localStorage by an
 *                 init script, so no credentials are typed on screen (spec 00 is the one that does)
 *   egressGuard   AUTO: fails the test when anything outside 127.0.0.1:43000 / 127.0.0.1:43080 was requested
 *   consoleLog    AUTO: console / page-error / HTTP-error capture; the test fails on an uncaught page error
 *                 or a 5xx answer, and the log is saved as evidence
 *
 * Every spec imports `test` and `expect` from here, never from '@playwright/test'.
 */
import { expect, test as base, type Page } from '@playwright/test';

import { getTokens, type Tokens } from './lib/api';
import { installEgressGuard, captureConsole, primeTokens, SpecKit, type ConsoleLog, type EgressRecord } from './lib/kit';
import { loadSeed, type Persona, type SeedJson } from './lib/seed';

export { expect };

interface Fixtures {
  seed: SeedJson;
  kit: SpecKit;
  personaTokens: (persona: Persona) => Promise<Tokens>;
  authedPage: Page;
  egressGuard: EgressRecord;
  consoleLog: ConsoleLog;
}

/**
 * URL patterns whose 5xx answers do not fail a test. Empty on purpose: the UI under test must never be
 * served a server error. A spec that provokes one deliberately (none does today) lists its URL here.
 */
const IGNORED_5XX: RegExp[] = [];

export const test = base.extend<Fixtures>({
  seed: async ({}, use) => {
    await use(loadSeed());
  },

  kit: async ({}, use, testInfo) => {
    await use(new SpecKit(testInfo.file));
  },

  personaTokens: async ({ request, seed }, use) => {
    await use((persona: Persona) => getTokens(request, seed, persona));
  },

  egressGuard: [
    async ({ context, kit }, use) => {
      const record = await installEgressGuard(context);
      await use(record);
      kit.log('egress.json', {
        allowed_origins: ['http://127.0.0.1:43000', 'http://127.0.0.1:43080'],
        contacted: record.contacted,
        blocked: record.blocked,
      });
      expect(record.blocked, 'the browser must only talk to 127.0.0.1:43000 and 127.0.0.1:43080').toEqual([]);
    },
    { auto: true },
  ],

  consoleLog: [
    async ({ page, kit }, use) => {
      const log = captureConsole(page);
      await use(log);
      kit.log('console.json', {
        counts: {
          messages: log.messages.length,
          page_errors: log.pageErrors.length,
          failed_requests: log.failedRequests.length,
          http_errors: log.badResponses.length,
        },
        page_errors: log.pageErrors,
        failed_requests: log.failedRequests,
        http_errors: log.badResponses,
        api_base_url_lines: log.messages.filter((m) => m.text.includes('api base url')).map((m) => m.text),
      });
      expect(log.pageErrors, 'no uncaught page errors').toEqual([]);
      const serverErrors = log.badResponses.filter(
        (r) => r.status >= 500 && !IGNORED_5XX.some((pattern) => pattern.test(r.url)),
      );
      expect(serverErrors, 'no HTTP 5xx answers while the UI ran').toEqual([]);
    },
    { auto: true },
  ],

  authedPage: async ({ page, context, personaTokens }, use) => {
    await primeTokens(context, await personaTokens('admin'));
    await use(page);
  },
});
