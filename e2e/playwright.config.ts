/**
 * Playwright configuration for the CBOM team-deliverables E2E proof harness (dss-e2e).
 *
 * Toolchain rules (see e2e/README.md):
 *  - @playwright/test is pinned EXACTLY to 1.62.0 in e2e/package.json. That release declares
 *    chromium / chromium-headless-shell 1234 and ffmpeg 1011, which are the revisions already in
 *    ~/.cache/ms-playwright. Browsers are NEVER downloaded here (`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
 *    npm ci`; never run `playwright install`).
 *  - `chromiumSandbox` is deliberately left at its default (false). The host's AppArmor policy
 *    (kernel.apparmor_restrict_unprivileged_userns=1) makes Chromium refuse to start with the
 *    sandbox enabled, so do not turn it on.
 *  - One worker, no retries, no parallelism: the specs share one seeded stack, and the backend
 *    rate limiter is per token, so runs must be sequential and deterministic.
 *
 * Environment (all optional; scripts/run-specs.sh exports them):
 *  - E2E_EVIDENCE_DIR  where videos / screenshots / downloads / reports go
 *  - E2E_BASE_URL      frontend URL        (default http://127.0.0.1:43000)
 *  - E2E_TEST_DIR      spec directory      (default ./specs; override only for local debugging)
 */
import * as path from 'node:path';

import { defineConfig } from '@playwright/test';

const E2E_ROOT = __dirname;
const EVIDENCE_DIR = process.env.E2E_EVIDENCE_DIR ?? path.join(E2E_ROOT, '.work', 'evidence');
const BASE_URL = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:43000';

const VIEWPORT = { width: 1440, height: 900 } as const;

export default defineConfig({
  testDir: process.env.E2E_TEST_DIR ?? path.join(E2E_ROOT, 'specs'),

  // Playwright empties outputDir at the start of every run, so it must be a sub-folder of the
  // evidence dir and never the evidence dir itself (collect-evidence.sh copies what is needed out).
  outputDir: path.join(EVIDENCE_DIR, 'test-results'),

  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 120_000,
  expect: { timeout: 15_000 },

  reporter: [
    ['list'],
    ['json', { outputFile: path.join(EVIDENCE_DIR, 'reports', 'playwright.json') }],
    ['html', { outputFolder: path.join(EVIDENCE_DIR, 'reports', 'html'), open: 'never' }],
  ],

  use: {
    baseURL: BASE_URL,
    viewport: VIEWPORT,
    video: { mode: 'on', size: VIEWPORT },
    screenshot: 'on',
    trace: 'on',
    acceptDownloads: true,
    locale: 'en-US',
    launchOptions: { slowMo: 100 },
  },

  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
});
