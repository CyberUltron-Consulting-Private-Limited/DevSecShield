/**
 * F3 Repositories pages, in a real browser against the real API (e2e/repos/serve_api.py: backend.main on a throw-away
 * PostgreSQL database, GitHub simulated by the backend tests' fake API). Separate from the CBOM proof harness
 * (../playwright.config.ts), which needs its own seeded dss-e2e stack. Run everything with e2e/repos/run.sh.
 *
 * Environment (run.sh exports them):
 *  - E2E_REPOS_BASE_URL   the frontend (next dev) URL, default http://127.0.0.1:13000
 *  - E2E_REPOS_STATE      state.json written by serve_api.py (API URL, team, tokens, fake GitHub URL)
 *  - E2E_REPOS_OUT        where videos, screenshots and the JSON report go (default e2e/.work/repos)
 */
import * as path from 'node:path';

import { defineConfig } from '@playwright/test';

const OUT = process.env.E2E_REPOS_OUT ?? path.join(__dirname, '..', '.work', 'repos');

export default defineConfig({
  testDir: __dirname,
  testMatch: /.*\.spec\.ts$/,
  outputDir: path.join(OUT, 'test-results'),
  fullyParallel: false,
  workers: 1, // one API, one database: the specs build on each other in order
  retries: 0,
  forbidOnly: true,
  timeout: 180_000, // the first page load compiles the route in next dev
  expect: { timeout: 30_000 },
  reporter: [['list'], ['json', { outputFile: path.join(OUT, 'report.json') }]],
  use: {
    baseURL: process.env.E2E_REPOS_BASE_URL ?? 'http://127.0.0.1:13000',
    viewport: { width: 1440, height: 900 },
    video: 'on',
    screenshot: 'on',
    trace: 'retain-on-failure',
    locale: 'en-US',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
