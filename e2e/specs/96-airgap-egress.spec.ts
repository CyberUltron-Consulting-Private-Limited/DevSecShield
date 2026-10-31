/**
 * Air-gap egress. The gateway still serves the app. A public connect from
 * inside the backend container fails.
 *
 *   npx playwright test specs/96-airgap-egress.spec.ts
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

import { expect, test } from '@playwright/test';

const PROBE = path.join(__dirname, '..', 'airgap', 'airgap_probe.py');

test('public egress fails and the gateway still serves the app', async ({ page }) => {
  test.setTimeout(60_000);
  const seen: string[] = [];
  page.on('request', (req) => seen.push(req.url()));
  const login = await page.goto('/login');
  expect(login?.status()).toBe(200);
  expect(seen.length).toBeGreaterThan(0);
  for (const url of seen) {
    const host = new URL(url).hostname;
    expect(['127.0.0.1', 'localhost']).toContain(host);
  }
  const output = execFileSync(
    'docker',
    ['exec', '-i', 'dss-e2e-backend', '/backend/.venv/bin/python', '-'],
    { input: fs.readFileSync(PROBE), encoding: 'utf8' },
  );
  expect(output).toContain('tcp4 1.1.1.1:443 FAILED');
  expect(output).toContain('tcp6 2606:4700:4700::1111:443 FAILED');
  expect(output).toContain('dns example.com FAILED');
  expect(output).not.toContain('SUCCEEDED');
});
