/**
 * F3 "Import repositories", as a customer, in a real browser, against the REAL API (serve_api.py: backend.main with
 * every router and real auth, PostgreSQL, GitHub simulated by backend/tests/support/fake_scm.py with 240 repositories
 * in the organisation "acme", served 100 per page).
 *
 * Every number the UI shows is checked twice: against the API's own answer for the same question (frontend / backend
 * consistency) and against an oracle computed here from the fake organisation's rules (make_repos: every 17th
 * repository archived, every 19th a fork, every 10th named legacy-*).
 *
 * Run: bash e2e/repos/run.sh   (starts the API and next dev, runs this file, stops both)
 */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

interface State { api: string; fake_api: string; team_id: number; org: string; repos: number; org_token: string;
  admin_token: string; member_token: string }

const state: State = JSON.parse(fs.readFileSync(process.env.E2E_REPOS_STATE ?? '', 'utf8'));
const TEAM = state.team_id;
const PAGE = `/${TEAM}/repositories`;
const CONNECTION = 'Acme GitHub';

// ---------------------------------------------------------------- oracle: the fake organisation (fake_scm.make_repos)
const repos = Array.from({ length: state.repos }, (_, i) => ({
  name: i % 10 ? `svc-${String(i).padStart(5, '0')}` : `legacy-${String(i).padStart(5, '0')}`,
  archived: i % 17 === 0,
  fork: i % 19 === 0,
}));
const keptByDefault = repos.filter((r) => !r.archived && !r.fork).length; // archived and forks are left out
const keptWithoutLegacy = repos.filter((r) => !r.archived && !r.fork && !r.name.startsWith('legacy-')).length;
const n = (v: number) => v.toLocaleString('en-US');
const credits = (v: number) => {
  const c = Math.round(v * 100) / 100;
  return `${c.toLocaleString('en-US', { maximumFractionDigits: 2 })} credit${c === 1 ? '' : 's'}`;
};

async function signIn(page: Page, token: string) {
  await page.addInitScript((t) => window.localStorage.setItem('access_token', t), token);
}

async function apiCall(request: APIRequestContext, method: 'GET' | 'POST' | 'PUT', path: string, body?: unknown,
  token = state.admin_token) {
  const res = await request.fetch(`${state.api}${path}`, {
    method, data: body, headers: { Authorization: `Bearer ${token}` },
  });
  return { status: res.status(), body: await res.json() };
}

test.describe.configure({ mode: 'serial' });

test('an admin imports an organisation: connect, discover, filter with a live count and price, import', async ({ page, request }) => {
  await signIn(page, state.admin_token);
  await page.goto(PAGE);
  await expect(page.getByRole('heading', { name: 'Repositories' })).toBeVisible();
  await expect(page.getByText('No repositories yet')).toBeVisible();
  await page.getByRole('button', { name: 'Import repositories' }).first().click();

  const wizard = page.getByRole('dialog', { name: 'Import repositories' });
  await expect(wizard.getByLabel('Import steps')).toContainText('1. Connect');

  // 1. Connect: the form says what is missing before anything is sent
  await wizard.getByRole('radio', { name: /Organisation, with a token/ }).check();
  await wizard.getByRole('button', { name: 'Connect and discover' }).click();
  await expect(wizard.getByText(/^1 to 64 letters/)).toBeVisible();
  await expect(wizard.getByText('The organisation is required')).toBeVisible();
  await expect(wizard.getByText('The access token is required')).toBeVisible();
  expect((await apiCall(request, 'GET', `/${TEAM}/scm/connections`)).body.connections).toHaveLength(0);

  await wizard.locator('#scm-name').fill(CONNECTION);
  await wizard.locator('#scm-scope-name').fill(state.org);
  await wizard.locator('#scm-token').fill(state.org_token);
  await expect(wizard.locator('#scm-token')).toHaveAttribute('type', 'password');

  // a self-hosted API the operator has not allowed: the server's sentence is shown and nothing is created
  await wizard.locator('#scm-api').fill('https://ghe.not-allowed.example/api/v3');
  await wizard.getByRole('button', { name: 'Connect and discover' }).click();
  await expect(wizard.getByRole('alert').filter({ hasText: 'GIT_ALLOWED_HOSTS' })).toBeVisible();
  expect((await apiCall(request, 'GET', `/${TEAM}/scm/connections`)).body.connections).toHaveLength(0);

  // the allowed server (the simulated GitHub Enterprise): connect, then discovery starts by itself
  await wizard.locator('#scm-api').fill(state.fake_api);
  await wizard.getByRole('button', { name: 'Connect and discover' }).click();

  // 2. Discover: 240 repositories, 100 per page
  await expect(wizard.getByText('Discovery complete')).toBeVisible({ timeout: 60_000 });
  await expect(wizard.getByTestId('discovered-count')).toContainText(`${n(state.repos)} repositories found in 3 pages`);
  const listed = await apiCall(request, 'GET', `/${TEAM}/scm/connections`);
  expect(listed.body.connections).toHaveLength(1);
  const conn = listed.body.connections[0];
  expect(conn.sync.summary.discovered).toBe(state.repos);
  expect(conn.secrets_set).toEqual(['token']);
  expect(JSON.stringify(listed.body)).not.toContain(state.org_token); // write-only credential
  await expect(page.locator('body')).not.toContainText(state.org_token);
  await page.screenshot({ path: test.info().outputPath('02-discovered.png') });

  // 3. Filter: the default leaves archived repositories and forks out
  await wizard.getByRole('button', { name: 'Choose which to scan' }).click();
  const preview = wizard.getByTestId('filter-preview');
  await expect(preview).toContainText(`${n(keptByDefault)} of ${n(state.repos)} repositories kept`);
  const apiDefault = await apiCall(request, 'POST', `/${TEAM}/scm/connections/${conn.id}/preview`,
    { filters: {}, products: ['sbom_sca'] });
  expect(apiDefault.body.in_scope).toBe(keptByDefault);
  await expect(preview).toContainText(credits(apiDefault.body.estimate.credits));

  // a typo in the size limit blocks the preview and the import instead of meaning "no limit"
  await wizard.locator('#wizard-filter-size').fill('abc');
  await expect(wizard.getByText(/^The size limit is a number of MB/).first()).toBeVisible();
  await expect(wizard.getByRole('button', { name: /^Import/ })).toBeDisabled();
  await wizard.locator('#wizard-filter-size').fill('');

  // exclude legacy-* and price CBOM as well: the count and the price follow the rules live
  await wizard.locator('#wizard-filter-exclude_names').fill('legacy-*');
  await wizard.getByRole('checkbox', { name: 'CBOM' }).check();
  await expect(preview).toContainText(`${n(keptWithoutLegacy)} of ${n(state.repos)} repositories kept`);
  const apiFiltered = await apiCall(request, 'POST', `/${TEAM}/scm/connections/${conn.id}/preview`,
    { filters: { exclude_names: ['legacy-*'] }, products: ['sbom_sca', 'cbom'] });
  expect(apiFiltered.body.in_scope).toBe(keptWithoutLegacy);
  await expect(preview).toContainText(`about ${credits(apiFiltered.body.estimate.credits)}`);
  await expect(preview).toContainText('Name excluded');
  await page.screenshot({ path: test.info().outputPath('03-filtered.png') });

  // 4. Import: nothing is charged; the webhook secret is shown once
  const balanceBefore = (await apiCall(request, 'GET', `/team/${TEAM}`)).body.team_credit_balance;
  await wizard.getByRole('button', { name: `Import ${n(keptWithoutLegacy)} repositories` }).click();
  await expect(wizard.getByTestId('import-done')).toContainText(`${n(keptWithoutLegacy)} repositories are in scope`);
  expect((await apiCall(request, 'GET', `/team/${TEAM}`)).body.team_credit_balance).toBe(balanceBefore);
  const hookUrl = `${state.api}/scm/webhooks/github/`;
  await expect(wizard.getByText(hookUrl, { exact: false })).toBeVisible();
  const secret = (await wizard.getByTestId('webhook-secret').innerText()).trim();
  expect(secret.length).toBeGreaterThanOrEqual(40);
  await page.screenshot({ path: test.info().outputPath('04-imported.png') });

  // the secret shown is the real one: GitHub's signature with it is accepted, a wrong one is refused
  const push = JSON.stringify({ ref: 'refs/heads/main', after: 'a'.repeat(40),
    repository: { id: 1001, full_name: `${state.org}/svc-00001`, default_branch: 'main' } });
  const sign = (key: string) => `sha256=${crypto.createHmac('sha256', key).update(push).digest('hex')}`;
  const hookPath = (await wizard.getByText(hookUrl, { exact: false }).innerText()).trim();
  const send = (sig: string) => request.post(hookPath, { data: push, headers: {
    'Content-Type': 'application/json', 'X-GitHub-Event': 'push', 'X-GitHub-Delivery': crypto.randomUUID(),
    'X-Hub-Signature-256': sig } });
  expect((await send(sign('not-the-secret'))).status()).toBe(401);
  expect((await send(sign(secret))).status()).toBeLessThan(300);

  await wizard.getByRole('button', { name: 'Done' }).click();
  await expect(wizard).toBeHidden();

  // the inventory agrees with the API, and survives a reload
  const inventory = await apiCall(request, 'GET', `/${TEAM}/scm/repositories?scope=in&page_size=1`);
  expect(inventory.body.total).toBe(keptWithoutLegacy);
  await expect(page.getByText(`${n(keptWithoutLegacy)} in scope of ${n(state.repos)} discovered`)).toBeVisible();
  await page.reload();
  await expect(page.getByText(`${n(keptWithoutLegacy)} in scope of ${n(state.repos)} discovered`)).toBeVisible();
  await expect(page.getByText(`${n(keptWithoutLegacy)} repositories · page 1 of ${Math.ceil(keptWithoutLegacy / 50)}`)).toBeVisible();
});

test('the same name again is refused with the server sentence, and nothing is created', async ({ page, request }) => {
  await signIn(page, state.admin_token);
  await page.goto(PAGE);
  await page.getByRole('button', { name: 'Import repositories' }).first().click();
  const wizard = page.getByRole('dialog', { name: 'Import repositories' });
  await wizard.getByRole('radio', { name: /Organisation, with a token/ }).check();
  await wizard.locator('#scm-name').fill(CONNECTION);
  await wizard.locator('#scm-scope-name').fill(state.org);
  await wizard.locator('#scm-token').fill(state.org_token);
  await wizard.locator('#scm-api').fill(state.fake_api);
  await wizard.getByRole('button', { name: 'Connect and discover' }).click();
  await expect(wizard.getByRole('alert').filter({ hasText: 'A connection with this name already exists' })).toBeVisible();
  await expect(wizard.getByLabel('Import steps')).toContainText('1. Connect');
  expect((await apiCall(request, 'GET', `/${TEAM}/scm/connections`)).body.connections).toHaveLength(1);
});

test('filters saved elsewhere meanwhile are a 409 in the editor, never silently overwritten', async ({ page, request }) => {
  await signIn(page, state.admin_token);
  await page.goto(`${PAGE}?tab=connections`);
  await page.getByRole('button', { name: 'Filters' }).click();
  const editor = page.getByRole('dialog', { name: `Repositories in scope: ${CONNECTION}` });
  await expect(editor.getByTestId('filter-preview')).toContainText(`${n(keptWithoutLegacy)} of ${n(state.repos)}`);

  // another admin saves different filters while this editor is open
  const conn = (await apiCall(request, 'GET', `/${TEAM}/scm/connections`)).body.connections[0];
  const other = await apiCall(request, 'PUT', `/${TEAM}/scm/connections/${conn.id}/filters`,
    { filters: { exclude_names: ['legacy-*'], include_forks: true }, expected_version: conn.row_version });
  expect(other.status).toBe(200);

  await editor.locator('#wizard-filter-include_names').fill('svc-0001*');
  const svc0001 = repos.filter((r) => !r.archived && !r.fork && r.name.startsWith('svc-0001')).length;
  await expect(editor.getByTestId('filter-preview')).toContainText(`${n(svc0001)} of ${n(state.repos)} repositories kept`);
  await editor.getByRole('button', { name: 'Save filters' }).click();
  await expect(editor.getByRole('alert').filter({ hasText: 'This was changed elsewhere' })).toBeVisible();
  const after = (await apiCall(request, 'GET', `/${TEAM}/scm/connections`)).body.connections[0];
  expect(after.filters.include_forks).toBe(true); // the other admin's save stands
  expect(after.filters.include_names).toEqual([]);
});

test('a member sees the inventory but cannot connect, change or start anything', async ({ page }) => {
  await signIn(page, state.member_token);
  await page.goto(PAGE);
  await expect(page.getByText('Only team admins can connect, change policies or start runs.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Import repositories' })).toHaveCount(0);
  await expect(page.getByRole('checkbox', { name: /Select every repository/ })).toHaveCount(0);
  await page.goto(`${PAGE}?tab=connections`);
  await expect(page.getByText(CONNECTION)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sync now' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Filters' })).toHaveCount(0);
});

test('an admin scans two repositories: price first, charged once, cancelled and refunded to the cent', async ({ page, request }) => {
  await signIn(page, state.admin_token);
  const balance = async () => (await apiCall(request, 'GET', `/team/${TEAM}`)).body.team_credit_balance as number;
  const before = await balance();
  await page.goto(PAGE);
  for (const name of ['svc-00001', 'svc-00002']) {
    await page.getByRole('checkbox', { name: `Select ${state.org}/${name}` }).check();
  }
  await expect(page.getByRole('region', { name: 'Bulk actions' })).toContainText('2 selected');
  await page.getByRole('button', { name: 'Scan now' }).click();
  const dialog = page.getByRole('dialog', { name: 'Scan 2 repositories now' });
  const estimate = dialog.getByTestId('run-estimate');
  await expect(estimate).toContainText('2 scans of 2 repositories for');

  // the price the dialog shows is the API's estimate for the same request, and nothing is charged by looking
  const ids = (await apiCall(request, 'GET', `/${TEAM}/scm/repositories?scope=in&q=svc-0000&page_size=10`)).body.items
    .filter((r: { name: string }) => ['svc-00001', 'svc-00002'].includes(r.name)).map((r: { id: number }) => r.id);
  const est = (await apiCall(request, 'POST', `/${TEAM}/scm/runs/estimate`, { repo_ids: ids, products: ['sbom_sca'] })).body;
  await expect(estimate).toContainText(`for ${credits(est.credits)}. The team has ${credits(before)}`);
  expect(await balance()).toBe(before);

  await dialog.getByRole('button', { name: `Start for ${credits(est.credits)}` }).click();
  await expect(page.getByText(`Queued 2 scans for ${credits(est.credits)}`)).toBeVisible();
  await expect(dialog).toBeHidden();
  expect(await balance()).toBeCloseTo(before - est.credits, 2); // one deduction for the whole run

  // the run waits in the queue (no scanner in this world); cancelling refunds what had not started
  await page.goto(`${PAGE}?tab=runs`);
  await expect(page.getByText('Run #1')).toBeVisible();
  await expect(page.getByText('Waiting 2')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.getByRole('button', { name: 'Cancel the waiting scans' }).click();
  await expect(page.getByText(`Cancelled; ${credits(est.credits)} refunded`)).toBeVisible();
  expect(await balance()).toBeCloseTo(before, 2);
  await page.screenshot({ path: test.info().outputPath('05-run-cancelled.png') });
});
