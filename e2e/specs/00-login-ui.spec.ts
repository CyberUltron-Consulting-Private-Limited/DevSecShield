/**
 * 00 - the real login form, with the real one-time-code flow, on the production build.
 *
 *   npx playwright test specs/00-login-ui.spec.ts
 *
 * The other specs skip the form (API login + tokens in localStorage, so no credential is typed on screen).
 * This one proves the form itself: a wrong one-time code is refused and does not log in; the right one
 * ends on /home with both tokens stored; the session then opens the team CBOM page and the Deliverables
 * button is there. It also proves the frontend bundle was built against the E2E backend: the app logs
 * `api base url :  http://127.0.0.1:43080` on start.
 *
 * Note: the admin persona's one-time code is the backend's LOCAL_DEV_VERIFICATION_CODE (its email is
 * LOCAL_DEV_VERIFICATION_EMAIL); the credentials are throw-away values of this stack only.
 */
import { expect, test } from '../fixtures';
import { loadExpected } from '../lib/expected';
import { API_URL } from '../lib/paths';

test('00 login form: wrong code refused, right code lands on /home, session opens the CBOM page', async ({
  page,
  kit,
  seed,
  consoleLog,
}) => {
  test.setTimeout(180_000);
  const exp = loadExpected();
  const admin = seed.users.admin;

  await test.step('the login page renders and the app is wired to the E2E backend', async () => {
    await page.goto('/login');
    await expect(page.getByText(exp.login_ui.heading, { exact: false }).first()).toBeVisible();
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('#verification_code')).toBeVisible();
    await expect(page.getByRole('button', { name: exp.login_ui.submit })).toBeVisible();
    await kit.shot(page, 'login-form-empty');
    // The frontend logs `api base url :  <NEXT_PUBLIC_BACKEND_URL>`; on the stack that is http://127.0.0.1:43080.
    const logged = new RegExp(`api base url\\s*:\\s*${API_URL.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`);
    await expect
      .poll(() => consoleLog.messages.some((m) => logged.test(m.text)), {
        message: `the bundle logs the E2E backend URL (${API_URL})`,
        timeout: 15_000,
      })
      .toBe(true);
  });

  await test.step('a wrong one-time code is refused: no tokens are stored, the page stays on /login', async () => {
    await page.locator('#email').fill(admin.email);
    await page.locator('#password').fill(admin.password);
    await page.locator('#verification_code').fill(exp.login_ui.negative_otp);
    await kit.shot(page, 'login-wrong-code-filled');
    const refused = page.waitForResponse((r) => r.url().endsWith('/login') && r.request().method() === 'POST');
    await page.getByRole('button', { name: exp.login_ui.submit }).click();
    expect((await refused).status(), 'POST /login with a wrong one-time code').toBe(400);
    await expect(page).toHaveURL(/\/login/);
    expect(await page.evaluate(() => localStorage.getItem('access_token'))).toBeNull();
    await kit.shot(page, 'login-wrong-code-refused');
  });

  await test.step('the right credentials log in and land on /home with both tokens stored', async () => {
    await page.locator('#email').fill(admin.email);
    await page.locator('#password').fill(admin.password);
    await page.locator('#verification_code').fill(admin.otp);
    const accepted = page.waitForResponse((r) => r.url().endsWith('/login') && r.request().method() === 'POST');
    await page.getByRole('button', { name: exp.login_ui.submit }).click();
    expect((await accepted).status(), 'POST /login').toBe(200);
    await expect(page).toHaveURL(new RegExp(`${exp.login_ui.landing_path}`), { timeout: 30_000 });
    const tokens = await page.evaluate(() => ({
      access: localStorage.getItem('access_token'),
      refresh: localStorage.getItem('refresh_token'),
    }));
    expect(tokens.access, 'access token stored').toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(tokens.refresh, 'refresh token stored').toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    await kit.shot(page, 'home-after-login');
  });

  await test.step('the session opens the team CBOM page with the Deliverables button', async () => {
    await page.goto(`/${seed.teams.demo!.id}/cbom`);
    await expect(page.getByRole('heading', { name: 'CBOM Scans' })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText(seed.teams.demo!.name).first()).toBeVisible();
    await expect(page.getByTestId('cbom-deliverables-trigger')).toBeVisible();
    await kit.shot(page, 'cbom-page-with-deliverables-button');
    kit.log('login-ui.json', {
      persona: 'admin',
      wrong_code_status: 400,
      right_code_status: 200,
      landed: page.url(),
      api_base_url_logged: consoleLog.messages.filter((m) => m.text.includes('api base url')).map((m) => m.text),
    });
  });
});
