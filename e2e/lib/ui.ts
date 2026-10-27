/**
 * UI helpers for the team CBOM landing page (`/{team}/cbom`) and its Deliverables menu (WP5).
 *
 * Selectors are the ones the page exposes: `data-testid="cbom-deliverables-trigger"` and
 * `data-testid="cbom-deliverable-<slug>"`; the label is `#<number> · <title>`; a disabled item carries
 * `data-disabled` and the manifest reason as its `title`.
 */
import { expect, type Locator, type Page, type Response } from '@playwright/test';

import { evidenceHeaders } from './api';
import type { Expected } from './expected';

export interface MenuItemState {
  slug: string;
  label: string;
  disabled: boolean;
  title: string | null;
}

const manifestUrl = (teamId: number) => (r: Response): boolean =>
  r.request().method() === 'GET' && new URL(r.url()).pathname === `/${teamId}/cbom/deliverables`;

/** Go to the team CBOM page and wait for the deliverables manifest the page requests on mount. */
export async function openLanding(page: Page, teamId: number): Promise<{ manifestStatus: number; manifest: unknown }> {
  const manifest = page.waitForResponse(manifestUrl(teamId), { timeout: 60_000 });
  await page.goto(`/${teamId}/cbom`);
  await expect(page.getByRole('heading', { name: 'CBOM Scans' })).toBeVisible({ timeout: 60_000 });
  const response = await manifest;
  await expect(page.getByTestId('cbom-deliverables-trigger')).toBeVisible();
  return { manifestStatus: response.status(), manifest: await response.json().catch(() => null) };
}

/** Open the Deliverables dropdown and wait for its items. */
export async function openMenu(page: Page): Promise<void> {
  await page.getByTestId('cbom-deliverables-trigger').click();
  await expect(page.getByRole('menu')).toBeVisible();
}

export async function closeMenu(page: Page): Promise<void> {
  await page.keyboard.press('Escape');
  await expect(page.getByRole('menu')).toBeHidden();
}

export function menuItem(page: Page, slug: string): Locator {
  return page.getByTestId(`cbom-deliverable-${slug}`);
}

/** State of every menu item, in the order the page renders them. */
export async function readMenu(page: Page, slugs: string[]): Promise<MenuItemState[]> {
  const out: MenuItemState[] = [];
  for (const slug of slugs) {
    const item = menuItem(page, slug);
    await expect(item).toBeVisible();
    out.push({
      slug,
      label: ((await item.innerText()) ?? '').replace(/\s+/g, ' ').trim(),
      disabled: (await item.getAttribute('data-disabled')) !== null || (await item.getAttribute('aria-disabled')) === 'true',
      title: await item.getAttribute('title'),
    });
  }
  return out;
}

/** The menu must list manifest.order, in that order, with those labels. */
export async function expectMenu(
  page: Page,
  exp: Expected,
  disabled: string[] = [],
): Promise<MenuItemState[]> {
  const slugs = exp.manifest.order as string[];
  const items = await readMenu(page, slugs);
  const order = await page.locator('[data-testid^="cbom-deliverable-"]').evaluateAll((nodes) => nodes.map((n) => n.getAttribute('data-testid')));
  expect(order, 'menu order').toEqual(slugs.map((slug) => `cbom-deliverable-${slug}`));
  for (const item of items) {
    expect(item.label, `menu label of ${item.slug}`).toBe(exp.documents[item.slug].menu_label);
    expect(item.disabled, `${item.slug} disabled`).toBe(disabled.includes(item.slug));
    if (disabled.includes(item.slug)) expect(item.title, `${item.slug} tooltip explains why`).toBe(exp.empty_team.disabled_reason);
  }
  return items;
}

export interface DownloadResult {
  download: import('@playwright/test').Download;
  api: {
    url: string;
    status: number;
    headers: Record<string, string>;
    ms: number;
    request_started: string;
  };
}

/** Click a menu item and capture the download and the API response behind it. */
export async function downloadViaMenu(page: Page, teamId: number, slug: string): Promise<DownloadResult> {
  const started = Date.now();
  const response = page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === `/${teamId}/cbom/deliverables/${slug}`,
    { timeout: 90_000 },
  );
  const download = page.waitForEvent('download', { timeout: 90_000 });
  await menuItem(page, slug).click();
  const [res, file] = await Promise.all([response, download]);
  const timing = res.request().timing();
  const ms = timing.responseEnd > 0 ? Math.round(timing.responseEnd) : Date.now() - started;
  return {
    download: file,
    api: {
      url: res.url(),
      status: res.status(),
      headers: evidenceHeaders(await res.allHeaders()),
      ms,
      request_started: new Date(started).toISOString(),
    },
  };
}

/** Today in UTC as the client formats it (`new Date().toISOString().slice(0, 10)` without dashes). */
export function clientDateStamp(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10).replace(/-/g, '');
}
