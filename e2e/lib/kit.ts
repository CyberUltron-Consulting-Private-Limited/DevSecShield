/**
 * Browser-side helpers shared by the fixtures and the specs:
 *
 *  - `installEgressGuard`  fails a test that makes ANY request outside 127.0.0.1:43000 / 127.0.0.1:43080
 *    (other hosts are aborted, not just reported, so nothing really leaves the machine) and keeps the list
 *    of origins that were contacted as evidence;
 *  - `ConsoleCapture`      console messages, uncaught page errors, failed requests and HTTP >= 400
 *    responses of a page; the specs fail on uncaught errors and on 5xx answers;
 *  - `primeTokens`         puts API-login tokens into localStorage before any page script runs;
 *  - `SpecKit`             numbered screenshots and logs named for the spec (`07-...`), which is how
 *    scripts/collect-evidence.sh finds them.
 */
import * as path from 'node:path';

import type { BrowserContext, Page } from '@playwright/test';

import { writeLog } from './evidence';
import { ALLOWED_ORIGINS, BASE_URL, EVIDENCE_DIR, evidencePath, specBaseName } from './paths';
import type { Tokens } from './api';

// ---------------------------------------------------------------------------------------------
// egress guard
// ---------------------------------------------------------------------------------------------
export interface EgressRecord {
  /** origin (or scheme) -> number of requests */
  contacted: Record<string, number>;
  /** URLs that were refused because they leave the two allowed origins */
  blocked: string[];
}

function classify(rawUrl: string): { allowed: boolean; origin: string } {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { allowed: false, origin: rawUrl.slice(0, 40) };
  }
  switch (url.protocol) {
    case 'data:':
    case 'blob:':
    case 'about:':
      return { allowed: true, origin: url.protocol };
    case 'file:':
      // Only the local PDF viewer / contact sheets under the evidence directory.
      return { allowed: decodeURIComponent(url.pathname).startsWith(path.resolve(EVIDENCE_DIR)), origin: 'file:' };
    case 'http:':
    case 'https:':
      return { allowed: ALLOWED_ORIGINS.includes(url.origin), origin: url.origin };
    case 'ws:':
    case 'wss:':
      return { allowed: ALLOWED_ORIGINS.some((o) => new URL(o).host === url.host), origin: `${url.protocol}//${url.host}` };
    default:
      return { allowed: false, origin: url.protocol };
  }
}

export async function installEgressGuard(context: BrowserContext): Promise<EgressRecord> {
  const record: EgressRecord = { contacted: {}, blocked: [] };
  await context.route('**/*', async (route) => {
    const { allowed, origin } = classify(route.request().url());
    record.contacted[origin] = (record.contacted[origin] ?? 0) + 1;
    if (allowed) {
      await route.continue();
    } else {
      record.blocked.push(`${route.request().method()} ${route.request().url().slice(0, 200)}`);
      await route.abort('blockedbyclient');
    }
  });
  return record;
}

// ---------------------------------------------------------------------------------------------
// console capture
// ---------------------------------------------------------------------------------------------
export interface ConsoleLog {
  messages: Array<{ type: string; text: string }>;
  pageErrors: string[];
  failedRequests: Array<{ url: string; failure: string }>;
  badResponses: Array<{ status: number; method: string; url: string }>;
}

export function captureConsole(page: Page): ConsoleLog {
  const log: ConsoleLog = { messages: [], pageErrors: [], failedRequests: [], badResponses: [] };
  page.on('console', (message) => log.messages.push({ type: message.type(), text: message.text().slice(0, 500) }));
  page.on('pageerror', (error) => log.pageErrors.push(String(error.message).slice(0, 500)));
  page.on('requestfailed', (request) =>
    log.failedRequests.push({ url: request.url().slice(0, 200), failure: request.failure()?.errorText ?? '' }),
  );
  page.on('response', (response) => {
    if (response.status() >= 400) {
      log.badResponses.push({ status: response.status(), method: response.request().method(), url: response.url().slice(0, 200) });
    }
  });
  return log;
}

// ---------------------------------------------------------------------------------------------
// tokens
// ---------------------------------------------------------------------------------------------
/**
 * Seed localStorage with the API-login tokens before any page script runs (so credentials never appear on
 * screen). The script only writes keys that are still empty: the app may have refreshed the access token
 * since, and a persona switch (spec 90) writes the new values itself.
 */
export async function primeTokens(context: BrowserContext, tokens: Tokens): Promise<void> {
  await context.addInitScript(
    ({ access, refresh, origin }) => {
      try {
        if (location.origin !== origin) return;
        if (!localStorage.getItem('access_token')) localStorage.setItem('access_token', access);
        if (!localStorage.getItem('refresh_token')) localStorage.setItem('refresh_token', refresh);
      } catch {
        /* no storage on this document */
      }
    },
    { access: tokens.access, refresh: tokens.refresh, origin: new URL(BASE_URL).origin },
  );
}

/** Replace the tokens of the page that is already open (persona switch). */
export async function switchTokens(page: Page, tokens: Tokens): Promise<void> {
  await page.evaluate(
    ({ access, refresh }) => {
      localStorage.setItem('access_token', access);
      localStorage.setItem('refresh_token', refresh);
    },
    { access: tokens.access, refresh: tokens.refresh },
  );
}

// ---------------------------------------------------------------------------------------------
// per-spec evidence naming
// ---------------------------------------------------------------------------------------------
export class SpecKit {
  readonly base: string;
  /** `07` for specs/07-certificate-estate-register.spec.ts */
  readonly number: string;
  private counter = 0;

  constructor(specFile: string) {
    this.base = specBaseName(specFile);
    this.number = this.base.slice(0, 2);
  }

  /** screenshots/<spec>-NN-<label>.png (viewport, 1440x900). Returns the path. */
  async shot(page: Page, label: string, options: { fullPage?: boolean } = {}): Promise<string> {
    this.counter += 1;
    const file = evidencePath('screenshots', `${this.base}-${String(this.counter).padStart(2, '0')}-${label}.png`);
    await page.screenshot({ path: file, fullPage: options.fullPage ?? false });
    return file;
  }

  /** logs/<NN>-<name> (the number prefix is what the collector looks for). */
  log(name: string, content: string | object): string {
    return writeLog(`${this.number}-${name}`, content);
  }
}
