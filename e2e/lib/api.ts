/**
 * Talking to the backend directly: login (+ token cache), refresh and timed GETs.
 *
 * Why a cache: POST /login allows 5 calls per 60 s per client (per gunicorn worker), the personas'
 * one-time codes (other / empty) are consumed by a successful login, and every spec needs a token.
 * Tokens are therefore obtained once per persona and kept in e2e/.work/auth-cache.json (mode 600,
 * keyed by the seed's `seeded_at`, so a reseed starts clean). An access token with less than two
 * minutes left is renewed through POST /refresh; only when that fails does a spec log in again.
 *
 * The deliverable routes are rate limited per token (30 requests / 60 s). A 429 is honoured: wait for
 * Retry-After and try once more, instead of failing a spec for being quick.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

import type { APIRequestContext } from '@playwright/test';

import { API_URL, WORK_DIR } from './paths';
import type { Persona, SeedJson } from './seed';

export interface Tokens {
  access: string;
  refresh: string;
}

export interface TimedResponse {
  status: number;
  headers: Record<string, string>;
  ms: number;
  body: Buffer;
  url: string;
}

const CACHE_FILE = path.join(WORK_DIR, 'auth-cache.json');
const MAX_WAIT_S = 70;

interface CacheShape {
  seeded_at: string;
  personas: Partial<Record<Persona, Tokens>>;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Seconds until a JWT expires (negative when it has), or 0 when it cannot be read. */
export function secondsLeft(jwt: string): number {
  try {
    const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8')) as { exp?: number };
    return typeof payload.exp === 'number' ? payload.exp - Date.now() / 1000 : 0;
  } catch {
    return 0;
  }
}

function readCache(seed: SeedJson): CacheShape {
  try {
    const cache = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')) as CacheShape;
    if (cache.seeded_at === seed.seeded_at) return cache;
  } catch {
    /* no cache yet, or unreadable: start clean */
  }
  return { seeded_at: seed.seeded_at, personas: {} };
}

function writeCache(cache: CacheShape): void {
  fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
  fs.writeFileSync(CACHE_FILE, `${JSON.stringify(cache)}\n`, { mode: 0o600 });
}

function retryAfterSeconds(headers: Record<string, string>): number {
  const wait = Number(headers['retry-after']);
  return Math.min(MAX_WAIT_S, Number.isFinite(wait) && wait > 0 ? wait + 1 : 5);
}

async function login(request: APIRequestContext, seed: SeedJson, persona: Persona): Promise<Tokens> {
  const user = seed.users[persona];
  for (let attempt = 0; attempt < 3; attempt++) {
    const response = await request.post(`${API_URL}/login`, {
      data: { email: user.email, password: user.password, verification_code: user.otp },
    });
    if (response.status() === 429) {
      await sleep(retryAfterSeconds(response.headers()) * 1000);
      continue;
    }
    if (!response.ok()) {
      throw new Error(
        `POST /login for persona "${persona}" returned ${response.status()}: ${(await response.text()).slice(0, 200)}` +
          (persona !== 'admin' ? ' (their one-time code is consumed by a login: reseed to get a new one)' : ''),
      );
    }
    const body = (await response.json()) as { access_token: string; refresh_token: string };
    return { access: body.access_token, refresh: body.refresh_token };
  }
  throw new Error(`POST /login for persona "${persona}" stayed rate limited`);
}

async function refreshAccess(request: APIRequestContext, refreshToken: string): Promise<string | null> {
  const response = await request.post(`${API_URL}/refresh`, { data: { refresh_token: refreshToken } });
  if (!response.ok()) return null;
  const body = (await response.json()) as { access_token?: string };
  return body.access_token ?? null;
}

/** A usable access token for the persona (cached, refreshed or freshly logged in). */
export async function getTokens(request: APIRequestContext, seed: SeedJson, persona: Persona): Promise<Tokens> {
  const cache = readCache(seed);
  const entry = cache.personas[persona];
  if (entry && secondsLeft(entry.access) > 120) return entry;
  if (entry && secondsLeft(entry.refresh) > 60) {
    const access = await refreshAccess(request, entry.refresh);
    if (access) {
      cache.personas[persona] = { access, refresh: entry.refresh };
      writeCache(cache);
      return cache.personas[persona] as Tokens;
    }
  }
  const tokens = await login(request, seed, persona);
  cache.personas[persona] = tokens;
  writeCache(cache);
  return tokens;
}

export interface GetOptions {
  token?: string | null;
  /** Authorization header sent verbatim (overrides `token`): for malformed-header checks. */
  authorization?: string;
  retryOn429?: boolean;
}

/** GET with timing; honours one 429 by waiting for Retry-After. The body is returned as bytes. */
export async function apiGet(request: APIRequestContext, route: string, options: GetOptions = {}): Promise<TimedResponse> {
  const url = route.startsWith('http') ? route : `${API_URL}${route}`;
  const headers: Record<string, string> = {};
  if (options.authorization !== undefined) headers.Authorization = options.authorization;
  else if (options.token) headers.Authorization = `Bearer ${options.token}`;
  for (let attempt = 0; ; attempt++) {
    const started = Date.now();
    const response = await request.get(url, { headers, failOnStatusCode: false, timeout: 120_000 });
    const ms = Date.now() - started;
    const result: TimedResponse = {
      status: response.status(),
      headers: response.headers(),
      ms,
      body: await response.body(),
      url,
    };
    if (result.status === 429 && attempt === 0 && options.retryOn429 !== false) {
      await sleep(retryAfterSeconds(result.headers) * 1000);
      continue;
    }
    return result;
  }
}

/** JSON view of a response body, or the raw text when it is not JSON. */
export function bodyJson(response: TimedResponse): unknown {
  const text = response.body.toString('utf8');
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Response headers worth keeping as evidence (no tokens, no cookies). */
export function evidenceHeaders(headers: Record<string, string>): Record<string, string> {
  const keep = [
    'content-type', 'content-disposition', 'content-length', 'cache-control', 'x-content-type-options',
    'x-cbom-scans-included', 'x-cbom-sources', 'x-cbom-fidelity', 'x-cbom-fingerprint', 'date',
  ]; // fmt: skip
  return Object.fromEntries(keep.filter((name) => name in headers).map((name) => [name, headers[name]]));
}
