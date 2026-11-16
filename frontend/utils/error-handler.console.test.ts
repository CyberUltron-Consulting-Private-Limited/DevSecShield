/**
 * Issue #31: a refused API call wrote the whole AxiosError to the browser console (handleApiError ran
 * console.log(error)). That error carries the request: config.data is the body (the password of a refused sign-in,
 * the current and new passwords on the Account page, the temporary password of Create admin user, integration
 * tokens) and config.headers holds the bearer token. A refused call now writes one line with its method, path and
 * status (or, with no response, axios's error code), and nothing else.
 * Failing-first on origin/dev bbe3cfef: console.log received the AxiosError, body and Authorization header included.
 * Run: npx --yes tsx@4.23.15 utils/error-handler.console.test.ts
 */
import assert from "node:assert/strict";
import test from "node:test";
import { inspect } from "node:util";
import { AxiosError, AxiosHeaders, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";

// Fabricated values: neither may ever reach the console.
const bodyMarker = "request-body-marker-31";
const headerMarker = "request-header-marker-31";
const STATUSES = [400, 401, 403, 404, 409, 422, 429, 500, 502, undefined];

/** A refused POST /account/password (a wrong current password) as axios rejects it; no status means no response. */
function refused(status?: number): AxiosError {
  const config: InternalAxiosRequestConfig = {
    method: "post",
    url: "/account/password",
    headers: new AxiosHeaders({ Authorization: `Bearer ${headerMarker}`, "Content-Type": "application/json" }),
    data: JSON.stringify({ current_password: bodyMarker, new_password: `${bodyMarker}-new` }),
  };
  const response: AxiosResponse | undefined = status === undefined ? undefined
    : { status, statusText: "Refused", headers: {}, config, data: { detail: "Incorrect current password" } };
  return new AxiosError(
    status === undefined ? "Network Error" : `Request failed with status code ${status}`,
    status === undefined ? AxiosError.ERR_NETWORK : AxiosError.ERR_BAD_REQUEST,
    config,
    { _body: config.data }, // the request object, which must not be logged either
    response,
  );
}

// handleApiError reads the browser's storage and location on a 401.
const store = new Map<string, string>();
Object.assign(globalThis, {
  window: { location: { href: "/1/account" } },
  localStorage: {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
  },
});

/** Every console call made while `fn` runs (and just after), as [level, ...args]. */
async function consoleCalls(fn: () => unknown): Promise<unknown[][]> {
  const sink = console as unknown as Record<string, (...args: unknown[]) => void>;
  const saved = new Map<string, (...args: unknown[]) => void>();
  const calls: unknown[][] = [];
  for (const level of ["log", "info", "warn", "error", "debug", "trace", "dir", "table"]) {
    saved.set(level, sink[level]);
    sink[level] = (...args: unknown[]) => void calls.push([level, ...args]);
  }
  try {
    await fn();
    await new Promise((resolve) => setTimeout(resolve, 20));
  } finally {
    for (const [level, original] of saved) sink[level] = original;
  }
  return calls;
}

test("a refused request writes one line: its method, path and status", async () => {
  const { handleApiError, showErrorToast } = await import("./error-handler");
  for (const status of STATUSES) {
    const line = status === undefined
      ? "API request failed: POST /account/password, no response (ERR_NETWORK)"
      : `API request failed: POST /account/password, status ${status}`;
    for (const handle of [handleApiError, (e: unknown) => showErrorToast(e, "fallback")]) {
      const calls = await consoleCalls(() => handle(refused(status)));
      assert.deepEqual(calls, [["warn", line]], `status ${status ?? "none"}`);
    }
  }
});

test("neither the request body nor the Authorization header reaches the console", async () => {
  const { handleApiError, showErrorToast } = await import("./error-handler");
  const calls = await consoleCalls(() => {
    for (const status of STATUSES) {
      handleApiError(refused(status));
      showErrorToast(refused(status), "fallback");
    }
  });
  const leaked = calls.filter((call) => inspect(call, { depth: 12 }).includes(bodyMarker)
    || inspect(call, { depth: 12 }).includes(headerMarker));
  assert.equal(leaked.length, 0, `${leaked.length} console call(s) wrote the request body or the bearer token`);
  const objects = calls.filter((call) => call.slice(1).some((arg) => typeof arg !== "string"));
  assert.equal(objects.length, 0, `${objects.length} console call(s) wrote an object (the error, its config, request or response)`);
});
