/**
 * L1 (round 5, local stack): a 403 that refuses an action (not a member of the team, not a superuser) must keep the
 * session; only "Session not active" ends it. Before, every 403 called GET /logout, which revokes every token of the
 * account: opening a link to a deleted team, or /admin as a customer, signed the user out on every device.
 * Run: npx --yes tsx utils/error-handler.test.ts
 */
import assert from "node:assert/strict";
import { AxiosError, AxiosHeaders } from "axios";

function axios403(detail: unknown): AxiosError {
  const config = { headers: new AxiosHeaders() } as any;
  return new AxiosError("Request failed with status code 403", "ERR_BAD_REQUEST", config, null, {
    status: 403, statusText: "Forbidden", headers: {}, config, data: { detail },
  });
}
const settle = () => new Promise((r) => setTimeout(r, 20));

// a browser-ish global for the module (localStorage, location) and a record of what it does
const calls: string[] = [];
const store = new Map<string, string>([["access_token", "a"], ["refresh_token", "r"]]);
(globalThis as any).window = { location: { href: "/1/sast" } };
(globalThis as any).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
  clear: () => { calls.push("localStorage.clear"); store.clear(); },
};

async function main() {
const { handleApiError, isClosedSession } = await import("./error-handler");
const api = (await import("./interceptors")).default;
// record GET /logout instead of sending it
api.defaults.adapter = async (config) => {
  calls.push(`${config.method?.toUpperCase()} ${config.url}`);
  return { data: {}, status: 200, statusText: "OK", headers: {}, config };
};


// 1. authorisation refusals: the server's reason is shown, nobody is logged out
for (const detail of ["User is not in team", "User is not a superuser", "Only team admins can do this"]) {
  calls.length = 0;
  const e = handleApiError(axios403(detail));
  await settle();
  assert.equal(e.status, 403);
  assert.equal(e.message, detail);
  assert.deepEqual(calls, [], `"${detail}" must not log out (did: ${calls.join(", ")})`);
  assert.equal(store.get("refresh_token"), "r");
  assert.equal((globalThis as any).window.location.href, "/1/sast");
}

// 2. no detail: a generic message, still no logout
calls.length = 0;
assert.match(handleApiError(axios403(undefined)).message, /do not have permission/);
await settle();
assert.deepEqual(calls, []);

// 3. a closed session ends the session: /logout, storage cleared, sent to /login
assert.equal(isClosedSession("Session not active"), true);
assert.equal(isClosedSession("User is not in team"), false);
calls.length = 0;
handleApiError(axios403("Session not active"));
await settle();
assert.deepEqual(calls, ["GET /logout", "localStorage.clear"]);
assert.equal((globalThis as any).window.location.href, "/login");

console.log("error-handler 403 handling: ok");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
