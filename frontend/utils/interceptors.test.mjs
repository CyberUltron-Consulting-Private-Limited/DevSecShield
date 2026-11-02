/**
 * The axios interceptor against a real local HTTP server: parallel 401s share ONE refresh, a 429 on /refresh is
 * waited out (never a logout), a refused refresh token sends the user to /login.
 * Run: npx --yes tsx utils/interceptors.test.mjs
 */
import assert from "node:assert/strict";
import http from "node:http";

const state = { refreshCalls: 0, refreshPlan: [], dataCalls: 0 };
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    if (req.url === "/refresh") {
      state.refreshCalls += 1;
      const step = state.refreshPlan.shift() ?? { status: 200, token: "new" };
      const headers = { "content-type": "application/json", ...(step.retryAfter ? { "retry-after": String(step.retryAfter) } : {}) };
      res.writeHead(step.status, headers);
      res.end(JSON.stringify(step.status === 200 ? { access_token: step.token } : { detail: "x" }));
      return;
    }
    state.dataCalls += 1;
    const ok = req.headers.authorization === "Bearer new";
    res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
    res.end(JSON.stringify(ok ? { ok: true } : { detail: "Could not validate credentials" }));
  });
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
process.env.NEXT_PUBLIC_BACKEND_URL = `http://127.0.0.1:${server.address().port}`;

const store = new Map();
globalThis.window = { location: { href: "/7/sast/12" } };
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};
const { default: api, retryAfterSeconds } = await import("./interceptors.js");

// 1. three parallel 401s, the first refresh is rate limited (Retry-After: 1): one shared refresh, no logout
store.set("access_token", "old");
store.set("refresh_token", "r");
state.refreshPlan = [{ status: 429, retryAfter: 1 }, { status: 200, token: "new" }];
const started = Date.now();
const results = await Promise.all([api.get("/a"), api.get("/b"), api.get("/c")]);
assert.deepEqual(results.map((r) => r.status), [200, 200, 200]);
assert.equal(state.refreshCalls, 2, "one refresh for all three requests (+1 retry after the 429)");
assert.ok(Date.now() - started >= 900, "the 429 was waited out");
assert.equal(store.get("access_token"), "new");
assert.equal(window.location.href, "/7/sast/12", "a rate-limited refresh never logs out");

// 2. the refresh token is refused (403): tokens dropped, sent to /login
store.set("access_token", "old");
state.refreshCalls = 0;
state.refreshPlan = [{ status: 403 }];
await assert.rejects(api.get("/d"), (err) => err?.response?.status === 401);
assert.equal(state.refreshCalls, 1);
assert.equal(window.location.href, "/login");
assert.equal(store.has("refresh_token"), false);

// 3. Retry-After parsing
assert.equal(retryAfterSeconds({ response: { headers: { "retry-after": "27" } } }), 27);
assert.equal(retryAfterSeconds({ response: { headers: {} } }), null);
const inTwoSeconds = new Date(Date.now() + 2500).toUTCString();
assert.ok([2, 3].includes(retryAfterSeconds({ response: { headers: { "retry-after": inTwoSeconds } } })));

server.close();
console.log("interceptors: all assertions passed");
