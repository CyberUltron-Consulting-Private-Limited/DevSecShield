/**
 * X1 (Nov 11): the MCP form's headers field accepted any JSON (null, [], "x", {"n": 3}) as "Valid JSON" and sent it,
 * null meaning no headers; a refused estimate (the server URL answers 404 -> now a 400 that says so) opened the error
 * view whose "Try Again" reloaded the page; a failed MCP scan said only "The scan failed." with no way to run it again.
 * Run: npx --yes tsx utils/mcpHeaders.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { parseMcpHeaders } from "./mcpHeaders";
import { readFormRerun, saveFormRerun } from "./formRerun";

assert.deepEqual(parseMcpHeaders(""), { headers: null, error: null });
assert.deepEqual(parseMcpHeaders('{"Authorization": "Bearer x"}'), { headers: { Authorization: "Bearer x" }, error: null });
for (const bad of ["{bad json", "null", "[]", '"x"', "3", '{"X-Retries": 3}', '{"": "v"}', '{"Bad Name": "v"}']) {
  const out = parseMcpHeaders(bad);
  assert.equal(out.headers, null, bad);
  assert.ok(out.error && out.error.length > 10, `${bad} is refused with a field error`);
}

// Run again keeps the URL, transport and environment, never a header value
const store = new Map<string, string>();
(globalThis as { sessionStorage?: unknown }).sessionStorage = {
  getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v),
};
saveFormRerun("mcp", 5, { server_url: "https://mcp.example/sse", server_mode: "sse", environment: "staging", headers: '{"Authorization":"Bearer c"}' });
assert.deepEqual(readFormRerun("mcp", 5), { server_url: "https://mcp.example/sse", server_mode: "sse", environment: "staging" });

const src = fs.readFileSync(path.join(__dirname, "..", "components", "mcp-options-sidebar.tsx"), "utf8");
assert.ok(src.includes("const headersError = parseMcpHeaders(headersJson).error;"), "the field error is derived from the text");
assert.ok(src.includes("if (error) throw new Error(error);"), "invalid headers are never sent as null");
assert.ok(!src.includes("location.reload"), "no page reload");
assert.ok(src.includes('<ScanRequestError message={errorMessage} />'), "a refused estimate is shown under the button");
const estimate = src.slice(src.indexOf("const estimateCreditsMutation"), src.indexOf("const startScanMutation"));
assert.ok(!estimate.includes('setOptionsSidebarState("error")'), "a refused estimate keeps the form");
assert.ok(src.includes("scanFailureMessage(query.data)"), "a failed scan says why");
assert.ok(src.includes("<NewScanRunAgainButton"), "a failed scan offers Run again");

console.log("mcp headers and refusals: tests passed");
