/**
 * Review & Run keeps the server's reason on the card when "Start scan" is refused (local lab, round 5, u3: a team with
 * 0 credits pressed Start, the API answered 400 "Not enough credits: ..." and nothing stayed on screen; a 409 "Every
 * selected source is already queued in a run" read "The estimate changed").
 * Run: npx --yes tsx components/cbom/sources/startRefusal.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from "axios";

function refused(status: number, data: unknown, headers: Record<string, string> = {}): AxiosError {
  const config = { headers: new AxiosHeaders() } as InternalAxiosRequestConfig;
  return new AxiosError(`Request failed with status code ${status}`, "ERR_BAD_REQUEST", config, null, {
    status, statusText: "", headers, config, data,
  });
}

(globalThis as unknown as { window: unknown }).window = { location: { href: "/1/cbom/sources" } };
(globalThis as unknown as { localStorage: unknown }).localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {}, clear: () => {} };

async function main() {
  const { startRefusal } = await import("./startRefusal");

  const credits = startRefusal(refused(400, { detail: "Not enough credits: this run needs 1, the team has 0" }));
  assert.deepEqual(credits, { tone: "red", text: "Not enough credits: this run needs 1, the team has 0", clearEstimate: false });

  const soc = startRefusal(refused(400, { detail: "soc_ack: confirm that your SOC has agreed the network ranges and scan windows" }));
  assert.equal(soc.tone, "red");
  assert.match(soc.text, /^soc_ack: confirm/);

  const queued = startRefusal(refused(409, { detail: "Every selected source is already queued in a run" }));
  assert.deepEqual(queued, { tone: "amber", text: "Every selected source is already queued in a run", clearEstimate: true });

  const limited = startRefusal(refused(429, { detail: "Too Many Requests" }, { "retry-after": "30" }));
  assert.equal(limited.tone, "red");
  assert.match(limited.text, /try again in 30 seconds/i);

  const invalid = startRefusal(refused(422, { detail: [{ loc: ["body", "include"], msg: "Field required" }] }));
  assert.equal(invalid.text, "include: Field required");

  assert.equal(startRefusal(new Error("Network Error")).text, "Network Error");

  // the card renders it, persistently (not only a toast)
  const tab = fs.readFileSync(path.join(__dirname, "ReviewRunTab.tsx"), "utf8");
  assert.ok(tab.includes("const refusal = startRefusal(err);"), "StartCard's start mutation uses the server's reason");
  assert.ok(tab.includes('role={notice.tone === "green" ? "status" : "alert"}'), "a refusal is announced as an alert");
  console.log("startRefusal tests passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
