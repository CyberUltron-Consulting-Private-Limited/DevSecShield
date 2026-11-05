/**
 * L1 (round 5, local stack): the send-code button of the sign-in, sign-up and reset forms. Before, it stayed at
 * "Resend in 29s" for good after one press (the interval was cleared after its first tick) and also started that
 * wait when the code had not been sent at all (a malformed address answered 422).
 * The countdown itself is a React hook (useResendCountdown); this checks the pure parts and that both forms use it.
 * The browser check is round5/ui/l1/pw/probe_resend.mjs (the button is enabled again after 30 s).
 * Run: npx --yes tsx utils/resend_countdown.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { resendLabel, waitAfterFailedSend } from "./resend_countdown";

assert.equal(resendLabel(false, 0), "Send Verification Code");
assert.equal(resendLabel(false, 17), "Resend in 17s");
assert.equal(resendLabel(true, 30), "Sending code...");

// a failed send leaves nothing to wait for, except a 429's Retry-After (capped)
assert.equal(waitAfterFailedSend(422, null), 0);
assert.equal(waitAfterFailedSend(503, 30), 0);
assert.equal(waitAfterFailedSend(undefined, null), 0);
assert.equal(waitAfterFailedSend(429, 42), 42);
assert.equal(waitAfterFailedSend(429, 0.2), 1);
assert.equal(waitAfterFailedSend(429, 3600), 120);
assert.equal(waitAfterFailedSend(429, null), 0);

// both forms use the hook; none keeps its own setInterval timer
for (const form of ["LoginForm.tsx", "ResetLoginForm.tsx"]) {
  const src = readFileSync(path.join(__dirname, "..", "components", "auth", form), "utf8");
  assert.match(src, /useResendCountdown\(/, `${form} uses useResendCountdown`);
  assert.doesNotMatch(src, /setInterval\(/, `${form} has no interval of its own`);
  assert.match(src, /countdown\.start\(waitAfterFailedSend\(/, `${form} ends the wait when the send failed`);
}

// the hook re-arms a one-second timeout while time is left and clears only that timeout
const hook = readFileSync(path.join(__dirname, "resend_countdown.ts"), "utf8");
assert.match(hook, /setTimeout\(\(\) => setLeft\(\(s\) => Math\.max\(0, s - 1\)\), 1000\)/);
assert.match(hook, /\}, \[left\]\);/);

console.log("resend countdown: ok");
