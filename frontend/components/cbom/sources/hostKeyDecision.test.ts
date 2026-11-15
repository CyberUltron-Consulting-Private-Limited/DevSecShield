// Run: npx --yes tsx components/cbom/sources/hostKeyDecision.test.ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { CbomHostKeyReset } from "@/utils/backend_api";

import { ACCEPT_WARNING, FORGET_WARNING, decisionsAllowed, hostKeyChange, pendingFor, pendingLabel } from "./hostKeyDecision";

const OLD = "SHA256:" + "E4CW" + "a".repeat(39);
const NEW = "SHA256:" + "rYnW" + "b".repeat(39);

// the node's own wording (scan_node/zs_scan_node/collectors/linux_ssh.py)
assert.deepEqual(hostKeyChange("host_key_changed", `host key changed (pinned ${OLD}, now ${NEW})`), { pinned: OLD, presented: NEW });
assert.deepEqual(hostKeyChange("host_key_changed", "the server no longer offers the pinned host key type"),
  { pinned: null, presented: null });
assert.equal(hostKeyChange("auth_failed", `host key changed (pinned ${OLD}, now ${NEW})`), null);
assert.equal(hostKeyChange("ready", undefined), null);
// a truncated fingerprint is not offered for acceptance (the server would refuse it anyway)
assert.deepEqual(hostKeyChange("host_key_changed", `host key changed (pinned ${OLD}, now SHA256:rYnW)`), { pinned: OLD, presented: null });

assert.equal(decisionsAllowed("tofu"), true);
assert.equal(decisionsAllowed(undefined), true); // the default policy is trust on first use
assert.equal(decisionsAllowed("pinned"), false);

assert.match(ACCEPT_WARNING, /intercepting/);
assert.match(FORGET_WARNING, /whatever key/);

const base: CbomHostKeyReset = {
  id: 1, source_id: 3, node_id: 2, job_id: 9, target: "10.232.0.102", port: 22, action: "accept", fingerprint: NEW,
  pinned_fingerprint: OLD, status: "pending", requested_by_user_id: 1, requested_at: "2026-11-15T00:00:00Z",
  applied_at: null, applied_job_id: null,
};
assert.equal(pendingFor([{ ...base, status: "applied" }], "10.232.0.102"), null);
assert.equal(pendingFor([base], "10.232.0.103"), null);
assert.equal(pendingFor([base, { ...base, id: 0, action: "forget" }], "10.232.0.102")?.id, 1);
assert.match(pendingLabel(base), /next job/);
assert.match(pendingLabel({ ...base, action: "forget", fingerprint: null }), /forgotten/);

// the backend's wording and fingerprint rule are the same as here
const backend = readFileSync(join(__dirname, "../../../../backend/utilities/cbom_sources/host_key_resets.py"), "utf8");
assert.ok(backend.includes('_FP = r"SHA256:[A-Za-z0-9+/]{43}"'));
assert.ok(backend.includes("intercepting the connection"));
const node = readFileSync(join(__dirname, "../../../../scan_node/zs_scan_node/collectors/linux_ssh.py"), "utf8");
assert.ok(node.includes('f"host key changed (pinned {pins[ktype]}, now {fp})"'));
assert.ok(node.includes('"the server no longer offers the pinned host key type"'));

console.log("hostKeyDecision tests passed");
