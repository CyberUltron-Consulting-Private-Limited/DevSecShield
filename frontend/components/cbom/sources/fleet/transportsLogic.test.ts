// Run: npx --yes tsx components/cbom/sources/fleet/transportsLogic.test.ts
// #318: the Fleet tab's transports (Ansible AWX/AAP, Salt, AWS SSM) and the Apply message after a save already applied.
import assert from "node:assert/strict";

import {
  ARTIFACTS_OF,
  NEEDS_RELEASE,
  SECRETS_OF,
  TEST_ELSEWHERE,
  TRANSPORT_LABEL,
  applyText,
  canTest,
  emptyTransportDraft,
  endpointText,
  transportBody,
  transportProblems,
  type TransportDraft,
} from "./transportsLogic";

const awx = (over: Partial<TransportDraft> = {}): TransportDraft => ({
  ...emptyTransportDraft("awx"), name: "awx-prod", baseUrl: "https://awx.example.com", jobTemplateId: "42", token: "t0ken-value", ...over,
});
const salt = (over: Partial<TransportDraft> = {}): TransportDraft => ({
  ...emptyTransportDraft("salt"), name: "salt-dc1", baseUrl: "https://salt.example.com:8000", username: "zs", password: "pw-value", ...over,
});
const ssm = (over: Partial<TransportDraft> = {}): TransportDraft => ({
  ...emptyTransportDraft("ssm"), name: "ssm-prod", roleArn: "arn:aws:iam::123456789012:role/zs-run", regions: "ap-south-1, eu-west-1",
  documentName: "devsecshield-collect", ...over,
});

// labels, the secrets each kind stores, the files each kind installs
assert.deepEqual(Object.keys(TRANSPORT_LABEL), ["awx", "salt", "ssm"]);
assert.match(TRANSPORT_LABEL.awx, /Ansible/);
assert.deepEqual(SECRETS_OF, { awx: ["token"], salt: ["username", "password"], ssm: [] });
assert.deepEqual(ARTIFACTS_OF.awx, ["ansible-collection", "sshca-trust-ansible"]);
assert.deepEqual(ARTIFACTS_OF.salt, ["salt-state", "sshca-trust-salt"]);
assert.deepEqual(ARTIFACTS_OF.ssm, ["ssm-document", "ssm-role-cfn", "sshca-trust-ssm"]);
// SSH CA trust installers do not need a zs-collect release (issue #83)
for (const name of ["sshca-trust-ansible", "sshca-trust-salt", "sshca-trust-ssm"]) assert.equal(NEEDS_RELEASE.has(name), false);
// backend/utilities/cbom_sources/transports/artifacts.py NEEDS_RELEASE: these 400 while no zs-collect release is active
assert.deepEqual([...NEEDS_RELEASE].sort(), ["ansible-collection", "salt-state", "ssm-document", "zs-collect-manifest"]);

// the body the backend expects (backend/routers/cbom_transports.py: AwxConfig, SaltConfig, SsmConfig, SECRETS)
assert.deepEqual(transportBody(awx()), {
  kind: "awx", name: "awx-prod",
  config: { base_url: "https://awx.example.com", job_template_id: 42, verify_tls: true },
  secrets: { token: "t0ken-value" },
});
assert.deepEqual(transportBody(awx({ verifyTls: false, caPem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----" })).config,
  { base_url: "https://awx.example.com", job_template_id: 42, verify_tls: false, ca_pem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----" });
assert.deepEqual(transportBody(salt()), {
  kind: "salt", name: "salt-dc1",
  config: { base_url: "https://salt.example.com:8000", eauth: "pam", client: "local_async", mode: "cmd", batch_size: 50, verify_tls: true },
  secrets: { username: "zs", password: "pw-value" },
});
assert.deepEqual(transportBody(ssm()), {
  kind: "ssm", name: "ssm-prod",
  config: { role_arn: "arn:aws:iam::123456789012:role/zs-run", regions: ["ap-south-1", "eu-west-1"], document_name: "devsecshield-collect" },
  secrets: {},
});
assert.deepEqual(transportBody(ssm({ bucket: "zs-out" })).config.output_s3_bucket, "zs-out");
// names and URLs are trimmed; a trailing slash goes
assert.equal(transportBody(awx({ name: "  awx-prod ", baseUrl: " https://awx.example.com/ " })).config.base_url, "https://awx.example.com");

// what blocks Add, named per field (the server checks again)
assert.deepEqual(transportProblems(awx()), {});
assert.deepEqual(transportProblems(salt()), {});
assert.deepEqual(transportProblems(ssm()), {});
assert.equal(transportProblems(awx({ name: " " })).name, "Enter a name");
assert.match(transportProblems(awx({ baseUrl: "http://awx.example.com" })).baseUrl ?? "", /https:\/\//);
assert.match(transportProblems(awx({ jobTemplateId: "0" })).jobTemplateId ?? "", /job template/i);
assert.match(transportProblems(awx({ token: "" })).token ?? "", /token/i);
assert.match(transportProblems(salt({ password: "" })).password ?? "", /password/i);
assert.match(transportProblems(salt({ username: "" })).username ?? "", /user/i);
assert.match(transportProblems(salt({ client: "ssh", batchSize: "200" })).batchSize ?? "", /100/);
assert.match(transportProblems(ssm({ roleArn: "arn:aws:iam::123:user/x" })).roleArn ?? "", /role ARN/);
assert.match(transportProblems(ssm({ regions: "" })).regions ?? "", /region/);
assert.match(transportProblems(ssm({ regions: "mumbai" })).regions ?? "", /ap-south-1/);
assert.match(transportProblems(ssm({ documentName: "collect" })).documentName ?? "", /devsecshield-/);

// the endpoint line of a row; secrets never appear
assert.equal(endpointText({ kind: "awx", config: { base_url: "https://awx.example.com", job_template_id: 42 } }), "https://awx.example.com · job template 42");
assert.equal(endpointText({ kind: "salt", config: { base_url: "https://salt.example.com:8000", client: "ssh" } }), "https://salt.example.com:8000 · salt-ssh");
assert.equal(endpointText({ kind: "ssm", config: { role_arn: "arn:aws:iam::123456789012:role/zs-run", regions: ["ap-south-1"] } }),
  "arn:aws:iam::123456789012:role/zs-run · ap-south-1");

// only SSM is tested from ZeroShield; AWX and Salt are reached from a scan node inside the customer's network
assert.equal(canTest("ssm"), true);
assert.equal(canTest("awx"), false);
assert.equal(canTest("salt"), false);
assert.match(TEST_ELSEWHERE, /scan node/);

// Apply: say what changed; when a save already applied the policies, say so instead of "0 sources added"
const zero = { materialize: true, sources_created: 0, sources_updated: 0, sources_removed: 0, deferred: 0, targets_assigned: 0,
  targets_unassigned: 0, schedules_created: 0, schedules_updated: 0, schedules_removed: 0, decisions_changed: 0, problems: [] };
assert.equal(applyText({ ...zero, sources_created: 2, sources_removed: 1, schedules_created: 1 }),
  "Applied: 2 sources created, 1 removed, 1 schedule created");
assert.equal(applyText({ ...zero, sources_updated: 1 }), "Applied: 1 source updated");
assert.equal(applyText({ ...zero, deferred: 3 }), "Applied: 3 changes wait for a running job");
assert.equal(applyText({ ...zero, previous: { ...zero, sources_created: 1, at: "2026-11-14T22:53:49Z", by: "automatic" } }),
  "Applied when saved (22:53 UTC): 1 source created. Nothing more to change.");
assert.equal(applyText({ ...zero, previous: { ...zero, sources_created: 1, at: "2026-11-14T22:53:49Z", by: "user" } }),
  "Nothing to change: the managed sources already match the policies.");
assert.equal(applyText({ ...zero, previous: { ...zero, at: "2026-11-14T22:53:49Z", by: "automatic" } }),
  "Nothing to change: the managed sources already match the policies.");
assert.equal(applyText({ ...zero, previous: null }), "Nothing to change: the managed sources already match the policies.");
assert.equal(applyText({ ...zero, materialize: false, decisions_changed: 2 }),
  "Decisions refreshed (2 changed); managed sources are turned off in this deployment");
assert.ok(!/0 sources added/.test(applyText(zero)));

console.log("transportsLogic: ok");
