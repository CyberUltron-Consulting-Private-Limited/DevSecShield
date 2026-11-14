/**
 * Issue #99: the CI/CD key in the UI. The snippets the key dialog offers are the product's own CI templates
 * (ciTemplates.ts), name the secret and never contain a key; the stored key is described by its state and last four
 * characters only; the dialog opens only for an answer that carries a real one-time key.
 * Failing-first on origin/dev 3e1c594d: apiKey.ts did not exist and the Jenkinsfile embedded the key it was given.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { CI_SECRET_NAME, KEY_ONCE_NOTE, ciSnippets, hasIssuedKey, keyStateLabel } from "./apiKey";
import { bambooScript, githubActionsWorkflow, gitlabCi, jenkinsfile } from "./ciTemplates";

const ENDPOINT = "https://api.example.test/cicd/cbom/scan";
const REAL_KEY = "cicd7-" + "0123456789abcdef".repeat(8);

test("snippets: the four shipped CI templates, in order, built by the template builders", () => {
  for (const kind of ["cbom", "sast", "ai_bom"]) {
    const ep = `https://api.example.test/cicd/${kind}/scan`;
    const got = ciSnippets(kind, ep);
    assert.deepEqual(got.map((s) => s.id), ["github-actions", "gitlab", "jenkins", "bamboo"]);
    assert.equal(got[0].text, githubActionsWorkflow({ kind, endpoint: ep, branch: "main" }));
    assert.equal(got[1].text, gitlabCi({ kind, endpoint: ep, branch: "main" }));
    assert.equal(got[2].text, jenkinsfile({ kind, endpoint: ep }));
    assert.equal(got[3].text, bambooScript({ kind, endpoint: ep }));
    for (const s of got) assert.ok(s.text.includes(ep), `${s.id} posts to the integration's endpoint`);
  }
});

test("snippets name the secret and never carry a key", () => {
  for (const s of ciSnippets("cbom", ENDPOINT)) {
    assert.ok(!/cicd\d+-[0-9a-f]{16,}/.test(s.text), `${s.id} contains no key`);
    assert.ok(s.text.includes("cicd-api-key"), `${s.id} sends the cicd-api-key header`);
    const secret = s.id === "bamboo" ? "cicd_api_key" : CI_SECRET_NAME;
    assert.ok(s.text.includes(secret), `${s.id} reads ${secret}`);
    assert.ok(s.secretHelp.includes(secret), `${s.id} tells where to store ${secret}`);
  }
  const jenkins = jenkinsfile({ kind: "sast", endpoint: ENDPOINT });
  assert.match(jenkins, /CICD_API_KEY = credentials\('CICD_API_KEY'\)/);
});

test("CBOM snippets keep the policy gate; DAST has no zip-upload snippets", () => {
  for (const s of ciSnippets("CBOM", ENDPOINT)) assert.ok(s.text.includes("gate_failed"), `${s.id} has the gate`);
  for (const s of ciSnippets("sast", ENDPOINT)) assert.ok(!s.text.includes("gate_failed"), `${s.id} has no gate`);
  assert.deepEqual(ciSnippets("dast", ENDPOINT), []);
  assert.deepEqual(ciSnippets("DAST", ENDPOINT), []);
});

test("the branch reaches the GitHub Actions and GitLab snippets", () => {
  const [gh, gl] = ciSnippets("sast", ENDPOINT, "release/2.x");
  assert.ok(gh.text.includes("branches: [ release/2.x ]"));
  assert.ok(gl.text.includes('$CI_COMMIT_BRANCH == "release/2.x"'));
});

test("the stored key is described without the key", () => {
  assert.equal(keyStateLabel({ api_key_state: "active", api_key_hint: "1a2b" }), "Active, ends in 1a2b");
  assert.equal(keyStateLabel({ api_key_state: "active", api_key_hint: null }), "Active");
  assert.equal(keyStateLabel({ api_key_state: "revoked", api_key_hint: "1a2b" }), "Revoked");
  assert.equal(keyStateLabel({}), "Unknown");
  assert.equal(keyStateLabel(null), "Unknown");
});

test("the reveal dialog opens only for a real one-time key", () => {
  assert.equal(hasIssuedKey({ integration_id: 3, api_key: REAL_KEY }), true);
  assert.equal(hasIssuedKey({ integration_id: 3 }), false); // an older backend
  assert.equal(hasIssuedKey({ integration_id: 3, api_key: "ddf9fa81...1c2d" }), false); // the old masked hash
  assert.equal(hasIssuedKey({ integration_id: 3, api_key: "cicd7-…1c2d" }), false); // a label
  assert.equal(hasIssuedKey(null), false);
  assert.equal(hasIssuedKey("x"), false);
  assert.match(KEY_ONCE_NOTE, /won't see it again/);
});

test("no CI/CD screen renders a key it did not just receive", () => {
  // The integration page, the list page and every guide used to print or copy `api_key` (a prefix of the stored
  // hash). They must no longer read it at all; only ApiKeyRevealDialog shows a key, from a create/rotate answer.
  const root = path.resolve(__dirname, "../..");
  const files = [
    "app/[team_id]/ci_cd/page.tsx",
    "app/[team_id]/ci_cd/[integration_id]/page.tsx",
    "components/GitHubActionsIntegrationGuide.tsx",
    "components/JenkinsIntegrationGuide.tsx",
    "components/BambooIntegrationGuide.tsx",
    "components/GitLabCiIntegrationGuide.tsx",
    "components/JenkinsDastGuide.tsx",
  ];
  for (const f of files) {
    const text = fs.readFileSync(path.join(root, f), "utf8");
    // `data.api_key` is the create/rotate answer (the one-time key); any other `.api_key` is the stored label
    assert.ok(!/(?<!\bdata)\.api_key\b(?!_)/.test(text), `${f} reads a stored .api_key`);
    assert.ok(!/apiKey\.substring|clipboard\.writeText\(apiKey/.test(text), `${f} shows or copies a stored key`);
    const storageLines = text.split("\n").filter((l) => /sessionStorage|localStorage/.test(l));
    assert.ok(!storageLines.some((l) => /api_?key|issued/i.test(l)), `${f} stores a key in the browser`);
  }
});
