/**
 * CB-30: the CI/CD files the integration guides generate fail a customer's pipeline on the CBOM policy gate.
 *
 * Each generated file is RUN here, not just read: its shell (GitHub Actions `run:` steps, the GitLab job script, the
 * Bamboo script, the Jenkinsfile `sh` steps) is executed with bash / sh against a local HTTP server that answers
 * POST /cicd/cbom/scan the way the backend does (compact JSON, gate_failed + gate). Expected exit codes come from the
 * policy: a high crypto finding fails the job; an explicit pass passes; an answer without a verdict (an older server,
 * a cut-off body) fails closed; an HTTP error fails as before. SAST / AI-BOM files must not change.
 * Each file runs the way its runner runs it: GitHub `bash -e <file>`, GitLab `sh -e`, Jenkins `sh` bodies executed
 * through their shebang, Bamboo `/bin/sh <file>`. Temporary directories persist between jobs where the runner keeps
 * them (TMPDIR for GitLab and Bamboo, WORKSPACE_TMP for Jenkins; GitHub empties RUNNER_TEMP per job), and a weak tree
 * then a clean tree must give 1 then 0: nothing of the first job may reach the second upload.
 * SAST / AI-BOM files are pinned by snapshots in ci-template-snapshots/ (a change there must be deliberate).
 * The reference copies in cicd_workflow_files/*.cbom.* must equal the builders' output (the Bamboo one is a .txt: it
 * is the body of a Bamboo Script task, valid only after Bamboo substitutes ${bamboo.cicd_api_key}, not a shell script).
 * Run (frontend/): npx --yes tsx@4.23.15 components/cicd/ciTemplates.test.ts   (needs bash, sh, curl, jq, zip)
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import { cbomGateScript } from "./ciScanScript";
import { CBOM_GATE_NOTE, bambooScript, githubActionsWorkflow, gitlabCi, jenkinsfile } from "./ciTemplates";

// js-yaml ships with ESLint (a dev dependency); the workflows are parsed as YAML so the test runs what a runner runs.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const yaml = require("js-yaml") as { load: (text: string) => unknown };

const KEY = "cb30-test-key-not-a-secret";

// ---------------------------------------------------------------------------------------- answers of the fake API
const row = (title: string, codes: string[], extra: Record<string, unknown> = {}) => ({
  title, finding_codes: codes, impact: codes.length ? "High" : null, location: "app/keys.py", line: 5, ...extra,
});
const gate = (verdict: string, failing: unknown[]) => ({
  policy: "cbom-code-high", verdict, fail_codes: ["WEAK_ALGORITHM"], failing_count: failing.length, failing,
  truncated: false, reason: verdict === "fail" ? "1 high crypto finding(s): WEAK_ALGORITHM." : verdict === "pass"
    ? "No high crypto finding." : "No CBOM result arrived within the time limit, so the tree was not judged.",
});
// Decoys: text inside a JSON string has its quotes escaped, so a snippet cannot fake the top-level verdict.
const FAIL_ANSWER = {
  results: { results: [row("RSA-1024", ["WEAK_ALGORITHM"], { snippet: 'print(\'"gate_failed":false\')' })] },
  status: "pending", cicd_log_id: "l1", finding_count: 1, gate_failed: true,
  gate: gate("fail", [{ codes: ["WEAK_ALGORITHM"], title: "RSA-1024", location: "app/keys.py", line: 5, impact: "High" }]),
};
const PASS_ANSWER = {
  results: { results: [row("AES-GCM", [], { snippet: 'x = \'"gate_failed":true\'' }), row("RSA-3072", ["QUANTUM_VULNERABLE"])] },
  status: "pending", cicd_log_id: "l2", finding_count: 2, gate_failed: false, gate: gate("pass", []),
};
const TIMEOUT_ANSWER = { results: null, status: "pending", cicd_log_id: "l3", finding_count: 0, gate_failed: true, gate: gate("no_result", []) };
// What a server without the gate answers (dev before CB-30): a CBOM template must not read silence as a pass.
const NO_VERDICT_ANSWER = { results: FAIL_ANSWER.results, status: "pending", cicd_log_id: "l4", finding_count: 1 };

type Reply = { status: number; body: string };
const replies: Record<string, Reply> = {
  fail: { status: 200, body: JSON.stringify(FAIL_ANSWER) },
  pass: { status: 200, body: JSON.stringify(PASS_ANSWER) },
  timeout: { status: 200, body: JSON.stringify(TIMEOUT_ANSWER) },
  noverdict: { status: 200, body: JSON.stringify(NO_VERDICT_ANSWER) },
  error: { status: 500, body: JSON.stringify({ detail: "Internal server error" }) },
};
// JSON.stringify is compact, like the backend's JSONResponse (separators "," and ":").
assert.match(replies.fail.body, /"gate_failed":true/);

// ------------------------------------------------------------------------------------------------- the harness
let current: Reply | "judge" = replies.pass;
const seen: { key?: string; bytes: number }[] = [];
const WEAK_MARKER = "weak_marker.py"; // a file only the weak tree has; a zip stores its name in plain text

function serve(): Promise<http.Server> {
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => { chunks.push(c); });
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      seen.push({ key: req.headers["cicd-api-key"] as string | undefined, bytes: body.length });
      // "judge": answer like the backend would for what was uploaded (any weak file in the zip fails the gate)
      const reply = current === "judge" ? (body.includes(WEAK_MARKER) ? replies.fail : replies.pass) : current;
      res.writeHead(reply.status, { "Content-Type": "application/json" });
      res.end(reply.body);
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

// All temporary files of this test live under one directory, removed at the end (nothing is left in /tmp).
const SCRATCH = fs.mkdtempSync(path.join(os.tmpdir(), "cb30-test-"));
const scratch = (prefix: string) => fs.mkdtempSync(path.join(SCRATCH, prefix));

function repoDir(weak = false): string {
  const dir = scratch("repo-");
  fs.writeFileSync(path.join(dir, "keys.py"), "KEY_SIZE = 3072\n");
  if (weak) fs.writeFileSync(path.join(dir, WEAK_MARKER), "KEY_SIZE = 1024\n");
  return dir;
}

// The child sees no proxy (the local server must be reached directly). It runs asynchronously: the fake API answers
// from this process's event loop.
function run(argv: string[], cwd: string, env: Record<string, string>): Promise<{ code: number; out: string }> {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, ...env };
  for (const k of Object.keys(childEnv)) {
    if (/^(https?|all|no)_proxy$/i.test(k)) delete childEnv[k];
  }
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { cwd, env: childEnv });
    let out = "";
    child.stdout.on("data", (c: Buffer) => { out += c.toString(); });
    child.stderr.on("data", (c: Buffer) => { out += c.toString(); });
    const timer = setTimeout(() => child.kill("SIGKILL"), 60_000);
    child.on("close", (code) => { clearTimeout(timer); resolve({ code: code ?? -1, out }); });
  });
}

// Every generated file, reduced to what its runner executes, in order. `argv(file)` is how the runner starts the step
// written to `file`; `shebang` marks a body run directly.
interface Step { script: string; argv: (file: string) => string[]; shebang?: boolean }
interface Job { name: string; steps: Step[]; env: Record<string, string> }

function githubJob(text: string): Job {
  // A run: step without `shell:` runs as `bash -e {0}` (no pipefail) on the runner.
  const wf = yaml.load(text) as { jobs: Record<string, { steps: { run?: string }[] }> };
  const steps = Object.values(wf.jobs)[0].steps.filter((s) => s.run).map((s) => ({ script: s.run!, argv: (f: string) => ["bash", "-e", f] }));
  return { name: "github", steps, env: {} };
}

function gitlabJob(text: string): Job {
  // The alpine image has no bash: the runner feeds the script to sh with errexit on.
  const doc = yaml.load(text) as Record<string, { script: string[] }>;
  const job = Object.values(doc)[0];
  return { name: "gitlab", steps: job.script.map((s) => ({ script: s, argv: (f: string) => ["sh", "-e", f] })), env: {} };
}

function jenkinsJob(text: string): Job {
  // sh '''...''' bodies (the Groovy script blocks only print). A body that starts with a shebang is run through it, with
  // no extra flags (Jenkins adds -xe only when there is none). Groovy unescapes ''' strings: a backslash at the end of a
  // line joins the next line; the bodies hold no other backslash.
  const steps = [...text.matchAll(/sh '''(#!\/bin\/sh\n[\s\S]*?)\n'''/g)].map((m) => {
    const body = m[1].replace(/\\\n/g, "");
    assert.doesNotMatch(body, /\\/, "a Jenkins sh body holds a backslash Groovy would unescape");
    return { script: body, argv: (f: string) => [f], shebang: true };
  });
  return { name: "jenkins", steps, env: {} };
}

function bambooJob(text: string): Job {
  // Bamboo replaces ${bamboo.cicd_api_key} before the script runs, then runs the body with /bin/sh (no -e).
  return { name: "bamboo", steps: [{ script: text.split("${bamboo.cicd_api_key}").join(KEY), argv: (f: string) => ["sh", f] }], env: {} };
}

// `shared` holds the directories a runner keeps between jobs (TMPDIR, Jenkins WORKSPACE_TMP); RUNNER_TEMP is per job.
async function runJob(job: Job, cwd: string, shared?: { tmpdir: string; workspaceTmp: string }): Promise<{ code: number; out: string }> {
  const perJob = scratch("job-");
  const env = {
    RUNNER_TEMP: perJob, TMPDIR: shared?.tmpdir ?? perJob, WORKSPACE_TMP: shared?.workspaceTmp ?? perJob, CICD_API_KEY: KEY, ...job.env,
  };
  let out = "";
  try {
    for (const [i, step] of job.steps.entries()) {
      const file = path.join(perJob, `step-${i}.sh`);
      fs.writeFileSync(file, step.script, { mode: step.shebang ? 0o755 : 0o644 });
      const r = await run(step.argv(file), cwd, env);
      out += r.out;
      if (r.code !== 0) return { code: r.code, out };
    }
    return { code: 0, out };
  } finally {
    fs.rmSync(perJob, { recursive: true, force: true });
  }
}

async function main() {
  const server = await serve();
  const port = (server.address() as { port: number }).port;
  const endpoint = `http://127.0.0.1:${port}/cicd/cbom/scan`;
  const cwd = repoDir(true);

  const cbomFiles: [string, string, (t: string) => Job][] = [
    ["github", githubActionsWorkflow({ kind: "cbom", endpoint, branch: "main" }), githubJob],
    ["gitlab", gitlabCi({ kind: "cbom", endpoint, branch: "main" }), gitlabJob],
    // the Jenkinsfile carries the key itself and reads the URL from SCAN_API_URL
    ["jenkins", jenkinsfile({ kind: "cbom", endpoint, apiKey: KEY }), (t) => ({ ...jenkinsJob(t), env: { SCAN_API_URL: endpoint } })],
    ["bamboo", bambooScript({ kind: "cbom", endpoint }), bambooJob],
  ];

  const expected: [keyof typeof replies, number][] = [["fail", 1], ["pass", 0], ["timeout", 1], ["noverdict", 1], ["error", 1]];
  for (const [name, text, toJob] of cbomFiles) {
    const dedent = (s: string) => s.split("\n").map((l) => l.trim()).join("\n");
    const gateText = dedent(cbomGateScript(name === "github" ? "response.json" : "devsecshield-response.json"));
    assert.ok(dedent(text).includes(gateText), `${name}: gate step present`);
    const job = toJob(text);
    assert.ok(job.steps.length > 0, `${name}: steps found`);
    for (const [answer, code] of expected) {
      current = replies[answer];
      seen.length = 0;
      const r = await runJob(job, cwd);
      assert.equal(r.code === 0 ? 0 : 1, code, `${name} on a "${answer}" answer: expected exit ${code}, got ${r.code}\n${r.out}`);
      assert.equal(seen.length, 1, `${name}: one upload per run`);
      assert.equal(seen[0].key, KEY, `${name}: the key travels in cicd-api-key`);
      assert.ok(seen[0].bytes > 100, `${name}: the zip was uploaded`);
      if (answer === "fail") assert.match(r.out, /CBOM policy gate: FAILED/);
      if (answer === "pass") assert.match(r.out, /CBOM policy gate: passed/);
      if (answer === "noverdict") assert.match(r.out, /no verdict/);
      if (answer === "error") assert.doesNotMatch(r.out, /CBOM policy gate/); // the request step already failed
      if (answer === "fail" && (name === "github" || name === "gitlab")) {
        assert.match(r.out, /High WEAK_ALGORITHM app\/keys\.py:5 RSA-1024/, `${name}: the failing finding is listed`);
      }
      // the verdict line starts a line of its own (Bamboo prints the compact JSON, which has no final newline)
      if (answer !== "error") assert.match(r.out, /^DevSecShield CBOM policy gate: /m, `${name}: the gate message starts its line`);
    }
    console.log(`ok ${name}: fail->1 pass->0 no_result->1 no-verdict->1 http-500->1`);

    // Same runner, weak tree then clean tree: the second job must upload only its own tree.
    current = "judge";
    const shared = { tmpdir: scratch("runner-tmp-"), workspaceTmp: scratch("workspace-tmp-") };
    const weak = await runJob(job, repoDir(true), shared);
    const clean = await runJob(job, repoDir(false), shared);
    assert.equal(weak.code === 0 ? 0 : 1, 1, `${name}: the weak tree fails\n${weak.out}`);
    assert.equal(clean.code, 0, `${name}: the clean tree after a weak one passes (nothing left from the first job)\n${clean.out}`);
    console.log(`ok ${name}: weak then clean on one runner -> 1, 0`);
  }

  // What the guides say under every CBOM file: what fails the job, and how to make the step advisory.
  for (const words of [/high crypto finding/, /no result arrives in time/, /cannot be reached|unreachable/, /error/, /wrong.*key|key.*wrong|invalid.*key/i,
    /continue-on-error/, /allow_failure/, /catchError/]) {
    assert.match(CBOM_GATE_NOTE, words, `CBOM_GATE_NOTE mentions ${words}`);
  }

  // Other scan types: no gate, and the exact files are pinned by snapshots. Against dev 3df26fd the SAST / AI-BOM GitHub
  // workflow differs only by the pinned actions/checkout line (CB-30 pins it for every kind); Jenkins and Bamboo are as
  // before; GitLab is new.
  const snapshots = path.join(__dirname, "ci-template-snapshots");
  for (const kind of ["sast", "ai_bom"]) {
    const ep = `https://api.example.test/cicd/${kind}/scan`;
    const files: [string, string][] = [
      ["github", githubActionsWorkflow({ kind, endpoint: ep, branch: "main" })],
      ["gitlab", gitlabCi({ kind, endpoint: ep, branch: "main" })],
      ["jenkins", jenkinsfile({ kind, endpoint: ep, apiKey: "<your DevSecShield CI/CD API key>" })],
      ["bamboo", bambooScript({ kind, endpoint: ep })],
    ];
    for (const [name, text] of files) {
      assert.doesNotMatch(text, /gate_failed|policy gate|Policy Gate/i, `${kind}: no CBOM gate`);
      const snapshot = path.join(snapshots, `${name}.${kind}.txt`);
      assert.equal(fs.readFileSync(snapshot, "utf8"), `${text}\n`, `${name} ${kind} file changed: if on purpose, update ${snapshot}`);
    }
  }
  // A SAST workflow is not blocked by a CBOM verdict it never asked for (its answer has none).
  current = replies.fail;
  assert.equal((await runJob(githubJob(githubActionsWorkflow({ kind: "sast", endpoint: endpoint.replace("cbom", "sast"), branch: "main" })), cwd)).code, 0);
  console.log("ok sast/ai_bom: no gate");

  // The reference copies for self-hosted customers are the builders' output.
  const ref = path.join(__dirname, "../../../cicd_workflow_files");
  const REF_ENDPOINT = "https://devsecshieldapi.zeroshield.ai/cicd/cbom/scan";
  const refs: [string, string][] = [
    ["github_actions.cbom.yaml", githubActionsWorkflow({ kind: "cbom", endpoint: REF_ENDPOINT, branch: "main" })],
    ["gitlab-ci.cbom.yml", gitlabCi({ kind: "cbom", endpoint: REF_ENDPOINT, branch: "main" })],
    ["Jenkinsfile.cbom", jenkinsfile({ kind: "cbom", endpoint: REF_ENDPOINT, apiKey: "<your DevSecShield CI/CD API key>" })],
    ["bamboo-script-body.cbom.txt", bambooScript({ kind: "cbom", endpoint: REF_ENDPOINT })],
  ];
  for (const [file, text] of refs) {
    const got = fs.readFileSync(path.join(ref, file), "utf8");
    assert.equal(got, `${text}\n`, `cicd_workflow_files/${file} differs from ciTemplates.ts (regenerate it)`);
  }
  console.log("ok reference files match");

  server.close();
  fs.rmSync(SCRATCH, { recursive: true, force: true });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
