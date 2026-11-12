// The CI/CD files the integration guides show (GitHub Actions, Jenkins, Atlassian Bamboo, GitLab CI), as pure
// functions so they can be tested by running their shell, and so cicd_workflow_files/*.cbom.* can be checked against
// them (ciTemplates.test.ts). Every file uploads the tree to POST /cicd/<kind>/scan with the shared request script
// (ciScanScript.ts). A CBOM file also ends with the CBOM policy gate: the job fails when the answer says
// "gate_failed":true or carries no verdict. Other kinds are unchanged.

import { cbomGateDetailsJq, cbomGateScript, indent, scanRequestScript, zipCommand } from "./ciScanScript";

const D = "$"; // writes a shell/Groovy "${" without starting a JS template interpolation

// actions/checkout pinned to a commit, not the movable tag (a tag can be repointed: supply-chain risk). Commit of the
// v4.4.0 tag (git ls-remote https://github.com/actions/checkout refs/tags/v4.4.0), as in this repository's workflows.
export const CHECKOUT_PIN = "11d5960a326750d5838078e36cf38b85af677262 # v4.4.0";

export interface TemplateOptions {
  kind: string; // the integration's scan type: sast, cbom, ai_bom
  endpoint: string; // full URL of POST /cicd/<kind>/scan
}

export const isCbom = (kind: string) => (kind || "").toLowerCase() === "cbom";

// Shown under every guide for a CBOM integration: what makes the generated job fail.
export const CBOM_GATE_NOTE =
  "The job fails when DevSecShield reports a high crypto finding (weak algorithm or key, ECB, hard-coded key, static " +
  "IV, reused nonce, weak RNG, weak padding, disabled certificate verification, a vulnerable crypto library) and when " +
  "no result arrives in time. Quantum-vulnerable findings are reported without failing the job. The job also fails " +
  "when DevSecShield cannot be reached, answers with an error or rejects a wrong or revoked API key. To make the " +
  "check advisory, mark the step continue-on-error (GitHub Actions), the job allow_failure (GitLab CI) or wrap the " +
  "stage in catchError (Jenkins).";

const kindOf = (kind: string) => (kind || "sast").toLowerCase();

export function githubActionsWorkflow({ kind: rawKind, endpoint, branch }: TemplateOptions & { branch: string }): string {
  const kind = kindOf(rawKind);
  const label = kind.toUpperCase();
  // Use string concatenation to avoid parsing ${{ }} as template literal syntax
  const githubActionsSecret = "${{ secrets.CICD_API_KEY }}";
  const scan = scanRequestScript({
    zipPath: "$RUNNER_TEMP/project.zip",
    url: endpoint,
    keyRef: "$CICD_API_KEY",
    responseFile: "response.json",
  });
  const workflow = `name: ${label} Check
on:
  push:
    branches: [ ${branch} ]  # Adjust this to your master branch name
  pull_request:
    branches: [ ${branch} ]  # Optionally run on PRs
jobs:
  ${kind}-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${CHECKOUT_PIN}

      # Everything but .git is scanned (vendored code, build output and nested archives included); installed
      # dependency trees stay out. The zip is written outside the workspace. Uploads are capped at 50 MB.
      - name: Create project zip
        run: |
          ${zipCommand("$RUNNER_TEMP/project.zip")}

      - name: Perform ${label} Scan
        id: ${kind}
        env:
          CICD_API_KEY: ${githubActionsSecret}
        run: |
${indent(scan, 10)}
          echo "${label} findings: $(jq '.finding_count // 0' response.json)"
          jq -r '(.results | if type == "object" then (.results // []) elif type == "array" then . else [] end)[] | (.impact // "unknown") + " " + (.title // .name // "")' response.json`;
  if (!isCbom(kind)) return workflow;
  return `${workflow}

      # Fails the job on a high crypto finding (weak algorithm or key, ECB, hard-coded key, static IV, reused nonce,
      # weak RNG, weak padding, disabled certificate verification, vulnerable crypto library), and when the answer
      # has no verdict. Quantum-vulnerable findings are reported, not blocked.
      - name: CBOM policy gate
        run: |
${indent(cbomGateDetailsJq("response.json"), 10)}
${indent(cbomGateScript("response.json"), 10)}`;
}

export function jenkinsfile({ kind: rawKind, endpoint, apiKey }: TemplateOptions & { apiKey: string }): string {
  const kind = kindOf(rawKind);
  const label = kind.toUpperCase();
  const zipPath = `${D}{WORKSPACE_TMP:-/tmp}/devsecshield-project.zip`;
  const scan = scanRequestScript({
    zipPath,
    url: `${D}{SCAN_API_URL}`,
    keyRef: `${D}{CICD_API_KEY}`,
    responseFile: "devsecshield-response.json",
  });
  const gateStage = isCbom(kind)
    ? `

        // Fails the build on a high crypto finding, and when the answer has no verdict (fail closed).
        stage('CBOM Policy Gate') {
            steps {
                script {
                    def jsonResponse = readJSON(file: 'devsecshield-response.json')
                    def gate = jsonResponse.containsKey('gate') ? jsonResponse.gate : null
                    if (gate instanceof Map) {
                        echo "${D}{gate.reason}"
                        (gate.failing ?: []).each { echo "${D}{it.impact} ${D}{it.codes} ${D}{it.location} ${D}{it.title}" }
                    }
                }
                sh '''#!/bin/sh
${cbomGateScript("devsecshield-response.json")}
'''
            }
        }`
    : "";
  return `pipeline {
    agent any

    environment {
        CICD_API_KEY = '${apiKey}'
        SCAN_API_URL = '${endpoint}'
    }

    stages {
        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        // Everything but .git is scanned (vendored code, build output and nested archives included); installed
        // dependency trees stay out. The zip is written outside the workspace. Uploads are capped at 50 MB.
        stage('Create ZIP File') {
            steps {
                sh '''#!/bin/sh
set -eu
rm -f "${zipPath}"
${zipCommand(zipPath)}
'''
            }
        }

        stage('Perform ${label} Scan') {
            steps {
                sh '''#!/bin/sh
${scan}
'''
                script {
                    def jsonResponse = readJSON(file: 'devsecshield-response.json')
                    def payload = jsonResponse.results
                    def findings = payload instanceof Map ? payload.results : payload

                    echo "Findings found during ${label}: ${D}{jsonResponse.finding_count}"
                    (findings ?: []).each { echo "${D}{it.impact} ${D}{it.title}" }

                    env.FINDINGS = jsonResponse.finding_count?.toString()
                }
            }
        }${gateStage}

        // Additional stages (e.g., deploy) can be added here
    }
}`;
}

export function bambooScript({ kind: rawKind, endpoint }: TemplateOptions): string {
  const kind = kindOf(rawKind);
  const label = kind.toUpperCase();
  const bambooVar = "bamboo";
  const scan = scanRequestScript({
    zipPath: `${D}{zip_file}`,
    url: endpoint,
    keyRef: `${D}{${bambooVar}.cicd_api_key}`,
    responseFile: "devsecshield-response.json",
  });
  const script = `# Everything but .git is scanned (vendored code, build output and nested archives included); installed
# dependency trees stay out. The zip is written outside the working directory. Uploads are capped at 50 MB.
zip_file="${D}(mktemp -d)/project.zip"
${zipCommand(`${D}{zip_file}`)}

# Call the API for ${label} scan
${scan}

FINDINGS=${D}(grep -o '"finding_count":[0-9]*' devsecshield-response.json | grep -o '[0-9]*' || echo "0")
echo "Findings found during ${label}: ${D}FINDINGS"
cat devsecshield-response.json`;
  if (!isCbom(kind)) return script;
  // echo: the compact JSON has no final newline, so the gate's message starts a line of its own
  return `${script}
echo

${cbomGateScript("devsecshield-response.json")}`;
}

export function gitlabCi({ kind: rawKind, endpoint, branch }: TemplateOptions & { branch: string }): string {
  const kind = kindOf(rawKind);
  const label = kind.toUpperCase();
  // A new directory per job: `zip -r` adds to an archive that already exists, and /tmp can outlive a job (shell
  // executor, several jobs on one host), so a fixed path would upload an earlier job's files too.
  const scan = scanRequestScript({
    zipPath: `${D}{zip_file}`,
    url: endpoint,
    keyRef: `${D}{CICD_API_KEY}`,
    responseFile: "devsecshield-response.json",
  });
  const body = [
    "# Everything but .git is scanned (vendored code, build output and nested archives included); installed",
    "# dependency trees stay out. The zip is written to a new directory outside the project. Uploads are capped at 50 MB.",
    `zip_file="${D}(mktemp -d)/project.zip"`,
    zipCommand(`${D}{zip_file}`),
    scan,
    `echo "${label} findings: ${D}(jq '.finding_count // 0' devsecshield-response.json)"`,
    `jq -r '(.results | if type == "object" then (.results // []) elif type == "array" then . else [] end)[] | (.impact // "unknown") + " " + (.title // .name // "")' devsecshield-response.json`,
    ...(isCbom(kind) ? [cbomGateDetailsJq("devsecshield-response.json"), cbomGateScript("devsecshield-response.json")] : []),
  ].join("\n");
  return `# DevSecShield ${label} scan for GitLab CI: add this job to .gitlab-ci.yml and the CI/CD variable CICD_API_KEY
# (Settings > CI/CD > Variables, masked).${isCbom(kind) ? " The job fails on a high crypto finding (CBOM policy gate)." : ""}
${kind}-check:
  image: alpine:3.22
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "${branch}"
  before_script:
    - apk add --no-cache curl jq zip
  script:
    - |
${indent(body, 6)}`;
}
