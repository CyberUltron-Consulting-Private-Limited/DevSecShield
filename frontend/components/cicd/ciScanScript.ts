// Shell shared by the CI/CD files the integration guides generate (ciTemplates.ts: GitHub Actions, Jenkins, Bamboo,
// GitLab CI). It behaves like the reference templates in cicd_workflow_files/ (ciTemplates.test.ts runs the generated
// files against a fake API):
//   * everything but .git is zipped: vendored code, build output and nested archives are handled by DevSecShield;
//     installed dependency trees (node_modules, virtualenvs) stay out, their manifests and lockfiles are scanned;
//   * curl --fail-with-body (curl 7.76+): a failed scan fails the pipeline and the reason is printed;
//   * 429 (rate limited): wait Retry-After seconds (30 if absent, 300 at most) and retry, up to 5 tries.
// POSIX sh only (Bamboo script tasks run /bin/sh).

const D = "$"; // writes a shell "${" without starting a JS template interpolation

export const CI_ZIP_EXCLUDES = "'.git/*' '*/.git/*' 'node_modules/*' '*/node_modules/*' 'venv/*' '.venv/*' '*/.venv/*'";

export function zipCommand(zipPath: string): string {
  return `zip -q -r "${zipPath}" . -x ${CI_ZIP_EXCLUDES}`;
}

export interface ScanRequestOptions {
  zipPath: string; // shell expression of the zip file
  url: string; // shell expression or literal URL of POST /cicd/<type>/scan
  keyRef: string; // shell expression of the CI/CD API key
  responseFile: string; // where the JSON answer is written
}

export function scanRequestScript({ zipPath, url, keyRef, responseFile }: ScanRequestOptions): string {
  return [
    "set -u",
    "# A failed scan fails the pipeline: --fail-with-body (curl 7.76+) exits non-zero on any HTTP error and still",
    "# prints the reason. 429 (rate limited): wait Retry-After seconds (30 if absent, 300 at most), up to 5 tries.",
    "for attempt in 1 2 3 4 5; do",
    "  rc=0",
    `  code=${D}(curl --fail-with-body -sS --max-time 900 -o ${responseFile} -D devsecshield-headers.txt -w '%{http_code}' \\`,
    `    -H "cicd-api-key: ${keyRef}" -F "zip_file=@${zipPath}" \\`,
    `    "${url}") || rc=${D}?`,
    `  if [ "${D}{code}" = "429" ] && [ "${D}{attempt}" -lt 5 ]; then`,
    `    delay=${D}(awk 'tolower(${D}1) == "retry-after:" {print ${D}2 + 0}' devsecshield-headers.txt | tail -n 1)`,
    `    [ -n "${D}{delay}" ] && [ "${D}{delay}" -gt 0 ] || delay=30`,
    `    [ "${D}{delay}" -le 300 ] || delay=300`,
    `    echo "DevSecShield is rate limiting this key; retrying in ${D}{delay}s (attempt ${D}{attempt} of 5)"`,
    `    sleep "${D}{delay}"`,
    "    continue",
    "  fi",
    "  break",
    "done",
    `if [ "${D}{rc}" -ne 0 ]; then`,
    `  echo "DevSecShield scan failed (curl exit ${D}{rc}, HTTP ${D}{code:-none}):"`,
    `  cat ${responseFile} 2>/dev/null || true`,
    "  exit 1",
    "fi",
  ].join("\n");
}

// CBOM policy gate (POSIX sh, grep only: no jq on Bamboo / Jenkins agents). POST /cicd/cbom/scan answers
// "gate_failed":true when the tree has a high crypto finding (the code-scan CLI's codes: weak algorithm or key, ECB,
// hard-coded key, static IV, reused nonce, weak RNG, weak padding, disabled certificate verification, vulnerable crypto
// library) and also when no result arrived in time. The answer is compact JSON, and text inside a JSON string has its
// quotes escaped, so only the top-level key can match. "true" is tested first; an answer with neither value (an older
// server, a cut-off body) fails the job too.
export function cbomGateScript(responseFile: string): string {
  return [
    "# CBOM policy gate: fail on a high crypto finding, and fail closed when the answer carries no verdict.",
    `if grep -Eq '"gate_failed"[[:space:]]*:[[:space:]]*true' ${responseFile}; then`,
    '  echo "DevSecShield CBOM policy gate: FAILED (high crypto findings, or no result in time; see the list above and the CI/CD page)"',
    "  exit 1",
    `elif grep -Eq '"gate_failed"[[:space:]]*:[[:space:]]*false' ${responseFile}; then`,
    '  echo "DevSecShield CBOM policy gate: passed (no high crypto finding)"',
    "else",
    '  echo "DevSecShield CBOM policy gate: the answer has no verdict, so the job fails (fail closed)"',
    "  exit 1",
    "fi",
  ].join("\n");
}

// jq lines printing the gate's reason and its failing findings (GitHub Actions and GitLab CI, where jq is present).
export function cbomGateDetailsJq(responseFile: string): string {
  return [
    `jq -r '.gate.reason // "No CBOM policy verdict in the answer."' ${responseFile}`,
    `jq -r '.gate.failing[]? | "\\(.impact // "High") \\(.codes | join(",")) \\(.location)\\(if .line then ":\\(.line)" else "" end) \\(.title)"' ${responseFile}`,
  ].join("\n");
}

export function indent(text: string, spaces: number): string {
  const pad = " ".repeat(spaces);
  return text
    .split("\n")
    .map((line) => (line ? pad + line : line))
    .join("\n");
}
