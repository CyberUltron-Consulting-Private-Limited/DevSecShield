// Shell shared by the CI/CD files the integration guides generate (GitHub Actions, Jenkins, Bamboo). It behaves like
// the reference templates in cicd_workflow_files/ (scripts verified against a fake API there):
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

export function indent(text: string, spaces: number): string {
  const pad = " ".repeat(spaces);
  return text
    .split("\n")
    .map((line) => (line ? pad + line : line))
    .join("\n");
}
