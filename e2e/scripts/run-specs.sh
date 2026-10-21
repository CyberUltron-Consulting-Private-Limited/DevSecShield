#!/usr/bin/env bash
# run-specs.sh - run the Playwright specs against the running, seeded stack.
#
# Sequential, headless Chromium from the browser cache that already exists on this VM. The pinned
# toolchain is installed with `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci`; `playwright install` is
# NEVER run, and the cache listing is compared before/after to prove nothing was downloaded.
#
# Usage: run-specs.sh [playwright test args...]
#   run-specs.sh                                        all specs
#   run-specs.sh specs/07-certificate-estate-register.spec.ts      one deliverable, independently
#
# Pacing: the backend limiter allows 30 downloads per 60 s per token, so specs must leave >= 1.5 s
# between PDF downloads (specs/lib concern; this script does not throttle).
# Logs: <evidence>/logs/04-specs.txt, playwright-cache-after.txt; reports in <evidence>/reports/
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Prints "<dir name>" for each browser revision the installed Playwright declares it needs.
declared_browser_dirs() {
  node -e '
    const b = require("./node_modules/playwright-core/browsers.json").browsers;
    for (const name of ["chromium", "chromium-headless-shell", "ffmpeg"]) {
      const e = b.find((x) => x.name === name);
      if (!e) { console.error("browsers.json has no " + name); process.exit(1); }
      console.log(name.replace(/-/g, "_") + "-" + e.revision);
    }
  '
}

main() {
  banner "run-specs"
  need_cmd node npm npx
  local ev cache
  ev="$(e2e_evidence_dir)"
  cache="${PLAYWRIGHT_BROWSERS_PATH:-${HOME}/.cache/ms-playwright}"

  http_ok "${E2E_API_URL}/docs" || die "backend is not answering 200 at ${E2E_API_URL}/docs: run scripts/up.sh first"
  http_ok "${E2E_BASE_URL}/login" || die "frontend is not answering 200 at ${E2E_BASE_URL}/login: run scripts/up.sh first"
  [[ -s "${E2E_WORK_DIR}/seed.json" ]] || die "${E2E_WORK_DIR#"${REPO_ROOT}"/}/seed.json is missing: run scripts/seed.sh first"

  cd "${E2E_ROOT}"
  if [[ ! -d node_modules/@playwright/test || package-lock.json -nt node_modules/.package-lock.json ]]; then
    log "installing the pinned toolchain (npm ci, browser download disabled)"
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci --no-audit --no-fund
  fi

  local version
  version="$(npx --no-install playwright --version)"
  log "${version}"
  [[ "${version}" == "Version ${E2E_PLAYWRIGHT_VERSION}" ]] || die "expected Playwright ${E2E_PLAYWRIGHT_VERSION}, got '${version}'"

  # The cached browsers must be exactly the revisions this Playwright expects: otherwise it would try
  # to download (we never allow that) or fail late.
  local dir
  while IFS= read -r dir; do
    [[ -d "${cache}/${dir}" ]] || die "browser cache lacks ${dir}, which Playwright ${E2E_PLAYWRIGHT_VERSION} declares; do NOT run playwright install here"
    log "browser cache has ${dir}"
  done < <(declared_browser_dirs)

  list_dir_names "${cache}" >"$(e2e_log_file playwright-cache-before-run.txt)"

  e2e_prepare_evidence_dirs
  export E2E_EVIDENCE_DIR="${ev}" E2E_BASE_URL E2E_API_URL E2E_WORK_DIR PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
  export E2E_SEED_JSON="${E2E_WORK_DIR}/seed.json"

  local rc=0
  npx --no-install playwright test "$@" || rc=$?

  list_dir_names "${cache}" >"$(e2e_log_file playwright-cache-after.txt)"
  # Prefer preflight's listing (taken before anything ran) as the baseline.
  local baseline
  baseline="$(e2e_log_file playwright-cache-before.txt)"
  [[ -f "${baseline}" ]] || baseline="$(e2e_log_file playwright-cache-before-run.txt)"
  if diff -q "${baseline}" "$(e2e_log_file playwright-cache-after.txt)" >/dev/null; then
    log "browser cache identical before and after (nothing was downloaded): $(basename "${baseline}") == playwright-cache-after.txt"
  else
    warn "browser cache CHANGED: $(diff "${baseline}" "$(e2e_log_file playwright-cache-after.txt)" | tr '\n' ' ')"
    rc=1
  fi
  log "playwright exit code: ${rc}"
  return "${rc}"
}

e2e_prepare_evidence_dirs
: >"$(e2e_log_file 04-specs.txt)"
run_logged "$(e2e_log_file 04-specs.txt)" main "$@"
