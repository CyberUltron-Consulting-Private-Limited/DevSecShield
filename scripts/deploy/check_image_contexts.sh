#!/usr/bin/env bash
# check_image_contexts.sh - prove that no secret file can enter any DevSecShield image build context.
#
# For each image it sends the real build context, filtered by the real ignore file (the context's .dockerignore, or
# <Dockerfile>.dockerignore when one sits next to the Dockerfile, as BuildKit does), to a throw-away build stage that
# only lists the files it received, and checks the listing:
#   * no .env / .env.* (except .env.example), *.pem, *.key or cu-devsecshield-key*, no .venv/ or node_modules/;
#   * the files the real Dockerfile needs are present (an over-eager ignore rule would break the build).
# Canary files (.env.zs-canary, zs-canary.pem, at the context root and one level down) are planted for the run and
# removed afterwards; the tracked .env files and the root SSH key are natural canaries too. Nothing is built or kept.
#
# Usage: scripts/deploy/check_image_contexts.sh     (needs docker buildx and the alpine:3.20 image)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
CANARIES=()
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  local f
  for f in "${CANARIES[@]}"; do rm -f "${f}"; done
  rm -rf "${WORK}"
}
trap cleanup EXIT

# name | Dockerfile | context | files the Dockerfile needs (space-separated, relative to the context)
TARGETS=(
  "backend|backend/Dockerfile|backend|main.py pyproject.toml uv.lock docker-entrypoint.sh new_models.py"
  "frontend|frontend/Dockerfile|frontend|package.json package-lock.json next.config.ts app/layout.tsx"
  "scan-worker|RabbitMQ/worker/Dockerfile|.|aibom/pyproject.toml aibom/README.md aibom/src/aibom/__init__.py aibom/config RabbitMQ/worker/pyproject.toml RabbitMQ/worker/uv.lock RabbitMQ/worker/scan_worker.py"
  "dast-worker|RabbitMQ/dast_worker/Dockerfile|RabbitMQ/dast_worker|pyproject.toml uv.lock dast_worker.py"
  "guardrail-worker|RabbitMQ/guardrail_worker/Dockerfile|RabbitMQ/guardrail_worker|pyproject.toml uv.lock guardrail_worker.py"
  "scan-node|scan_node/Dockerfile|scan_node|requirements.txt requirements.lock zs_scan_node/__main__.py"
)

plant() { # <dir>: canaries at the root and in the first sub-directory
  local d=$1 sub f
  sub="$(find "${d}" -mindepth 1 -maxdepth 1 -type d ! -name '.*' ! -name node_modules | sort | head -n 1)"
  for f in "${d}/.env.zs-canary" "${d}/zs-canary.pem" ${sub:+"${sub}/.env.zs-canary"} ${sub:+"${sub}/zs-canary.pem"}; do
    [[ -e "${f}" ]] && continue
    printf 'ZS_CANARY=not-a-secret\n' >"${f}"
    CANARIES+=("${f}")
  done
}

fail=0
for t in "${TARGETS[@]}"; do
  IFS='|' read -r name dockerfile ctx needs <<<"${t}"
  dir="${WORK}/${name}"
  mkdir -p "${dir}/out"
  printf 'FROM alpine:3.20 AS list\nCOPY . /ctx\nRUN cd /ctx && find . -mindepth 1 | sed "s|^\\./||" | sort > /listing.txt\nFROM scratch\nCOPY --from=list /listing.txt /\n' \
    >"${dir}/Dockerfile"
  [[ -f "${REPO_ROOT}/${dockerfile}.dockerignore" ]] && cp "${REPO_ROOT}/${dockerfile}.dockerignore" "${dir}/Dockerfile.dockerignore"
  if [[ "${ctx}" == "." ]]; then plant "${REPO_ROOT}"; plant "${REPO_ROOT}/RabbitMQ/worker"; else plant "${REPO_ROOT}/${ctx}"; fi
  docker buildx build --quiet --network none --output "type=local,dest=${dir}/out" -f "${dir}/Dockerfile" \
    "${REPO_ROOT}/${ctx}" >/dev/null
  listing="${dir}/out/listing.txt"
  leaks="$(grep -E '(^|/)(\.env(\.[^/]*)?|[^/]*\.pem|[^/]*\.key|cu-devsecshield-key[^/]*)$|(^|/)(\.venv|node_modules)(/|$)' "${listing}" |
    grep -vE '(^|/)\.env\.example$' || true)"
  missing=""
  for f in ${needs}; do grep -qxF -- "${f}" "${listing}" || missing+=" ${f}"; done
  if [[ -n "${leaks}" || -n "${missing}" ]]; then
    fail=1
    printf 'FAIL %-17s context %-26s %5d entries\n' "${name}" "${ctx}" "$(wc -l <"${listing}")"
    # shellcheck disable=SC2001 # indent every line of a multi-line listing
    [[ -n "${leaks}" ]] && printf '     would enter the image:\n%s\n' "$(sed 's/^/       /' <<<"${leaks}")"
    [[ -n "${missing}" ]] && printf '     needed by the Dockerfile but excluded:%s\n' "${missing}"
  else
    printf 'PASS %-17s context %-26s %5d entries, no .env/.pem/.key/.venv/node_modules, needed files present\n' \
      "${name}" "${ctx}" "$(wc -l <"${listing}")"
  fi
done
printf '%d canary files were planted and removed\n' "${#CANARIES[@]}"
exit "${fail}"
