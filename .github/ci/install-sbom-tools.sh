#!/usr/bin/env bash
# Install the Syft and Grype the scan-worker image ships, for the worker test job (review 6028132826 M3: the PR's
# evidence came from Syft 1.18 / Grype 0.87 while the image runs 1.57 / 0.121, and the real-Syft tests skipped in CI).
#
# The versions and SHA-256 sums are read from RabbitMQ/worker/Dockerfile (ARG SYFT_VERSION, SYFT_SHA256_<ARCH>, ...),
# so CI cannot drift from the image. Binaries go to $RUNNER_TEMP/sbom-tools/bin (or ./.sbom-tools/bin), which is put
# on PATH for the following steps through $GITHUB_PATH. No Grype database is downloaded.
#
# Usage (repo root or any directory): bash .github/ci/install-sbom-tools.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dockerfile="${here}/../../RabbitMQ/worker/Dockerfile"
[ -f "${dockerfile}" ] || { echo "::error::${dockerfile} not found" >&2; exit 1; }

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "::error::no pinned syft/grype for $(uname -m)" >&2; exit 1 ;;
esac
ARCH_UPPER=$(printf '%s' "${arch}" | tr '[:lower:]' '[:upper:]')

arg() {  # the default of "ARG <name>=<value>" in the worker Dockerfile
  local value
  value=$(sed -n "s/^ARG ${1}=\(.*\)$/\1/p" "${dockerfile}" | head -n 1)
  [ -n "${value}" ] || { echo "::error::ARG ${1} not found in ${dockerfile}" >&2; exit 1; }
  printf '%s' "${value}"
}

dest="${RUNNER_TEMP:-$(pwd)/.sbom-tools}/sbom-tools/bin"
mkdir -p "${dest}"
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

for tool in syft grype; do
  upper=$(printf '%s' "${tool}" | tr '[:lower:]' '[:upper:]')
  version=$(arg "${upper}_VERSION")
  sum=$(arg "${upper}_SHA256_${ARCH_UPPER}")
  [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::bad ${tool} version ${version}" >&2; exit 1; }
  [[ "${sum}" =~ ^[0-9a-f]{64}$ ]] || { echo "::error::bad ${tool} sha256" >&2; exit 1; }
  file="${tool}_${version}_linux_${arch}.tar.gz"
  curl -sSfL --retry 3 -o "${work}/${file}" "https://github.com/anchore/${tool}/releases/download/v${version}/${file}"
  printf '%s  %s\n' "${sum}" "${work}/${file}" | sha256sum -c - >/dev/null
  tar -xzf "${work}/${file}" -C "${dest}" "${tool}"
  "${dest}/${tool}" version | sed -n '1,2p'
done

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "${dest}" >> "${GITHUB_PATH}"
fi
# the worker's tests run Syft offline: no update checks, no database download
if [ -n "${GITHUB_ENV:-}" ]; then
  {
    echo "SYFT_CHECK_FOR_APP_UPDATE=false"
    echo "GRYPE_CHECK_FOR_APP_UPDATE=false"
    echo "GRYPE_DB_AUTO_UPDATE=false"
  } >> "${GITHUB_ENV}"
fi
echo "syft and grype pinned to RabbitMQ/worker/Dockerfile: ${dest}"
