#!/usr/bin/env bash
# init-env.sh - create deploy/local/.env from .env.example with a fresh random value for every `change-me`
# (deploy/local/README.md). Refuses to overwrite an existing .env. Needs openssl. Prints no secret.
#
#   deploy/local/init-env.sh [DSS_TAG]      e.g. deploy/local/init-env.sh pr-93
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE="${DIR}/.env.example"
OUT="${DIR}/.env"

die() { printf 'init-env: %s\n' "$*" >&2; exit 1; }

[[ -f "${EXAMPLE}" ]] || die "missing ${EXAMPLE}"
[[ ! -e "${OUT}" ]] || die "${OUT} exists; remove it first (docker compose down -v also drops the data made with it)"
command -v openssl >/dev/null || die "openssl is needed"
tag="${1:-}"
[[ -z "${tag}" || "${tag}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die "not a tag: ${tag}"

value_for() { # <key>: a random value of the shape the key needs
  case "$1" in
    # Fernet: urlsafe base64 of 32 random bytes.
    ENCRYPTION_KEY) openssl rand -base64 32 | tr '+/' '-_' ;;
    JWT_SECRET_KEY | JWT_REFRESH_SECRET_KEY) openssl rand -hex 32 ;;
    *) openssl rand -hex 20 ;;
  esac
}

umask 077
tmp="$(mktemp "${DIR}/.env.XXXXXX")"
trap 'rm -f "${tmp}"' EXIT
n=0
while IFS= read -r line || [[ -n "${line}" ]]; do
  if [[ "${line}" =~ ^([A-Z][A-Z0-9_]*)=change-me$ ]]; then
    printf '%s=%s\n' "${BASH_REMATCH[1]}" "$(value_for "${BASH_REMATCH[1]}")"
    n=$((n + 1))
  elif [[ -n "${tag}" && "${line}" =~ ^DSS_TAG= ]]; then
    printf 'DSS_TAG=%s\n' "${tag}"
  else
    printf '%s\n' "${line}"
  fi
done <"${EXAMPLE}" >"${tmp}"
grep -q '=change-me$' "${tmp}" && die "a change-me placeholder is left in ${tmp}"
chmod 600 "${tmp}"
mv "${tmp}" "${OUT}"
trap - EXIT
printf 'init-env: wrote %s (mode 600) with %d generated values; DSS_TAG=%s\n' "${OUT}" "${n}" \
  "$(sed -n 's/^DSS_TAG=//p' "${OUT}")"
