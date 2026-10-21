#!/usr/bin/env bash
# build_trees.sh - assemble the ephemeral scan trees the E2E seed scans (plan 7.4 step 1, Appendix B).
#
# Output: e2e/.work/trees/<tree>/ (mounted read-only into the aibom-scan container) and an empty
# e2e/.work/out/ (where the scanner writes <tree>.scan_data.json). Both are recreated on every run:
# the authored certificates are dated relative to TODAY so the expired / near-expiry bands stay
# valid for the whole run.
#
#   tree                  = frozen aibom fixture (+ additions)                         Appendix-B scan
#   payments-service-v1   = synthetic-crypto-app                                       #1
#   payments-service-v2   = synthetic-crypto-app + deploy/tls/server.crt (chain-leaf)   #2
#   identity-gateway      = synthetic-crypto-certs + certs/imported/payments-ca.pem    #3  (= app cert.pem)
#   crypto-misuse-lab     = synthetic-crypto-misuse                                    #4
#   pqc-pilot             = synthetic-crypto-pqc                                       #5
#   cert-lifecycle-lab    = authored expired.crt (-35 d) + expiring-soon.crt (+20 d)   #6
#   vendor-sdk-manifests  = synthetic-crypto-manifests                                 #7
#   other-team-app        = authored other-team-canary.crt (team 2 only)               T2
# (#8 legacy-billing is the committed Tier-B JSON, not a tree. vendor/ is never used: the
# certificate scanner skips it, plan R-07.)
#
# The copies exclude only __pycache__ and *.pyc, exactly like the WP1a fixture generator, so the
# scan results match the Appendix-B oracle. Nothing under aibom/tests/fixtures is modified. The
# certificates are authored with the openssl CLI: an authoring-time tool, not a product dependency.
#
# Self-check (independent of the product): 17 certificate files across the team-1 trees must yield
# 14 unique DER SHA-256 fingerprints (`openssl x509 -fingerprint -sha256`), and the validity bands
# are derived with `openssl x509 -checkend`.
set -euo pipefail
# shellcheck source=../scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/lib.sh"

FIXTURES="${REPO_ROOT}/aibom/tests/fixtures"
KEY_TMP=""
cleanup() {
  # The throw-away authoring keys live under .work/ so the guarded delete helper covers them.
  if [[ -n "${KEY_TMP}" && -d "${KEY_TMP}" ]]; then
    safe_rm_rf "${KEY_TMP}"
  fi
}
trap cleanup EXIT

copy_tree() { # <fixture dir> <tree name>
  local src="${FIXTURES}/$1" dst="${E2E_TREES_DIR}/$2"
  [[ -d "${src}" ]] || die "fixture directory missing: ${src}"
  mkdir -p "${dst}"
  tar -C "${src}" --exclude='__pycache__' --exclude='*.pyc' -cf - . | tar -C "${dst}" -xf -
}

# date_stamp <offset like "-35 days"> -> YYYYMMDD000000Z (UTC midnight, openssl -not_before/-not_after)
date_stamp() { date -u -d "${TODAY} $1" +%Y%m%d000000Z; }

# author_cert <outfile> <CN> <not_before> <not_after>
# Self-signed leaf: RSA-2048, sha256WithRSAEncryption, O=DevSecShield-E2E, CA:FALSE (openssl defaults
# to CA:TRUE, which would hide SELF_SIGNED_LEAF). The private key goes to a temp dir that is wiped on
# exit; it is never written into a tree.
author_cert() {
  openssl req -x509 -newkey rsa:2048 -sha256 -noenc -keyout "${KEY_TMP}/k.pem" \
    -subj "/O=DevSecShield-E2E/CN=$2" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -not_before "$3" -not_after "$4" -out "$1" 2>/dev/null
}

# cert_band <file> -> expired | le30 | le90 | valid   (relative to now, via openssl -checkend)
cert_band() {
  if ! openssl x509 -in "$1" -noout -checkend 0 >/dev/null 2>&1; then
    echo expired
  elif ! openssl x509 -in "$1" -noout -checkend $((30 * 86400)) >/dev/null 2>&1; then
    echo le30
  elif ! openssl x509 -in "$1" -noout -checkend $((90 * 86400)) >/dev/null 2>&1; then
    echo le90
  else
    echo valid
  fi
}

main() {
  need_cmd openssl tar date find sha256sum sort awk
  openssl req -help 2>&1 | grep -q -- '-not_before' || die "openssl req lacks -not_before/-not_after (OpenSSL >= 3.4 needed)"
  [[ -d "${FIXTURES}" ]] || die "aibom fixtures not found: ${FIXTURES}"

  TODAY="$(date -u +%F)"
  log "building scan trees for ${TODAY} (UTC) into ${E2E_TREES_DIR#"${REPO_ROOT}"/}"

  safe_rm_rf "${E2E_TREES_DIR}"
  safe_rm_rf "${E2E_OUT_DIR}"
  safe_rm_rf "${E2E_WORK_DIR}/trees.manifest.sha256"
  mkdir -p "${E2E_TREES_DIR}" "${E2E_OUT_DIR}"
  KEY_TMP="$(mktemp -d "${E2E_WORK_DIR}/keys.XXXXXX")"

  # --- tree copies from the frozen fixtures ---
  copy_tree synthetic-crypto-app payments-service-v1
  copy_tree synthetic-crypto-app payments-service-v2
  copy_tree synthetic-crypto-certs identity-gateway
  copy_tree synthetic-crypto-misuse crypto-misuse-lab
  copy_tree synthetic-crypto-pqc pqc-pilot
  copy_tree synthetic-crypto-manifests vendor-sdk-manifests

  # --- additions that turn single-fixture trees into the Appendix-B scans ---
  mkdir -p "${E2E_TREES_DIR}/payments-service-v2/deploy/tls"
  cp "${FIXTURES}/synthetic-crypto-certs/chain-leaf.crt" "${E2E_TREES_DIR}/payments-service-v2/deploy/tls/server.crt"
  mkdir -p "${E2E_TREES_DIR}/identity-gateway/certs/imported"
  cp "${FIXTURES}/synthetic-crypto-app/cert.pem" "${E2E_TREES_DIR}/identity-gateway/certs/imported/payments-ca.pem"

  # --- authored certificates (dated relative to today) ---
  mkdir -p "${E2E_TREES_DIR}/cert-lifecycle-lab" "${E2E_TREES_DIR}/other-team-app"
  author_cert "${E2E_TREES_DIR}/cert-lifecycle-lab/expired.crt" expired-api.e2e.test \
    "$(date_stamp '-400 days')" "$(date_stamp '-35 days')"
  author_cert "${E2E_TREES_DIR}/cert-lifecycle-lab/expiring-soon.crt" expiring-soon.e2e.test \
    "$(date_stamp '-345 days')" "$(date_stamp '+20 days')"
  author_cert "${E2E_TREES_DIR}/other-team-app/other-team-canary.crt" other-team-canary.test \
    "$(date_stamp '-30 days')" "$(date_stamp '+730 days')"

  chmod -R u=rwX,go=rX "${E2E_TREES_DIR}"

  # --- self-check: independent oracle over the certificate FILES of the team-1 trees ---
  local tree file fp subject not_after band
  local files=0 expired=0 le30=0 le90=0 valid=0
  declare -A seen_fp=()
  log "certificate files in the team-1 trees (openssl view):"
  while IFS= read -r file; do
    tree="${file#"${E2E_TREES_DIR}/"}"
    tree="${tree%%/*}"
    [[ "${tree}" == "other-team-app" ]] && continue
    grep -q 'BEGIN CERTIFICATE' "${file}" || continue
    fp="$(openssl x509 -in "${file}" -noout -fingerprint -sha256 | sed 's/^.*=//; s/://g' | tr 'A-F' 'a-f')"
    subject="$(openssl x509 -in "${file}" -noout -subject -nameopt multiline | awk -F'= *' '/commonName/ {print $2}')"
    not_after="$(openssl x509 -in "${file}" -noout -enddate | sed 's/^notAfter=//')"
    files=$((files + 1))
    if [[ -z "${seen_fp[${fp}]:-}" ]]; then
      band="$(cert_band "${file}")"
      seen_fp["${fp}"]="${tree}/${file#"${E2E_TREES_DIR}/${tree}/"}"
      case "${band}" in
        expired) expired=$((expired + 1)) ;;
        le30) le30=$((le30 + 1)) ;;
        le90) le90=$((le90 + 1)) ;;
        valid) valid=$((valid + 1)) ;;
      esac
    fi
    printf '  %-22s %-44s CN=%-26s notAfter=%s sha256=%s\n' \
      "${tree}" "${file#"${E2E_TREES_DIR}/${tree}/"}" "${subject:-?}" "${not_after}" "${fp:0:16}"
  done < <(find "${E2E_TREES_DIR}" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.cer' \) | LC_ALL=C sort)

  local unique=${#seen_fp[@]}
  log "team-1 certificate files: ${files} (expected 17); unique SHA-256 fingerprints: ${unique} (expected 14)"
  log "validity bands over the ${unique} unique certs: expired=${expired} le30=${le30} le90=${le90} valid=${valid} (Appendix B at authoring time: 1 / 1 / 0 / 12)"

  [[ "${files}" -eq 17 ]] || die "expected 17 certificate files in the team-1 trees, found ${files}"
  [[ "${unique}" -eq 14 ]] || die "expected 14 unique certificate fingerprints, found ${unique} (dedupe oracle broken)"
  # The authored certs are the only date-relative ones: they must land in exactly these bands.
  [[ "$(cert_band "${E2E_TREES_DIR}/cert-lifecycle-lab/expired.crt")" == expired ]] || die "expired.crt is not expired"
  [[ "$(cert_band "${E2E_TREES_DIR}/cert-lifecycle-lab/expiring-soon.crt")" == le30 ]] || die "expiring-soon.crt is not in the <=30 day band"
  [[ "$(cert_band "${E2E_TREES_DIR}/other-team-app/other-team-canary.crt")" == valid ]] || die "other-team-canary.crt is not valid"
  if [[ "${expired}" -ne 1 || "${le30}" -ne 1 || "${le90}" -ne 0 || "${valid}" -ne 12 ]]; then
    warn "fixture certificate validity drifted from Appendix B (a frozen fixture cert is now within 90 days of expiry or expired): expected.json band counts must be re-derived"
  fi

  # No private key material may have leaked into a tree from the authoring step.
  if find "${E2E_TREES_DIR}" -name 'k.pem' | grep -q .; then
    die "authoring key leaked into a tree"
  fi

  # Content manifest (outside the trees: everything inside them is scanned).
  (cd "${E2E_TREES_DIR}" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) >"${E2E_WORK_DIR}/trees.manifest.sha256"
  log "trees: $(find "${E2E_TREES_DIR}" -mindepth 1 -maxdepth 1 -type d | wc -l) directories, $(find "${E2E_TREES_DIR}" -type f | wc -l) files; manifest ${E2E_WORK_DIR#"${REPO_ROOT}"/}/trees.manifest.sha256"
  for tree in $(find "${E2E_TREES_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | LC_ALL=C sort); do
    log "  ${tree}: $(find "${E2E_TREES_DIR}/${tree}" -type f | wc -l) files"
  done
  log "build_trees: OK"
}

main "$@"
