#!/bin/sh
# Check the exact Alpine package pins of the lab images against the repository today (Alpine keeps only the newest
# build of a package per branch, so a pin breaks when the branch moves: 16.15-r0 -> 16.16-r0 broke the tools image on
# 2026-11-14). Runs the pinned base image, reads `apk policy` for every `name=version` the Dockerfiles install and
# prints one line per package: OK, or MISSING with the version the branch has now. Exit 1 when a pin is missing.
#   e2e/cbom/lab/images/apk-pins.sh            # behind a TLS-intercepting proxy: CB_LAB_BUILD_CA=<ca.pem>
set -eu
here=$(cd "$(dirname "$0")" && pwd)
base=$(sed -n 's/^FROM \${REGISTRY}\/\(alpine:[^ ]*\).*/\1/p' "$here/tools.Dockerfile" | head -n 1)
registry=${CB_LAB_REGISTRY:-mirror.gcr.io/library}
pins=$(sed -n 's/^ *\([a-z0-9][a-z0-9.+_-]*\)=\([0-9][^ \\]*\).*/\1=\2/p' "$here/tools.Dockerfile" "$here/target.Dockerfile" \
  | sort -u)
set -- --rm -e PINS="$pins"
if [ -n "${HTTPS_PROXY:-}" ]; then set -- "$@" --network host -e HTTPS_PROXY="$HTTPS_PROXY"; fi
if [ -n "${CB_LAB_BUILD_CA:-}" ]; then set -- "$@" -e SSL_CERT_FILE=/ca.pem -v "$CB_LAB_BUILD_CA:/ca.pem:ro"; fi
exec docker run "$@" "$registry/$base" sh -c '
apk update -q >/dev/null 2>&1 || { echo "apk update failed" >&2; exit 2; }
rc=0
for pin in $PINS; do
  name=${pin%%=*}; want=${pin#*=}
  have=$(apk policy "$name" 2>/dev/null | sed -n "2s/^ *\([^:]*\):.*/\1/p")
  if [ "$have" = "$want" ]; then echo "OK      $name=$want"; else echo "MISSING $name=$want (repository: ${have:-none})"; rc=1; fi
done
exit $rc'
