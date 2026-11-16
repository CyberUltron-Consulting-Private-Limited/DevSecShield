#!/bin/sh
# Build the zs-collect one-file binary, then write and (optionally) sign the release manifest.
#
#   scan_node/zs_collect/build.sh <version> [out-dir]
#     ARCH=amd64|arm64        architecture to build (default amd64; arm64 needs docker buildx with QEMU)
#     BASE_IMAGE=...          builder base image (default: the digest-pinned one in Dockerfile.build)
#     SIGNING_KEY=<file>      Ed25519 release key (offline); without it the manifest is written but not signed
#
# Output: <out-dir>/zs-collect-<version>-linux-<arch>, zs-collect-<version>.manifest.json (+ .sig when signed).
set -eu
VERSION="${1:?usage: build.sh <version> [out-dir]}"
OUT="${2:-dist}"
ARCH="${ARCH:-amd64}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NODE="$(cd "$HERE/.." && pwd)"
case "$ARCH" in amd64|arm64) ;; *) echo "ARCH must be amd64 or arm64" >&2; exit 2 ;; esac
grep -q "^VERSION = \"$VERSION\"$" "$NODE/zs_scan_node/__init__.py" || {
  echo "zs_scan_node.VERSION is not $VERSION (the binary reports that version)" >&2; exit 2; }
mkdir -p "$OUT"
TAG="zs-collect-build:$VERSION-$ARCH"
set -- --platform "linux/$ARCH" -f "$HERE/Dockerfile.build" -t "$TAG"
[ -n "${BASE_IMAGE:-}" ] && set -- "$@" --build-arg "BASE_IMAGE=$BASE_IMAGE"
[ -n "${HTTPS_PROXY:-}" ] && set -- "$@" --build-arg "HTTPS_PROXY=$HTTPS_PROXY" --build-arg "https_proxy=$HTTPS_PROXY" \
  --build-arg APT_HTTPS=1 --network host
docker build "$@" "$NODE"
CID="$(docker create "$TAG")"
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT
docker cp "$CID:/build/dist/zs-collect" "$OUT/zs-collect-$VERSION-linux-$ARCH"
chmod 0755 "$OUT/zs-collect-$VERSION-linux-$ARCH"
COMMIT="$(git -C "$NODE" rev-parse HEAD)"
PY="${PYTHON:-python3}"
"$PY" "$HERE/release.py" manifest --version "$VERSION" --git-commit "$COMMIT" \
  --out "$OUT/zs-collect-$VERSION.manifest.json" "$OUT"/zs-collect-"$VERSION"-linux-*
if [ -n "${SIGNING_KEY:-}" ]; then
  "$PY" "$HERE/release.py" sign --key "$SIGNING_KEY" "$OUT/zs-collect-$VERSION.manifest.json"
  "$PY" "$HERE/release.py" verify --public "$HERE/zs-release-ed25519.pub" --files "$OUT" \
    "$OUT/zs-collect-$VERSION.manifest.json"
fi
