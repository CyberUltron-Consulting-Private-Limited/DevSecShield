#!/usr/bin/env python3
"""zs-collect release tooling: manifest, Ed25519 signature, verification and the launcher the transports embed.

    release.py keygen   --private KEY --public PUB          (offline machine; the private key never enters the repo)
    release.py manifest --version V --git-commit SHA --out DIR/zs-collect-V.manifest.json BINARY...
    release.py sign     --key KEY MANIFEST                   -> MANIFEST.sig (base64 of the raw 64-byte signature)
    release.py verify   --public PUB MANIFEST [--files DIR]  (signature, then each binary's sha256 and size)
    release.py wrapper  --public PUB MANIFEST --out zs-collect-run.sh
    release.py fingerprint PUB

Binaries are named ``zs-collect-<version>-linux-<amd64|arm64>``.  The manifest is canonical JSON (sorted keys, no
spaces) so the bytes that are signed are stable.  OpenSSL 3 checks the same signature:
``openssl pkeyutl -verify -rawin -pubin -inkey PUB -in MANIFEST -sigfile <(base64 -d MANIFEST.sig)``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

MANIFEST_FORMAT = "zs-collect-manifest/1"
NAME_RE = re.compile(r"^zs-collect-(?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)-linux-(?P<arch>amd64|arm64)$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?$")


class VerifyError(Exception):
    pass


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def keygen(private_path: Path, public_path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    Path(public_path).write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                                serialization.PublicFormat.SubjectPublicKeyInfo))


def build_manifest(binaries: list[Path], version: str, git_commit: str) -> dict:
    if not VERSION_RE.match(version):
        raise ValueError(f"bad version {version}")
    if not re.fullmatch(r"[0-9a-f]{40}", git_commit):
        raise ValueError("git_commit must be a full 40-character commit id")
    files = []
    for path in sorted(binaries, key=lambda p: Path(p).name):
        m = NAME_RE.match(Path(path).name)
        if not m or m.group("version") != version:
            raise ValueError(f"{Path(path).name}: expected zs-collect-{version}-linux-<amd64|arm64>")
        files.append({"name": Path(path).name, "arch": m.group("arch"), "sha256": _sha256(Path(path)),
                      "size": Path(path).stat().st_size})
    if len({f["arch"] for f in files}) != len(files) or not files:
        raise ValueError("one binary per architecture")
    return {"format": MANIFEST_FORMAT, "version": version, "git_commit": git_commit, "files": files}


def write_manifest(binaries: list[Path], version: str, git_commit: str, out: Path) -> dict:
    manifest = build_manifest(binaries, version, git_commit)
    Path(out).write_bytes(canonical(manifest))
    return manifest


def sign(private_path: Path, manifest_path: Path) -> Path:
    key = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("the release key must be Ed25519")
    sig = base64.b64encode(key.sign(Path(manifest_path).read_bytes())).decode()
    out = Path(str(manifest_path) + ".sig")
    out.write_text(sig + "\n")
    return out


def verify(public_pem: str, manifest_bytes: bytes, sig_b64: str, files_dir: Path | None = None) -> dict:
    """The manifest when the signature is the release key's (and every binary present in ``files_dir`` matches)."""
    key = serialization.load_pem_public_key(public_pem.encode())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise VerifyError("the release public key is not Ed25519")
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
        key.verify(sig, manifest_bytes)
    except (InvalidSignature, ValueError):
        raise VerifyError("the manifest signature is not valid for the release key") from None
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError:
        raise VerifyError("the manifest is not JSON") from None
    if manifest.get("format") != MANIFEST_FORMAT or not VERSION_RE.match(str(manifest.get("version"))):
        raise VerifyError("not a zs-collect manifest")
    for entry in manifest.get("files") or []:
        if not NAME_RE.match(str(entry.get("name"))) or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256"))):
            raise VerifyError("malformed manifest entry")
        if files_dir is not None:
            path = Path(files_dir) / entry["name"]
            if path.exists():
                if _sha256(path) != entry["sha256"] or path.stat().st_size != entry["size"]:
                    raise VerifyError(f"{entry['name']}: sha256 does not match the signed manifest")
    return manifest


def fingerprint(public_pem: str) -> str:
    key = serialization.load_pem_public_key(public_pem.encode())
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


WRAPPER = r"""#!/bin/sh
# zs-collect launcher for release @VERSION@ (generated by ZeroShield; do not edit).
# It copies the binary into a private temp dir, refuses it unless its sha256 is the signed manifest's, verifies the
# mirrored manifest's Ed25519 signature with OpenSSL 3 when the manifest is present, runs it, and removes the temp dir.
# Exit 3: binary missing or unsupported machine; exit 4: integrity check failed; otherwise zs-collect's own status.
set -u
umask 077
ZS_DIR="${ZS_COLLECT_DIR:-/opt/zeroshield/zs-collect}"
case "$(uname -m)" in
  x86_64|amd64) ZS_ARCH=amd64; ZS_SHA="@SHA_AMD64@" ;;
  aarch64|arm64) ZS_ARCH=arm64; ZS_SHA="@SHA_ARM64@" ;;
  *) echo "zs-collect: unsupported machine $(uname -m)" >&2; exit 3 ;;
esac
if [ -z "$ZS_SHA" ]; then echo "zs-collect: release @VERSION@ has no $ZS_ARCH build" >&2; exit 3; fi
ZS_NAME="zs-collect-@VERSION@-linux-$ZS_ARCH"
ZS_TMP="$(mktemp -d "${TMPDIR:-/tmp}/zs-collect.XXXXXXXX")" || { echo "zs-collect: mktemp failed" >&2; exit 3; }
trap 'rm -rf "$ZS_TMP"' EXIT
trap 'exit 130' INT TERM HUP
chmod 0700 "$ZS_TMP"
if ! cp "$ZS_DIR/$ZS_NAME" "$ZS_TMP/zs-collect" 2>/dev/null; then
  echo "zs-collect: $ZS_DIR/$ZS_NAME is missing (mirror release @VERSION@ there)" >&2; exit 3
fi
if ! printf '%s  %s\n' "$ZS_SHA" "$ZS_TMP/zs-collect" | sha256sum -c --status - 2>/dev/null; then
  echo "zs-collect: checksum mismatch for $ZS_NAME; refusing to run it" >&2; exit 4
fi
ZS_MANIFEST="$ZS_DIR/zs-collect-@VERSION@.manifest.json"
if [ -f "$ZS_MANIFEST" ] && command -v openssl >/dev/null 2>&1 && openssl version 2>/dev/null | grep -q '^OpenSSL [3-9]'; then
  cat > "$ZS_TMP/release.pub" <<'ZS_PUB_EOF'
@PUBLIC_PEM@ZS_PUB_EOF
  printf '%s' '@SIG_B64@' | openssl base64 -d -A > "$ZS_TMP/manifest.sig" 2>/dev/null
  if ! openssl pkeyutl -verify -rawin -pubin -inkey "$ZS_TMP/release.pub" -in "$ZS_MANIFEST" \
       -sigfile "$ZS_TMP/manifest.sig" >/dev/null 2>&1; then
    echo "zs-collect: the mirrored manifest's signature is not valid; refusing to run" >&2; exit 4
  fi
  if ! grep -q "$ZS_SHA" "$ZS_MANIFEST"; then
    echo "zs-collect: the mirrored manifest does not list this binary; refusing to run" >&2; exit 4
  fi
fi
chmod 0500 "$ZS_TMP/zs-collect"
TMPDIR="$ZS_TMP" "$ZS_TMP/zs-collect" --tmp-dir "$ZS_TMP" "$@"
exit $?
"""


def render_wrapper(manifest: dict, public_pem: str, sig_b64: str) -> str:
    """The launcher for one verified release (sha256 per arch baked in)."""
    version = str(manifest["version"])
    if not VERSION_RE.match(version):
        raise ValueError("bad version")
    sha = {f["arch"]: f["sha256"] for f in manifest.get("files") or []}
    for value in sha.values():
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("bad sha256")
    sig = sig_b64.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=]{40,200}", sig):
        raise ValueError("bad signature encoding")
    pem = public_pem.strip() + "\n"
    if not re.fullmatch(r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n", pem):
        raise ValueError("bad public key")
    return (WRAPPER.replace("@VERSION@", version).replace("@SHA_AMD64@", sha.get("amd64", ""))
            .replace("@SHA_ARM64@", sha.get("arm64", "")).replace("@PUBLIC_PEM@", pem).replace("@SIG_B64@", sig))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="release.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--private", required=True)
    k.add_argument("--public", required=True)
    m = sub.add_parser("manifest")
    m.add_argument("--version", required=True)
    m.add_argument("--git-commit", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("binaries", nargs="+")
    s = sub.add_parser("sign")
    s.add_argument("--key", required=True)
    s.add_argument("manifest")
    v = sub.add_parser("verify")
    v.add_argument("--public", required=True)
    v.add_argument("--files")
    v.add_argument("manifest")
    w = sub.add_parser("wrapper")
    w.add_argument("--public", required=True)
    w.add_argument("--out", required=True)
    w.add_argument("manifest")
    f = sub.add_parser("fingerprint")
    f.add_argument("public")
    args = p.parse_args(argv)
    if args.cmd == "keygen":
        keygen(Path(args.private), Path(args.public))
        print(fingerprint(Path(args.public).read_text()))
    elif args.cmd == "manifest":
        manifest = write_manifest([Path(b) for b in args.binaries], args.version, args.git_commit, Path(args.out))
        print(json.dumps(manifest, indent=2))
    elif args.cmd == "sign":
        print(sign(Path(args.key), Path(args.manifest)))
    elif args.cmd in ("verify", "wrapper"):
        data = Path(args.manifest).read_bytes()
        sig = Path(args.manifest + ".sig").read_text()
        try:
            manifest = verify(Path(args.public).read_text(), data, sig, Path(args.files) if args.cmd == "verify" and args.files else None)
        except VerifyError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 1
        if args.cmd == "verify":
            print(f"ok: zs-collect {manifest['version']} ({len(manifest['files'])} files) signed by "
                  f"{fingerprint(Path(args.public).read_text())}")
        else:
            out = Path(args.out)
            out.write_text(render_wrapper(manifest, Path(args.public).read_text(), sig))
            out.chmod(0o755)
            print(out)
    elif args.cmd == "fingerprint":
        print(fingerprint(Path(args.public).read_text()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
