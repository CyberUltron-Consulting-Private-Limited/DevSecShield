#!/usr/bin/env python3
"""Assemble the scan-node downloads a ZeroShield server offers on Add scan node (backend/routers/cbom_node_artifacts.py),
next to the image file that scripts/release/scan_node_image.sh wrote:

  <out>/scan-node-<version>.tar.gz (+ .sha256)          the image (docker save), already there
  <out>/cbom-scan-node-<version>.tgz (+ .sha256)        the Helm chart (deploy/helm/cbom-scan-node), version and
                                                        appVersion = <version>, so its default tag is the image's
  <out>/cbom-scan-node-ova-kit-<version>.zip (+ .sha256) Packer kit for the OVA, with a README for customers
  <out>/cbom-scan-node-ami-kit-<version>.zip (+ .sha256) Packer kit for the AMI, with a README for customers
  <out>/manifest.json                                   version, image_ref, file names (what the server reads)

The kits build from the downloaded image file (node_image_archive), never from a registry; their defaults name this
version's file and image. Every file is reproducible: fixed times, owners and order, so the same tree gives the same
SHA-256.

  python3 -I scripts/release/node_artifacts.py --version 1.0.0 --image-ref zeroshield/cbom-scan-node:1.0.0 --out DIR
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "deploy" / "helm" / "cbom-scan-node"
IMAGES = REPO / "deploy" / "node-images"
VERSION_RE = re.compile(r"[0-9][0-9A-Za-z.-]{0,18}")  # scan_node_image.sh NODE_VERSION_RE
# [registry[:port]/]path:tag, as backend/routers/cbom_node_artifacts.py accepts it
IMAGE_RE = re.compile(r"(?:[A-Za-z0-9.-]+(?::[0-9]{1,5})?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
                      r":[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
ZIP_TIME = (1980, 1, 1, 0, 0, 0)
EXECUTABLE = {"scripts/install.sh", "scripts/make-ova.sh", "files/zs-node-run", "files/zs-ovf-env"}
KIT_FILES = {
    "ova": ["ova.pkr.hcl", "scripts/install.sh", "scripts/make-ova.sh", "files/zs-node-run", "files/zs-scan-node.service",
            "files/zs-ovf-env", "files/zs-ovf-env.service", "ovf/zs-scan-node.ovf.in"],
    "ami": ["ami.pkr.hcl", "scripts/install.sh", "files/zs-node-run", "files/zs-scan-node.service"],
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sidecar(path: Path) -> None:
    path.with_name(path.name + ".sha256").write_text(f"{sha256_file(path)}  {path.name}\n")


def set_defaults(template: str, version: str, image_ref: str) -> str:
    """The kit's Packer template defaults to this version's image file and the image it loads as."""
    out, n1 = re.subn(r'(variable "node_image_archive" \{[^}]*?default\s*=\s*)"[^"]*"', rf'\1"scan-node-{version}.tar.gz"',
                      template, flags=re.S)
    out, n2 = re.subn(r'(variable "node_image" \{[^}]*?default\s*=\s*)"[^"]*"', rf'\1"{image_ref}"', out, flags=re.S)
    if n1 != 1 or n2 != 1:
        raise SystemExit("node_artifacts: a Packer template lost its node_image_archive or node_image variable")
    return out


def package_chart(out: Path, version: str, image_ref: str) -> Path:
    repository = image_ref.rsplit(":", 1)[0]
    target = out / f"cbom-scan-node-{version}.tgz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for path in sorted(p for p in CHART.rglob("*") if p.is_file()):
            rel = path.relative_to(CHART).as_posix()
            data = path.read_bytes()
            if rel == "Chart.yaml":
                text, n = re.subn(r"(?m)^version: .*$", f"version: {version}", data.decode())
                text, m = re.subn(r"(?m)^appVersion: .*$", f'appVersion: "{version}"', text)
                if n != 1 or m != 1:
                    raise SystemExit("node_artifacts: Chart.yaml has no version/appVersion line")
                data = text.encode()
            elif rel == "values.yaml":
                text, n = re.subn(r"(?m)^(  repository: ).*$", rf"\g<1>{repository}", data.decode(), count=1)
                if n != 1:
                    raise SystemExit("node_artifacts: values.yaml has no image.repository line")
                data = text.encode()
            info = tarfile.TarInfo(f"cbom-scan-node/{rel}")
            info.size, info.mode, info.mtime, info.uid, info.gid, info.uname, info.gname = len(data), 0o644, 0, 0, 0, "", ""
            tf.addfile(info, io.BytesIO(data))
    with target.open("wb") as fh, gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0) as gz:
        gz.write(buf.getvalue())
    return target


def build_kit(out: Path, kind: str, version: str, image_ref: str) -> Path:
    top = f"cbom-scan-node-{kind}-kit-{version}"
    target = out / f"{top}.zip"
    readme = (IMAGES / "kit" / f"README-{kind}.md").read_text()
    readme = readme.replace("@VERSION@", version).replace("@IMAGE@", image_ref)
    entries: list[tuple[str, bytes]] = [("README.md", readme.encode())]
    for rel in KIT_FILES[kind]:
        data = (IMAGES / rel).read_bytes()
        if rel.endswith(".pkr.hcl"):
            data = set_defaults(data.decode(), version, image_ref).encode()
        entries.append((rel, data))
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel, data in entries:
            info = zipfile.ZipInfo(f"{top}/{rel}", date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = ((0o100755 if rel in EXECUTABLE else 0o100644) & 0xFFFF) << 16
            info.create_system = 3  # unix: the modes above apply on unzip
            zf.writestr(info, data)
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--image-ref", required=True, help="the name the image file loads as (docker load)")
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)
    if not VERSION_RE.fullmatch(args.version):
        raise SystemExit(f"node_artifacts: invalid version {args.version!r} (see scan_node_image.sh)")
    if not IMAGE_RE.fullmatch(args.image_ref) or not args.image_ref.endswith(f":{args.version}"):
        raise SystemExit(f"node_artifacts: --image-ref must be <name>:{args.version}")
    out: Path = args.out
    image = out / f"scan-node-{args.version}.tar.gz"
    if not image.is_file():
        raise SystemExit(f"node_artifacts: {image} is missing (scripts/release/scan_node_image.sh build {args.version})")
    write_sidecar(image)
    files = {"image": image.name}
    for key, path in (("helm-chart", package_chart(out, args.version, args.image_ref)),
                      ("ova-kit", build_kit(out, "ova", args.version, args.image_ref)),
                      ("ami-kit", build_kit(out, "ami", args.version, args.image_ref))):
        write_sidecar(path)
        files[key] = path.name
    (out / "manifest.json").write_text(json.dumps(
        {"version": args.version, "image_ref": args.image_ref, "files": files}, indent=2, sort_keys=True) + "\n")
    for name in files.values():
        print(f"{name}\t{(out / name).stat().st_size}\t{sha256_file(out / name)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
