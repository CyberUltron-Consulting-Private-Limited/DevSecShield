"""The scan-node downloads ship with a staging release: `staging.sh node-artifacts` makes them on the build machine
(scripts/release/node_artifacts.py after scan_node_image.sh), `push` counts them in the host's disk check and copies
them, `deploy` checks them and puts them where the backend of the tag mounts them (node-artifacts/<tag>, the API's
CBOM_NODE_ARTIFACT_DIR), and retention keeps them with their tag's images.

The kits and the chart are checked as a customer gets them: no registry.zeroshield.ai, no `make` in a repository,
the Packer defaults naming the downloaded image file, the chart's default tag the image's.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from test_deploy_staging_script import BASH, ROOT, failed, ok, running_tags
from test_staging_deploy_disk import ARCH, IMG, NEED, ShortHost, build_machine, push

pytestmark = pytest.mark.skipif(BASH is None or shutil.which("sha256sum") is None, reason="needs bash and sha256sum")

VERSION = "1.0.0"
IMAGE_REF = f"zeroshield/cbom-scan-node:{VERSION}"
KINDS = ("image", "helm-chart", "ova-kit", "ami-kit")


def make_artifacts(out: Path, image_bytes: bytes = b"docker-save-archive" * 512) -> dict:
    """What `staging.sh node-artifacts` leaves: the image file from scan_node_image.sh (a stand-in here), then
    node_artifacts.py (the real one)."""
    out.mkdir(parents=True, exist_ok=True)
    (out / f"scan-node-{VERSION}.tar.gz").write_bytes(image_bytes)
    done = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/release/node_artifacts.py"), "--version", VERSION,
                           "--image-ref", IMAGE_REF, "--out", str(out)], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads((out / "manifest.json").read_text())


# ------------------------------------------------------------------------------------------------ node_artifacts.py
def test_node_artifacts_writes_every_download_with_its_sha256(tmp_path):
    manifest = make_artifacts(tmp_path)
    assert manifest["version"] == VERSION and manifest["image_ref"] == IMAGE_REF
    assert manifest["files"] == {"image": f"scan-node-{VERSION}.tar.gz", "helm-chart": f"cbom-scan-node-{VERSION}.tgz",
                                 "ova-kit": f"cbom-scan-node-ova-kit-{VERSION}.zip",
                                 "ami-kit": f"cbom-scan-node-ami-kit-{VERSION}.zip"}
    for name in manifest["files"].values():
        check = subprocess.run(["sha256sum", "-c", f"{name}.sha256"], cwd=tmp_path, capture_output=True, text=True)
        assert check.returncode == 0, check.stdout + check.stderr


def test_node_artifacts_are_reproducible(tmp_path):
    a = make_artifacts(tmp_path / "a")
    make_artifacts(tmp_path / "b")
    for name in a["files"].values():
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes(), name


def test_the_chart_installs_from_the_file_with_the_image_s_tag(tmp_path):
    make_artifacts(tmp_path)
    with tarfile.open(tmp_path / f"cbom-scan-node-{VERSION}.tgz") as tf:
        names = tf.getnames()
        chart = tf.extractfile("cbom-scan-node/Chart.yaml").read().decode()
        values = tf.extractfile("cbom-scan-node/values.yaml").read().decode()
        everything = "".join(tf.extractfile(m).read().decode() for m in tf.getmembers() if m.isfile())
    assert "registry.zeroshield.ai" not in everything and "make node-image" not in everything and "oci://" not in everything
    assert all(n.startswith("cbom-scan-node/") for n in names)
    assert {"cbom-scan-node/templates/deployment.yaml", "cbom-scan-node/templates/daemonset.yaml"} <= set(names)
    assert f"\nversion: {VERSION}\n" in chart and f'\nappVersion: "{VERSION}"\n' in chart  # default tag = the image's
    assert "  repository: zeroshield/cbom-scan-node\n" in values  # the name the image file loads as


@pytest.mark.parametrize("kind,template", [("ova", "ova.pkr.hcl"), ("ami", "ami.pkr.hcl")])
def test_the_build_kits_build_from_the_downloaded_image_file(tmp_path, kind, template):
    make_artifacts(tmp_path)
    top = f"cbom-scan-node-{kind}-kit-{VERSION}"
    with zipfile.ZipFile(tmp_path / f"{top}.zip") as zf:
        names = set(zf.namelist())
        text = {n: zf.read(n).decode() for n in names}
        modes = {n: (zf.getinfo(n).external_attr >> 16) & 0o777 for n in names}
    assert {f"{top}/README.md", f"{top}/{template}", f"{top}/scripts/install.sh", f"{top}/files/zs-node-run",
            f"{top}/files/zs-scan-node.service"} <= names
    if kind == "ova":
        assert {f"{top}/scripts/make-ova.sh", f"{top}/files/zs-ovf-env", f"{top}/ovf/zs-scan-node.ovf.in"} <= names
    assert modes[f"{top}/scripts/install.sh"] == 0o755 and modes[f"{top}/files/zs-node-run"] == 0o755
    pkr = text[f"{top}/{template}"]
    # the defaults name this version's file and the image it loads; the file is copied in and loaded, never pulled
    assert f'default     = "scan-node-{VERSION}.tar.gz"' in pkr and f'default     = "{IMAGE_REF}"' in pkr
    assert "source      = var.node_image_archive" in pkr and "NODE_IMAGE_ARCHIVE=/tmp/zs-node-image.tar.gz" in pkr
    readme = text[f"{top}/README.md"]
    assert f"sha256sum -c scan-node-{VERSION}.tar.gz.sha256" in readme and "packer build" in readme
    assert "Download scan node image" in readme
    assert "@VERSION@" not in readme and "@IMAGE@" not in readme  # (ovf.in keeps its placeholders for make-ova.sh)
    for name, body in text.items():
        assert "registry.zeroshield.ai" not in body and "make node-image" not in body, name


def test_install_sh_loads_the_file_and_checks_the_image_it_holds(tmp_path):
    """install.sh (run by Packer on the build VM) with a stub docker: load, then refuse an archive without the image."""
    script = (ROOT / "deploy/node-images/scripts/install.sh").read_text()
    load = script.index('docker load -i "$NODE_IMAGE_ARCHIVE"')
    assert script.index('docker image inspect "$NODE_IMAGE"', load) > load


def test_node_artifacts_refuses_a_missing_image_or_a_mismatched_ref(tmp_path):
    run = [sys.executable, "-I", str(ROOT / "scripts/release/node_artifacts.py"), "--out", str(tmp_path)]
    missing = subprocess.run([*run, "--version", VERSION, "--image-ref", IMAGE_REF], capture_output=True, text=True)
    assert missing.returncode != 0 and "missing" in missing.stderr
    (tmp_path / f"scan-node-{VERSION}.tar.gz").write_bytes(b"x")
    for version, ref in ((VERSION, "zeroshield/cbom-scan-node:2.0.0"), ("latest", "zeroshield/cbom-scan-node:latest")):
        bad = subprocess.run([*run, "--version", version, "--image-ref", ref], capture_output=True, text=True)
        assert bad.returncode != 0, (version, ref)


# ------------------------------------------------------------------------------------------------ staging host
def put_part(host: ShortHost, tag: str, **kw) -> Path:
    part = host.root / "deploy/staging/node-artifacts" / f"{tag}.part"
    make_artifacts(part, **kw)
    return part


def test_deploy_puts_checked_downloads_where_the_backend_mounts_them(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    put_part(host, "t3")
    proc = ok(host.staging("deploy", "t3"))
    dest = host.root / "deploy/staging/node-artifacts/t3"
    assert (dest / "manifest.json").is_file() and not (host.root / "deploy/staging/node-artifacts/t3.part").exists()
    assert "scan-node downloads of t3 in place" in proc.stdout
    compose = (ROOT / "deploy/staging/docker-compose.yml").read_text()
    assert "./node-artifacts/${DSS_TAG:?set DSS_TAG}:/node-artifacts:ro" in compose  # the dir above, for DSS_TAG
    assert host.env_tag() == "t3"


def test_damaged_downloads_stop_the_deploy_before_anything_is_switched(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    part = put_part(host, "t3")
    (part / f"cbom-scan-node-ami-kit-{VERSION}.zip").write_bytes(b"truncated")
    proc = failed(host.staging("deploy", "t3"))
    assert "do not match their .sha256" in proc.stderr and "nothing was switched" in proc.stderr
    assert host.env_tag() == "t2" and running_tags(host) == {"t2"}
    assert not (host.root / "deploy/staging/node-artifacts/t3").exists()


def test_a_release_without_downloads_still_deploys_and_the_api_says_so(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    proc = ok(host.staging("deploy", "t3"))
    assert "no scan-node downloads for t3" in proc.stdout
    dest = host.root / "deploy/staging/node-artifacts/t3"
    assert dest.is_dir() and not any(dest.iterdir())  # ours (not a root-owned one Docker would create), empty


def test_retention_keeps_the_downloads_of_the_tags_whose_images_it_keeps(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    base = host.root / "deploy/staging/node-artifacts"
    for tag in ("t0", "old", "t1", "t2"):
        (base / tag).mkdir(parents=True, exist_ok=True)
        (base / tag / "manifest.json").write_text("{}")
    (base / "t0.part").mkdir()  # an interrupted push of an old tag
    put_part(host, "t3")
    ok(host.staging("deploy", "t3"))
    # t3 runs, t2 is its rollback target and the last that passed: their downloads stay; t1, t0, old go
    assert sorted(p.name for p in base.iterdir()) == ["t2", "t3"]


def test_push_counts_the_downloads_in_the_disk_check_then_copies_and_installs_them(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    build = build_machine(tmp_path, host)
    files = make_artifacts(build / "deploy/staging/images/node-artifacts")["files"]
    out = build / "deploy/staging/images/node-artifacts"
    total = sum(f.stat().st_size for f in out.iterdir() if f.is_file())
    proc = ok(push(host, build))
    calls = (host.root / "ssh.log").read_text().splitlines()
    check = next(i for i, c in enumerate(calls) if "disk-check" in c)
    assert f"--node-artifacts-bytes {total}" in calls[check]
    copy = next(i for i, c in enumerate(calls) if c.startswith("scp ") and "manifest.json" in c)
    deploy = next(i for i, c in enumerate(calls) if "staging.sh deploy" in c)
    assert check < copy < deploy, calls
    dest = host.root / "deploy/staging/node-artifacts/t3"
    for name in files.values():
        assert hashlib.sha256((dest / name).read_bytes()).hexdigest() == hashlib.sha256((out / name).read_bytes()).hexdigest()
    assert "deployed t3" in proc.stdout


def test_push_without_downloads_warns_and_deploys(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG)
    build = build_machine(tmp_path, host)
    proc = ok(push(host, build))
    assert "no scan-node downloads in" in proc.stdout
    assert "--node-artifacts-bytes" not in (host.root / "ssh.log").read_text()


def test_the_disk_check_refuses_when_the_downloads_do_not_fit(tmp_path):
    host = ShortHost(tmp_path, free=NEED + IMG, stale=())
    for name in ("dss-staging-t3.tar.gz", "dss-staging-t3.tar.gz.sha256"):
        (host.images_dir / name).unlink()
    base = host.root / "deploy/staging/node-artifacts"
    base.mkdir(parents=True, exist_ok=True)
    st = host.state
    st["disk"]["mounts"][str(base)] = 2 * 1024 * 1024  # its own filesystem: 2 GiB, 1 GiB of it the reserve
    host.state_file.write_text(json.dumps(st))
    args = ("disk-check", "t3", "--archive-bytes", str(ARCH * 1024), "--need-bytes", str(ARCH * 1024))
    ok(host.staging(*args, "--node-artifacts-bytes", str(512 * 1024 * 1024)))
    proc = failed(host.staging(*args, "--node-artifacts-bytes", str(1536 * 1024 * 1024)))
    assert "scan-node downloads" in proc.stdout + proc.stderr
    failed(host.staging(*args, "--node-artifacts-bytes", "lots"))


def test_the_bundle_never_carries_the_host_s_downloads():
    script = (ROOT / "scripts/deploy/staging.sh").read_text()
    assert "--exclude='deploy/staging/node-artifacts'" in script
    assert "deploy/staging/node-artifacts/" in (ROOT / ".gitignore").read_text()


def test_the_node_version_is_the_scan_node_s():
    init = (ROOT / "scan_node/zs_scan_node/__init__.py").read_text()
    assert f'VERSION = "{VERSION}"' in init  # these tests and the UI's fallback name assume it
    ui = (ROOT / "frontend/components/cbom/sources/logic.ts").read_text()
    assert f'"{IMAGE_REF}"' in ui
    assert 'IMAGE="${SCAN_NODE_IMAGE:-zeroshield/cbom-scan-node}"' in (ROOT / "scripts/release/scan_node_image.sh").read_text()
