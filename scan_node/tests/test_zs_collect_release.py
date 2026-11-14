"""zs-collect releases: the signed manifest, its verification, and the launcher every transport runs.

The launcher (``release.py wrapper``) is what the SSM document, the Salt state and the Ansible role embed: it copies the
binary into a private temp dir, refuses it unless its sha256 is the one baked in from the verified manifest, verifies
the mirrored manifest's Ed25519 signature with OpenSSL 3 when it is present, runs it, and removes the temp dir.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[1] / "zs_collect"


def _release():
    spec = importlib.util.spec_from_file_location("zs_collect_release", ROOT / "release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _release()
ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine(), "amd64")


@pytest.fixture()
def keys(tmp_path):
    priv, pub = tmp_path / "release.key", tmp_path / "release.pub"
    R.keygen(priv, pub)
    assert (os.stat(priv).st_mode & 0o777) == 0o600
    return priv, pub


def _fake_binary(directory: Path, version: str, marker: Path) -> Path:
    """A stand-in for the PyInstaller binary: records its arguments and TMPDIR, prints a document."""
    path = directory / f"zs-collect-{version}-linux-{ARCH}"
    path.write_text("#!/bin/sh\n"
                    f'printf "%s\\n" "TMPDIR=$TMPDIR" "$@" > "{marker}"\n'
                    'echo \'{"format": "zs-collect/1"}\'\n'
                    "exit 0\n")
    path.chmod(0o755)
    return path


def _release_dir(tmp_path, keys, version="1.0.0"):
    d = tmp_path / "mirror"
    d.mkdir()
    marker = tmp_path / "ran.txt"
    binary = _fake_binary(d, version, marker)
    manifest_path = d / f"zs-collect-{version}.manifest.json"
    R.write_manifest([binary], version, "0123456789abcdef0123456789abcdef01234567", manifest_path)
    sig_path = R.sign(keys[0], manifest_path)
    return d, binary, manifest_path, sig_path, marker


def test_manifest_sign_verify_roundtrip(tmp_path, keys):
    d, binary, manifest_path, sig_path, _m = _release_dir(tmp_path, keys)
    manifest = json.loads(manifest_path.read_text())
    assert manifest["format"] == "zs-collect-manifest/1" and manifest["version"] == "1.0.0"
    assert manifest["files"] == [{"name": binary.name, "arch": ARCH,
                                  "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                                  "size": binary.stat().st_size}]
    assert sig_path.name == manifest_path.name + ".sig"
    assert len(base64.b64decode(sig_path.read_text().strip())) == 64
    pub = keys[1].read_text()
    assert R.verify(pub, manifest_path.read_bytes(), sig_path.read_text(), files_dir=d) == manifest


def test_tampered_manifest_or_binary_is_refused(tmp_path, keys):
    d, binary, manifest_path, sig_path, _m = _release_dir(tmp_path, keys)
    pub = keys[1].read_text()
    tampered = manifest_path.read_bytes().replace(b"1.0.0", b"1.0.1")
    with pytest.raises(R.VerifyError, match="signature"):
        R.verify(pub, tampered, sig_path.read_text())
    other = ed25519.Ed25519PrivateKey.generate()
    forged = base64.b64encode(other.sign(manifest_path.read_bytes())).decode()
    with pytest.raises(R.VerifyError, match="signature"):
        R.verify(pub, manifest_path.read_bytes(), forged)
    binary.write_bytes(binary.read_bytes() + b"# extra\n")
    with pytest.raises(R.VerifyError, match="sha256"):
        R.verify(pub, manifest_path.read_bytes(), sig_path.read_text(), files_dir=d)


def _openssl3() -> bool:
    exe = shutil.which("openssl")
    if not exe:
        return False
    out = subprocess.run([exe, "version"], capture_output=True, text=True).stdout
    return out.startswith("OpenSSL ") and int(out.split()[1].split(".")[0]) >= 3


@pytest.mark.skipif(not _openssl3(), reason="OpenSSL 3 is needed for Ed25519 -rawin verification")
def test_openssl_verifies_the_same_signature(tmp_path, keys):
    _d, _b, manifest_path, sig_path, _m = _release_dir(tmp_path, keys)
    raw = tmp_path / "sig.bin"
    raw.write_bytes(base64.b64decode(sig_path.read_text()))
    ok = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(keys[1]),
                         "-in", str(manifest_path), "-sigfile", str(raw)], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
    bad = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(keys[1]),
                          "-in", str(manifest_path), "-sigfile", str(raw)], capture_output=True, text=True)
    assert bad.returncode != 0


def _wrapper(tmp_path, keys, manifest_path, sig_path) -> Path:
    manifest = json.loads(manifest_path.read_text())
    script = R.render_wrapper(manifest, keys[1].read_text(), sig_path.read_text())
    path = tmp_path / "zs-collect-run.sh"
    path.write_text(script)
    path.chmod(0o755)
    return path


def _run_wrapper(wrapper: Path, mirror: Path, tmp_path: Path):
    work = tmp_path / "tmproot"
    work.mkdir(exist_ok=True)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "ZS_COLLECT_DIR": str(mirror), "TMPDIR": str(work)}
    return subprocess.run(["/bin/sh", str(wrapper), "--nonce", "run-0123456789abcdef", "--tier", "2"],
                          capture_output=True, text=True, env=env, timeout=60), work


def test_wrapper_runs_a_verified_binary_in_a_private_temp_dir(tmp_path, keys):
    mirror, _b, manifest_path, sig_path, marker = _release_dir(tmp_path, keys)
    wrapper = _wrapper(tmp_path, keys, manifest_path, sig_path)
    p, work = _run_wrapper(wrapper, mirror, tmp_path)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["format"] == "zs-collect/1"
    lines = marker.read_text().splitlines()
    tmpdir = lines[0].split("=", 1)[1]
    assert tmpdir.startswith(str(work) + "/zs-collect.")
    assert lines[1:] == ["--tmp-dir", tmpdir, "--nonce", "run-0123456789abcdef", "--tier", "2"]
    assert not os.path.exists(tmpdir) and os.listdir(work) == []  # removed at exit


def test_wrapper_refuses_a_binary_whose_checksum_differs(tmp_path, keys):
    mirror, binary, manifest_path, sig_path, marker = _release_dir(tmp_path, keys)
    wrapper = _wrapper(tmp_path, keys, manifest_path, sig_path)
    binary.write_text(binary.read_text().replace("exit 0", "touch /tmp/pwned; exit 0"))
    p, work = _run_wrapper(wrapper, mirror, tmp_path)
    assert p.returncode == 4 and "checksum" in p.stderr
    assert not marker.exists() and os.listdir(work) == []


@pytest.mark.skipif(not _openssl3(), reason="OpenSSL 3 is needed for Ed25519 -rawin verification")
def test_wrapper_refuses_a_mirrored_manifest_with_a_bad_signature(tmp_path, keys):
    mirror, _b, manifest_path, sig_path, marker = _release_dir(tmp_path, keys)
    wrapper = _wrapper(tmp_path, keys, manifest_path, sig_path)
    manifest_path.write_text(manifest_path.read_text().replace('"1.0.0"', '"1.0.0" '))
    p, _work = _run_wrapper(wrapper, mirror, tmp_path)
    assert p.returncode == 4 and "signature" in p.stderr
    assert not marker.exists()


def test_wrapper_reports_a_missing_binary(tmp_path, keys):
    mirror, binary, manifest_path, sig_path, marker = _release_dir(tmp_path, keys)
    wrapper = _wrapper(tmp_path, keys, manifest_path, sig_path)
    binary.unlink()
    p, _work = _run_wrapper(wrapper, mirror, tmp_path)
    assert p.returncode == 3 and "missing" in p.stderr


def test_committed_release_public_key_is_ed25519():
    pem = (ROOT / "zs-release-ed25519.pub").read_bytes()
    key = serialization.load_pem_public_key(pem)
    assert isinstance(key, ed25519.Ed25519PublicKey)
    assert R.fingerprint(pem.decode()).startswith("SHA256:")


def test_wrapper_is_posix_sh():
    if not shutil.which("sh"):
        pytest.skip("no sh")
    key = ed25519.Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    manifest = {"format": "zs-collect-manifest/1", "version": "1.0.0", "git_commit": "0" * 40,
                "files": [{"name": "zs-collect-1.0.0-linux-amd64", "arch": "amd64", "sha256": "a" * 64, "size": 1}]}
    script = R.render_wrapper(manifest, pub.decode(), base64.b64encode(b"x" * 64).decode())
    p = subprocess.run(["sh", "-n"], input=script, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "a" * 64 in script and "zs-collect-1.0.0-linux-$ZS_ARCH" in script
