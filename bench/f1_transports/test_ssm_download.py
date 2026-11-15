"""CB-36: an evidence file larger than SSM's 24,000-character stdout comes back whole, or not at all.

The shell commands are the ones the EC2 driver sends. They run here under bash against a
local file, which is the same ``stat`` / ``sha256sum`` / ``dd | base64`` a sandbox Amazon
Linux host runs. No AWS call.
"""
from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ssm_download as dl  # noqa: E402

ROOT = HERE.parents[1]


def _bash(command: str) -> str:
    proc = subprocess.run(["bash", "-c", command], capture_output=True, check=False)
    if proc.returncode != 0:
        raise AssertionError(proc.stderr.decode()[-400:])
    return proc.stdout.decode()


def test_the_cap_matches_the_product_ssm_transport():
    text = (ROOT / "backend/utilities/cbom_sources/transports/ssm.py").read_text(encoding="utf-8")
    assert "INLINE_CAP = 24_000" in text
    assert dl.INLINE_CAP == 24_000


def test_a_file_bigger_than_one_ssm_stdout_round_trips(tmp_path: Path):
    payload = os.urandom(50_000)
    remote = tmp_path / "evidence-har.bin"
    remote.write_bytes(payload)
    whole = base64.b64encode(payload).decode()
    assert len(whole) > dl.INLINE_CAP  # one `run` of `base64` would be cut

    def run(command: str) -> str:
        out = _bash(command)
        assert len(out) < dl.INLINE_CAP
        return out

    dest = tmp_path / "local.bin"
    digest = dl.save_download(run, str(remote), dest)
    assert dest.read_bytes() == payload
    assert digest == hashlib.sha256(payload).hexdigest()
    assert not (tmp_path / "local.bin.partial").exists()


def test_empty_exact_and_one_past_a_chunk(tmp_path: Path):
    for size in (0, dl.RAW_CHUNK, dl.RAW_CHUNK + 1):
        remote = tmp_path / f"n{size}.bin"
        remote.write_bytes(b"q" * size)
        dest = tmp_path / f"out{size}.bin"
        dl.save_download(_bash, str(remote), dest)
        assert dest.read_bytes() == b"q" * size


def test_a_stdout_at_the_cap_is_refused_and_nothing_is_written(tmp_path: Path):
    remote = tmp_path / "cut.bin"
    remote.write_bytes(b"abc" * 100)

    def run(command: str) -> str:
        out = _bash(command)
        if "base64" in command:
            return "A" * dl.INLINE_CAP
        return out

    dest = tmp_path / "local.bin"
    try:
        dl.save_download(run, str(remote), dest)
    except dl.DownloadError as exc:
        assert "cap" in str(exc)
    else:
        raise AssertionError("truncated stdout was saved")
    assert not dest.exists()
    assert not Path(str(dest) + ".partial").exists()


def test_a_tampered_chunk_fails_the_sha256_check(tmp_path: Path):
    remote = tmp_path / "tamper.bin"
    remote.write_bytes(os.urandom(dl.RAW_CHUNK + 10))

    def run(command: str) -> str:
        out = _bash(command)
        if "base64" in command and "skip=0" in command:
            return base64.b64encode(b"\x00" * dl.RAW_CHUNK).decode()
        return out

    try:
        dl.save_download(run, str(remote), tmp_path / "out.bin")
    except dl.DownloadError as exc:
        assert "sha256" in str(exc)
    else:
        raise AssertionError("tampered chunk was saved")
    assert not (tmp_path / "out.bin").exists()


def test_a_short_chunk_is_refused(tmp_path: Path):
    remote = tmp_path / "short.bin"
    remote.write_bytes(b"z" * (dl.RAW_CHUNK + 3))

    def run(command: str) -> str:
        out = _bash(command)
        if "skip=0" in command:
            return base64.b64encode(b"z" * 4).decode()
        return out

    try:
        dl.pull(run, str(remote))
    except dl.DownloadError as exc:
        assert "not" in str(exc)
    else:
        raise AssertionError("short chunk was accepted")


def test_shell_metacharacters_never_become_a_command():
    calls: list[str] = []

    def run(command: str) -> str:
        calls.append(command)
        return ""

    for path in ("/tmp/a;id", "/tmp/a b", "relative", "/tmp/../etc/passwd", "/tmp/a$(id)", ""):
        try:
            dl.pull(run, path)
        except dl.DownloadError:
            pass
        else:
            raise AssertionError(path)
    assert calls == []


def test_write_refuses_an_existing_file_and_a_symlink(tmp_path: Path):
    dest = tmp_path / "have.bin"
    dest.write_bytes(b"keep")
    try:
        dl.write_verified(dest, b"new")
    except dl.DownloadError:
        pass
    else:
        raise AssertionError("existing file was replaced")
    assert dest.read_bytes() == b"keep"
    link = tmp_path / "link.bin"
    link.symlink_to(dest)
    try:
        dl.write_verified(link, b"new")
    except dl.DownloadError:
        pass
    else:
        raise AssertionError("symlink was followed")
    assert dest.read_bytes() == b"keep"


def test_output_at_the_cap_is_the_run_guard():
    assert dl.output_is_at_cap("x" * dl.INLINE_CAP)
    assert not dl.output_is_at_cap("x" * (dl.INLINE_CAP - 1))
