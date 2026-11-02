"""The shared CBOM file walk: no symbolic links, one skip-directory rule, vendored output only when opted in."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aibom.cbom.files import (
    SKIP_DIRS,
    VENDORED_DIRS,
    FileWalk,
    read_bytes,
    skipped_dirs,
)
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.posture import safeio

_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "-----END RSA PRIVATE KEY-----\n"
)


def _sources(result) -> set[str]:
    return {(c.properties or {}).get("discovery:source") or "" for c in result.components}


def test_a_linked_key_file_is_never_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "worker_env"
    secret.write_text(_PRIVATE_KEY)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    os.symlink(secret, repo / "key.pem")  # key.pem -> a file outside the repository
    os.symlink(outside, repo / "linked_dir")  # a directory link

    result = scan_crypto(repo)

    assert not any("key.pem" in s or "linked_dir" in s for s in _sources(result))
    assert not [c for c in result.components
                if (c.properties or {}).get("crypto:materialKind") == "private-key"]
    assert result.properties["crypto:coverage:skippedSymlinks"] == "2"
    assert "SHA-256" in {c.name for c in result.components}


def test_read_bytes_refuses_links_and_fifos(tmp_path: Path) -> None:
    target = tmp_path / "t.txt"
    target.write_text("hello")
    link = tmp_path / "l.txt"
    os.symlink(target, link)
    fifo = tmp_path / "f"
    os.mkfifo(fifo)
    assert read_bytes(target) == b"hello"
    assert read_bytes(link) is None
    assert read_bytes(fifo) is None
    assert read_bytes(target, max_bytes=3) is None


def test_vendored_output_is_opt_in(tmp_path: Path) -> None:
    for d in ("vendor", "node_modules", "dist", "build"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "legacy.js").write_text("const h = require('crypto').createHash('md5');\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.js").write_text("const h = require('crypto').createHash('sha256');\n")

    default = scan_crypto(tmp_path)
    assert not any(s.split("/", 1)[0] in VENDORED_DIRS for s in _sources(default))
    assert default.properties["crypto:coverage:skippedVendoredDirs"] == "4"

    opted = scan_crypto(tmp_path, include_vendored=True)
    md5_sources = {(c.properties or {}).get("discovery:source") for c in opted.components if c.name == "MD5"}
    assert md5_sources == {f"{d}/legacy.js" for d in ("vendor", "node_modules", "dist", "build")}
    assert opted.properties["crypto:coverage:vendoredIncluded"] == "true"
    assert "crypto:coverage:skippedVendoredDirs" not in opted.properties


def test_tool_directories_are_never_entered_even_when_opted_in(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "x.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    result = scan_crypto(tmp_path, include_vendored=True)
    assert not [c for c in result.components if c.name == "MD5"]


def test_oversized_and_binary_sources_are_reported(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_bytes(b"import hashlib\n" + b"#" * 2_100_000)
    (tmp_path / "blob.py").write_bytes(b"import hashlib\x00\x00 hashlib.md5()\n")
    result = scan_crypto(tmp_path)
    assert result.properties["crypto:coverage:skippedOversized"] == "1"
    assert result.properties["crypto:coverage:skippedBinary"] == "1"


def test_clean_tree_carries_no_coverage_properties(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    assert not [k for k in scan_crypto(tmp_path).properties if k.startswith("crypto:coverage:")]


def test_walk_order_matches_sorted_rglob(tmp_path: Path) -> None:
    for rel in ("b/z.py", "a/y.py", "a.py", "a/b/x.py", "B.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x = 1\n")
    expected = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert FileWalk(tmp_path).files() == expected


@pytest.mark.parametrize("include_vendored", [False, True])
def test_posture_walk_shares_the_skip_rule(include_vendored: bool) -> None:
    assert skipped_dirs(include_vendored) >= SKIP_DIRS
    assert (VENDORED_DIRS <= skipped_dirs(include_vendored)) is not include_vendored
    assert safeio.SKIP_DIRS == skipped_dirs(False)
