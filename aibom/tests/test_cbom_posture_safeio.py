"""Walker confinement."""

import os
from pathlib import Path

from aibom.cbom.posture.context import CbomScanContext
from aibom.cbom.posture.limits import BYTES_PER_CONFIG_FILE


def _codes(ctx: CbomScanContext) -> list[str]:
    return [item.code for item in ctx.posture.diagnostics.stored()]


def test_walk_order_file_before_child_directory(tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text('resource "a" "b" {}\n', encoding="utf-8")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.tf").write_text('resource "a" "c" {}\n', encoding="utf-8")
    index = CbomScanContext(tmp_path).posture.index()
    rels = [item.rel for item in index.files]
    assert rels.index("a.tf") < rels.index("a/b.tf")


def test_symlink_to_passwd_is_not_opened(tmp_path: Path) -> None:
    link = tmp_path / "secret.conf"
    link.symlink_to("/etc/passwd")
    ctx = CbomScanContext(tmp_path)
    index = ctx.posture.index()
    assert index.files == ()
    assert "special_file_skipped" in _codes(ctx)
    assert not any(item.rel.endswith("passwd") for item in index.files)


def test_fifo_is_skipped(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe.conf")
    ctx = CbomScanContext(tmp_path)
    ctx.posture.index()
    assert "special_file_skipped" in _codes(ctx)


def test_size_one_byte_over_the_cap_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "nginx.conf"
    path.write_bytes(b"a" * (BYTES_PER_CONFIG_FILE + 1))
    ctx = CbomScanContext(tmp_path)
    index = ctx.posture.index()
    assert index.files == ()
    assert "size_cap" in _codes(ctx)


def test_nul_in_the_first_8192_bytes_is_binary(tmp_path: Path) -> None:
    (tmp_path / "redis.conf").write_bytes(b"port 1\n\x00rest\n")
    ctx = CbomScanContext(tmp_path)
    item = ctx.posture.index().files[0]
    assert ctx.posture.read(item) is None
    assert "binary_skipped" in _codes(ctx)


def test_utf16_bom_decodes(tmp_path: Path) -> None:
    (tmp_path / "redis.conf").write_bytes("port 6379\n".encode("utf-16"))
    ctx = CbomScanContext(tmp_path)
    item = ctx.posture.index().files[0]
    decoded = ctx.posture.read(item)
    assert decoded is not None
    assert decoded.encoding == "utf-16"
    assert "6379" in decoded.text


def test_path_is_sanitized_to_512_bytes(tmp_path: Path) -> None:
    name = "n" * 600 + ".conf"
    # A single path segment that long may fail on some filesystems; sanitize directly.
    from aibom.cbom.posture.safeio import sanitize_path

    cleaned = sanitize_path("a/\x01b/" + ("c" * 600))
    assert "\x01" not in cleaned
    assert len(cleaned.encode("utf-8")) <= 512
    assert name  # the long name is the case the walker would sanitize


def test_skipped_directories_are_not_walked(tmp_path: Path) -> None:
    nested = tmp_path / "node_modules"
    nested.mkdir()
    (nested / "redis.conf").write_text("port 1\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x\n", encoding="utf-8")
    index = CbomScanContext(tmp_path).posture.index()
    assert index.files == ()
