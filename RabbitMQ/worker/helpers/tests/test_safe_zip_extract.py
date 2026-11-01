"""Zip-bomb guard must reject expansion bombs and accept small sparse archives."""

import io
import tempfile
import zipfile
from pathlib import Path

import pytest

from helpers.context.scan_context import MIN_UNCOMPRESSED_FOR_RATIO, safe_extract_zip


def _zip_of(name: str, payload: bytes) -> Path:
    handle = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    handle.close()
    path = Path(handle.name)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, payload)
    return path


def test_small_sparse_archive_extracts() -> None:
    payload = b"\0" * (2 * 1024 * 1024)
    archive = _zip_of("ruvector.db", payload)
    try:
        with zipfile.ZipFile(archive) as opened:
            info = opened.infolist()[0]
            assert info.file_size / info.compress_size > 100
            assert info.file_size < MIN_UNCOMPRESSED_FOR_RATIO
        with tempfile.TemporaryDirectory() as dest:
            safe_extract_zip(str(archive), dest)
            assert (Path(dest) / "ruvector.db").stat().st_size == len(payload)
    finally:
        archive.unlink(missing_ok=True)


def test_large_high_ratio_archive_is_rejected() -> None:
    payload = b"\0" * (MIN_UNCOMPRESSED_FOR_RATIO + 1024 * 1024)
    archive = _zip_of("bomb.bin", payload)
    try:
        with tempfile.TemporaryDirectory() as dest:
            with pytest.raises(ValueError, match="zip bomb"):
                safe_extract_zip(str(archive), dest)
    finally:
        archive.unlink(missing_ok=True)


def _zip_entries(entries: dict[str, bytes]) -> Path:
    handle = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    handle.close()
    path = Path(handle.name)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return path


def test_names_the_filesystem_cannot_hold_are_skipped_not_fatal() -> None:
    # found by the AWS lab hostile suite: one 255+ byte name or a 2000-deep path failed the whole upload
    deep = "/".join(f"d{i:03d}" for i in range(2000)) + "/x.py"
    archive = _zip_entries({"a" * 300 + ".py": b"x", deep: b"x", "src/app.py": b"import hashlib\n"})
    try:
        with tempfile.TemporaryDirectory() as dest:
            safe_extract_zip(str(archive), dest)
            assert (Path(dest) / "src" / "app.py").read_bytes() == b"import hashlib\n"
            assert not (Path(dest) / "d000").exists()
    finally:
        archive.unlink()


def test_traversal_is_still_refused_including_sibling_prefixes() -> None:
    with tempfile.TemporaryDirectory() as dest:
        for name in ("../../evil.txt", "/tmp/zs_abs.txt", "../" + Path(dest).name + "x/evil.txt"):
            archive = _zip_entries({name: b"x"})
            try:
                with pytest.raises(ValueError, match="Path traversal"):
                    safe_extract_zip(str(archive), dest)
            finally:
                archive.unlink()


def test_a_refused_archive_leaves_nothing_in_tmp(monkeypatch) -> None:
    # found by the AWS lab hostile suite: 8 partial /tmp/repo_* trees after refused uploads
    from helpers.context import scan_context

    archive = _zip_entries({"../../evil.txt": b"x"})
    made = []
    real_mkdtemp = tempfile.mkdtemp
    monkeypatch.setattr(scan_context, "download_zip_file", lambda bucket, key: str(archive))
    monkeypatch.setattr(scan_context.tempfile, "mkdtemp", lambda **kw: made.append(real_mkdtemp(**kw)) or made[-1])
    with pytest.raises(ValueError, match="Path traversal"):
        scan_context.get_directory_from_zip_context(scan_context.ZipContext(bucket_name="b", object_name="o"))
    assert made and not Path(made[0]).exists() and not archive.exists()
