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
