"""Chunked, sha256-checked file download over SSM (CB-36 Tier V evidence).

``GetCommandInvocation`` returns at most ``INLINE_CAP`` characters of
``StandardOutputContent`` (24,000; the same cap the product transport refuses in
``backend/utilities/cbom_sources/transports/ssm.py``). One ``run`` of a HAR, a
node log or a screenshot archive therefore comes back cut. ``save_download``
reads the remote file in base64 chunks that each stay under that cap, checks
the length of every chunk, and checks the file's sha256 before any byte is
written. A stdout that is already at the cap is refused: it may be truncated,
and a truncated evidence file is not a bundle.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
from collections.abc import Callable
from pathlib import Path

# GetCommandInvocation.StandardOutputContent. Kept equal to transports.ssm.INLINE_CAP.
INLINE_CAP = 24_000
# base64 of a full chunk is 21,848 characters plus one newline: under the cap.
RAW_CHUNK = 16_384
MAX_BYTES = 64 * 1024 * 1024
_PATH = re.compile(r"/[A-Za-z0-9._-]{1,200}(?:/[A-Za-z0-9._-]{1,200})*")


class DownloadError(Exception):
    """The remote file was not saved. Nothing at the destination is a complete copy."""


def output_is_at_cap(text: str) -> bool:
    return len(text) >= INLINE_CAP


def check_remote_path(path: str) -> str:
    """An absolute path the shell can quote without treating any character as syntax."""
    if not isinstance(path, str) or _PATH.fullmatch(path) is None:
        raise DownloadError(
            "remote path must be absolute and use only letters, digits, '.', '_' and '-'"
        )
    parts = path.split("/")
    # parts[0] is "" because the path is absolute. Every later segment must be a real name.
    if parts[0] != "" or any(part in {"", ".", ".."} for part in parts[1:]):
        raise DownloadError("remote path has an empty or parent segment")
    return path


def header_command(remote: str) -> str:
    quoted = shlex.quote(check_remote_path(remote))
    return f"stat -c %s -- {quoted} && sha256sum -- {quoted}"


def chunk_command(remote: str, index: int, raw_chunk: int = RAW_CHUNK) -> str:
    quoted = shlex.quote(check_remote_path(remote))
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise DownloadError("chunk index")
    if isinstance(raw_chunk, bool) or not isinstance(raw_chunk, int) or raw_chunk < 1:
        raise DownloadError("chunk size")
    full_b64 = 4 * ((raw_chunk + 2) // 3)
    if full_b64 + 1 >= INLINE_CAP:
        raise DownloadError("chunk would meet the SSM stdout cap")
    return (
        f"dd if={quoted} bs={raw_chunk} skip={index} count=1 status=none | base64 -w 0"
    )


def parse_header(stdout: str) -> tuple[int, str]:
    if output_is_at_cap(stdout):
        raise DownloadError("the size header is at the SSM stdout cap")
    lines = stdout.splitlines()
    if len(lines) != 2:
        raise DownloadError("the size header is not a size line and a sha256 line")
    try:
        size = int(lines[0])
    except ValueError as exc:
        raise DownloadError("the remote size is not an integer") from exc
    if size < 0 or size > MAX_BYTES:
        raise DownloadError(f"remote size {size} is outside 0..{MAX_BYTES}")
    digest = lines[1].split()[0].lower() if lines[1].split() else ""
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise DownloadError("the remote sha256 is not 64 hex characters")
    return size, digest


def chunk_lengths(size: int, raw_chunk: int = RAW_CHUNK) -> list[int]:
    if size == 0:
        return []
    count, last = divmod(size, raw_chunk)
    lengths = [raw_chunk] * count
    if last:
        lengths.append(last)
    return lengths


def decode_chunk(stdout: str, expected_len: int) -> bytes:
    if output_is_at_cap(stdout):
        raise DownloadError(
            "a chunk is at the SSM stdout cap and may be truncated; it was not saved"
        )
    text = stdout[:-1] if stdout.endswith("\n") else stdout
    if text.endswith("\r"):
        text = text[:-1]
    if "\n" in text or "\r" in text or text != stdout.strip("\r\n"):
        raise DownloadError("a chunk is not a single base64 line")
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise DownloadError("a chunk is not valid base64") from exc
    if len(raw) != expected_len:
        raise DownloadError(f"a chunk is {len(raw)} bytes, not {expected_len}")
    return raw


def assemble(chunks: list[bytes], size: int, digest: str) -> bytes:
    body = b"".join(chunks)
    if len(body) != size:
        raise DownloadError("the downloaded length does not match the remote size")
    got = hashlib.sha256(body).hexdigest()
    if got != digest:
        raise DownloadError("the downloaded sha256 does not match the remote sha256")
    return body


def pull(run: Callable[[str], str], remote: str, raw_chunk: int = RAW_CHUNK) -> bytes:
    """Read ``remote`` through ``run(shell command) -> stdout``. Raises before returning a bad body."""
    check_remote_path(remote)
    size, digest = parse_header(run(header_command(remote)))
    lengths = chunk_lengths(size, raw_chunk)
    chunks = [
        decode_chunk(run(chunk_command(remote, index, raw_chunk)), length)
        for index, length in enumerate(lengths)
    ]
    return assemble(chunks, size, digest)


def write_verified(dest: Path, data: bytes) -> None:
    """Write ``data`` as a new file (mode 0600). An existing path, including a symlink, is left untouched."""
    dest = Path(dest)
    if dest.exists() or dest.is_symlink():
        raise DownloadError("destination already exists")
    tmp = dest.with_name(dest.name + ".partial")
    if tmp.exists() or tmp.is_symlink():
        raise DownloadError("a partial download is already at the destination")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise DownloadError("short write")
            view = view[written:]
    except Exception:
        os.close(fd)
        os.unlink(tmp)
        raise
    os.close(fd)
    if dest.exists() or dest.is_symlink():
        os.unlink(tmp)
        raise DownloadError("destination already exists")
    os.replace(tmp, dest)


def save_download(run: Callable[[str], str], remote: str, dest: Path,
                  raw_chunk: int = RAW_CHUNK) -> str:
    """Download and write. Returns the sha256 hex digest. On failure the destination is absent."""
    data = pull(run, remote, raw_chunk)
    write_verified(Path(dest), data)
    return hashlib.sha256(data).hexdigest()
