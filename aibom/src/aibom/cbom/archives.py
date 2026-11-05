"""Key and certificate files inside archives the repository carries (``.zip``, ``.jar``, ``.war``, ``.ear``).

An upload is extracted once by the worker; an archive committed INSIDE the repository (``assets/bundle.zip``) or a
jar in ``lib/`` is not, and a key packed into it was invisible. This module reads such archives in memory (never
extracting to disk), recursing into nested archives, and returns their key / certificate members as
:class:`VirtualFile` objects named ``outer.zip!inner/path`` for the key/certificate lane.

One budget is shared by every archive of a scan and every nesting level: total bytes read, members visited,
nesting depth (:data:`MAX_DEPTH`) and the compression ratio of a member (a zip bomb lies in its headers, so the
read itself is capped too). An archive whose central directory is too large to parse (:data:`MAX_DIRECTORY_BYTES`)
is not opened. Encrypted members, unsupported compression and corrupt archives or members are not read; they are
counted as coverage (``crypto:coverage:archive*``), never a failed scan. Only key/certificate members are returned:
other members (source code in a jar) are counted as not scanned.
"""

from __future__ import annotations

import io
import lzma
import os
import stat
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ARCHIVE_SUFFIXES = (".zip", ".jar", ".war", ".ear")
#: Key / certificate member suffixes (the certificate lane's set plus keystores).
KEY_SUFFIXES = (".pem", ".crt", ".cer", ".cert", ".der", ".ca-bundle", ".key", ".pub", ".p7b", ".p7c", ".gpg",
                ".asc", ".jks", ".p12", ".pfx")
MAX_DEPTH = 3
MAX_ARCHIVE_BYTES = 256_000_000  # an archive on disk larger than this is not opened
MAX_NESTED_BYTES = 16_000_000  # an inner archive is read into memory up to this size
MAX_MEMBER_BYTES = 2_000_000
MAX_TOTAL_BYTES = 64_000_000
MAX_MEMBERS = 20_000
MAX_RATIO = 200
#: ``zipfile`` turns the whole central directory into ZipInfo objects (about 9x its size in memory) before the
#: first member is read, bounding that parse by the directory's byte length, not its entry count. An archive
#: whose directory is larger than this (about 80,000 entries of real names) is not opened.
MAX_DIRECTORY_BYTES = 8_000_000
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass
class VirtualFile:
    """A file that is not on disk under its own path: an archive member or a blob from git history."""

    rel: str
    data: bytes
    props: dict[str, str] = field(default_factory=dict)

    @property
    def suffix(self) -> str:
        name = self.rel.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
        # A history blob that differs from the working-tree file at its path is named ``path@<commit[:12]>``
        # (aibom.cbom.githistory); only that tag is dropped: ``alice@example.com.crt`` keeps its suffix.
        commit = self.props.get("crypto:gitCommit", "")
        if commit and name.endswith(f"@{commit[:12]}"):
            name = name[: -len(commit[:12]) - 1]
        return ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""


#: Limits of the binary / image / firmware lane (scan option ``scan_binaries``). The same budget object carries
#: them, so the zip key lane and the unpacker of :mod:`aibom.cbom.unpack` share one count per scan.
BINARY_TOTAL_BYTES = 2_000_000_000  # decompressed bytes produced across every archive, layer and level
BINARY_MEMBERS = 400_000


@dataclass
class ArchiveBudget:
    bytes_read: int = 0
    members: int = 0
    skipped_encrypted: int = 0
    skipped_unsupported: int = 0
    skipped_budget: int = 0
    skipped_depth: int = 0
    skipped_directory: int = 0  # archives whose central directory is over the cap (never opened)
    not_scanned: int = 0
    # limits (raised for a scan with ``scan_binaries``; see :func:`ArchiveBudget.for_binaries`)
    max_total_bytes: int = MAX_TOTAL_BYTES
    max_members: int = MAX_MEMBERS
    # members refused by the unpacker (never read): reason -> count (see :mod:`aibom.cbom.unpack`)
    refused: dict[str, int] = field(default_factory=dict)

    @classmethod
    def for_binaries(cls) -> "ArchiveBudget":
        return cls(max_total_bytes=BINARY_TOTAL_BYTES, max_members=BINARY_MEMBERS)

    def refuse(self, reason: str, n: int = 1) -> None:
        self.refused[reason] = self.refused.get(reason, 0) + n

    def take(self, n: int) -> bool:
        """Account ``n`` decompressed bytes; False (and counted) when that passes the scan's total."""
        if self.bytes_read + n > self.max_total_bytes:
            self.skipped_budget += 1
            return False
        self.bytes_read += n
        return True

    def coverage(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for name, value in (
            ("crypto:coverage:archiveEncrypted", self.skipped_encrypted),
            ("crypto:coverage:archiveUnsupported", self.skipped_unsupported),
            ("crypto:coverage:archiveBudgetExceeded", self.skipped_budget),
            ("crypto:coverage:archiveTooDeep", self.skipped_depth),
            ("crypto:coverage:archiveDirectoryTooLarge", self.skipped_directory),
            ("crypto:coverage:archiveMembersNotScanned", self.not_scanned),
        ):
            if value:
                out[name] = str(value)
        for reason, value in sorted(self.refused.items()):
            if value:
                out[f"crypto:coverage:unpackRefused:{reason}"] = str(value)
        return out


def open_zip(fh, budget: ArchiveBudget) -> zipfile.ZipFile | None:
    """``zipfile.ZipFile(fh)``, or None (counted) when the end record shows a central directory too large to parse:
    over :data:`MAX_DIRECTORY_BYTES`, or more entries than twice the scan's member budget. The end record is read
    with ``zipfile``'s own reader, so the size checked is the size ``zipfile`` then parses. Raises
    ``zipfile.BadZipFile`` / ``OSError`` as ``zipfile.ZipFile`` does."""
    zipmod: Any = zipfile  # its end-record reader and field indexes are private (no stubs)
    end = zipmod._EndRecData(fh)
    if not end:
        raise zipfile.BadZipFile("File is not a zip file")
    if end[zipmod._ECD_SIZE] > MAX_DIRECTORY_BYTES or end[zipmod._ECD_ENTRIES_TOTAL] > 2 * budget.max_members:
        budget.skipped_directory += 1
        return None
    return zipfile.ZipFile(fh)


def _member_name(name: str) -> str:
    return "/".join(p for p in name.replace("\\", "/").split("/") if p not in ("", ".", ".."))


def _read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int, budget: ArchiveBudget) -> bytes | None:
    if info.flag_bits & 0x1:
        budget.skipped_encrypted += 1
        return None
    if info.file_size > limit or (info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_RATIO) \
            or budget.bytes_read + info.file_size > budget.max_total_bytes:
        budget.skipped_budget += 1
        return None
    chunks: list[bytes] = []
    got = 0
    try:
        with zf.open(info) as fh:
            while True:
                chunk = fh.read(1 << 16)
                if not chunk:
                    break
                got += len(chunk)
                if got > limit or got > info.file_size or budget.bytes_read + got > budget.max_total_bytes:
                    budget.skipped_budget += 1  # the header lied about the size
                    return None
                chunks.append(chunk)
    except NotImplementedError:
        budget.skipped_unsupported += 1
        return None
    except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, ValueError, zlib.error, lzma.LZMAError):
        budget.skipped_unsupported += 1  # a corrupt deflate / LZMA stream raises its codec's own error
        return None
    budget.bytes_read += got
    return b"".join(chunks)


def _walk_archive(zf: zipfile.ZipFile, label: str, depth: int, budget: ArchiveBudget, out: list[VirtualFile]) -> None:
    try:
        infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
        budget.skipped_unsupported += 1
        return
    for info in sorted(infos, key=lambda i: i.filename):
        if info.is_dir():
            continue
        budget.members += 1
        if budget.members > budget.max_members:
            budget.skipped_budget += 1
            return
        name = _member_name(info.filename)
        low = name.lower()
        rel = f"{label}!{name}"
        if low.endswith(ARCHIVE_SUFFIXES):
            if depth >= MAX_DEPTH:
                budget.skipped_depth += 1
                continue
            data = _read_member(zf, info, MAX_NESTED_BYTES, budget)
            if data is None:
                continue
            try:
                inner = open_zip(io.BytesIO(data), budget)
                if inner is not None:
                    with inner:
                        _walk_archive(inner, rel, depth + 1, budget, out)
            except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
                budget.skipped_unsupported += 1
            continue
        if not low.endswith(KEY_SUFFIXES):
            budget.not_scanned += 1
            continue
        data = _read_member(zf, info, MAX_MEMBER_BYTES, budget)
        if data is not None:
            out.append(VirtualFile(rel, data, {"crypto:archive": label.split("!", 1)[0]}))


def archive_members(root: Path, archives: list[Path], budget: ArchiveBudget) -> list[VirtualFile]:
    """Key/certificate members of ``archives`` (files under ``root``), recursing into nested archives."""
    out: list[VirtualFile] = []
    for path in archives:
        try:
            fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
        except OSError:
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE_BYTES:
                budget.skipped_budget += 1
                continue
            with os.fdopen(os.dup(fd), "rb") as fh:
                zf = open_zip(fh, budget)
                if zf is not None:
                    with zf:
                        _walk_archive(zf, path.relative_to(root).as_posix(), 1, budget, out)
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
            budget.skipped_unsupported += 1
        finally:
            os.close(fd)
    return out


__all__ = ["ARCHIVE_SUFFIXES", "ArchiveBudget", "KEY_SUFFIXES", "VirtualFile", "archive_members", "open_zip"]
