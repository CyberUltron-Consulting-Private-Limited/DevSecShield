"""The files a CBOM scan reads: one walk, one skip-directory set, never a symbolic link.

A cloned repository or an uploaded archive is attacker-controlled. A committed link such as
``deploy/key.pem -> /proc/self/environ`` would make a scanner read the worker's environment into the evidence, and
a link to a directory outside the tree would walk the host. So:

* the walk never follows a link (file or directory) and never yields one;
* every read opens the file with ``O_NOFOLLOW`` and checks it is a regular file of at most ``MAX_FILE_BYTES``
  (a link or FIFO swapped in after the walk is refused too);
* tool, cache, VCS and virtual-environment directories (:data:`SKIP_DIRS`) are never entered;
* third-party and build output (:data:`VENDORED_DIRS`: ``vendor/``, ``dist/``, ``build/``, ``node_modules/``)
  is entered only when the scan opts in (``include_vendored``).

What was left out is counted and reported on the scan as coverage properties (``crypto:coverage:*``), so a
reader knows which files the inventory does not cover and why.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path

from aibom.cbom.archives import (
    ARCHIVE_SUFFIXES,
    KEY_SUFFIXES,
    MAX_ARCHIVE_BYTES,
    ArchiveBudget,
    VirtualFile,
    archive_members,
)
from aibom.cbom.notebook import MAX_NOTEBOOK_BYTES, is_notebook, virtual_source

#: Directories no lane ever enters: VCS metadata, caches, virtual environments and generated IaC state.
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git", ".hg", ".svn",
        ".venv", "venv", "site-packages", "__pycache__",
        ".tox", ".mypy_cache", ".pytest_cache",
        ".next", ".nuxt", "target",
        ".terraform", ".terragrunt-cache", "cdk.out", ".serverless", ".aws-sam",
    }
)

#: Third-party and build output: scanned only when the scan option ``include_vendored`` is on.
VENDORED_DIRS: frozenset[str] = frozenset({"vendor", "dist", "build", "node_modules"})

MAX_FILE_BYTES = 2_000_000
_NUL_PROBE = 8192
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def skipped_dirs(include_vendored: bool = False) -> frozenset[str]:
    """The directory names a walk does not enter."""
    return SKIP_DIRS if include_vendored else SKIP_DIRS | VENDORED_DIRS


def read_bytes(path: Path, max_bytes: int = MAX_FILE_BYTES) -> bytes | None:
    """The bytes of ``path`` if it is a regular file (not a link, FIFO or device) of at most ``max_bytes``."""
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            return None
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        return None if len(raw) > max_bytes else raw
    except OSError:
        return None
    finally:
        os.close(fd)


def decode_text(raw: bytes) -> str:
    """Text as ``Path.read_text(encoding="utf-8", errors="ignore")`` returns it (universal newlines); a UTF-16 file
    with a byte-order mark is decoded as UTF-16."""
    text = None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            text = None
    if text is None:
        text = raw.decode("utf-8", errors="ignore")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def is_vendored(rel: str) -> bool:
    """A repository path inside third-party or build output (``vendor/``, ``dist/``, ``build/``,
    ``node_modules/``)."""
    return any(part in VENDORED_DIRS for part in rel.split("!", 1)[0].split("/")[:-1])


def read_notebook(path: Path) -> str | None:
    """The virtual source of a Jupyter notebook (code cells + text outputs), or None."""
    raw = read_bytes(path, MAX_NOTEBOOK_BYTES)
    if raw is None:
        return None
    vs = virtual_source(raw)
    return vs[0] if vs is not None else None


def looks_binary(raw: bytes) -> bool:
    return not raw.startswith((b"\xff\xfe", b"\xfe\xff")) and b"\x00" in raw[:_NUL_PROBE]


class FileWalk:
    """One sorted walk of a scan root, shared by every lane of a scan (see the module docstring)."""

    def __init__(self, root: Path, *, include_vendored: bool = False) -> None:
        self.root = Path(root)
        self.include_vendored = include_vendored
        self._files: list[tuple[Path, int]] | None = None
        self.skipped_links: set[str] = set()
        self.skipped_oversized: set[str] = set()
        self.skipped_binary: set[str] = set()
        self.skipped_vendored: set[str] = set()
        # Git history of the tree's own ``.git``: None = read it unless it is a shallow clone, True = read it
        # even when shallow (history depth opted in), False = never.
        self.scan_history: bool | None = None
        self._virtual: list[VirtualFile] | None = None
        self.archive_budget = ArchiveBudget()
        self.history_coverage: dict[str, str] = {}

    def virtual_files(self) -> list[VirtualFile]:
        """Key / certificate files that are not on disk under their own path: members of archives in the tree
        (``outer.zip!inner/key.pem``, see :mod:`aibom.cbom.archives`) and blobs only in git history
        (:mod:`aibom.cbom.githistory`). Read once per scan."""
        if self._virtual is None:
            from aibom.cbom.githistory import history_key_files

            archives = self.files(lambda p: p.name.lower().endswith(ARCHIVE_SUFFIXES), max_bytes=MAX_ARCHIVE_BYTES)
            found = archive_members(self.root, archives, self.archive_budget)
            if self.scan_history is not False:
                tree = {self.rel(p): p for p in self.files(lambda p: p.name.lower().endswith(KEY_SUFFIXES))}
                history, self.history_coverage = history_key_files(self.root, tree, force=bool(self.scan_history))
                skip = skipped_dirs(self.include_vendored)  # the walk's own rule applies to history paths too
                found.extend(h for h in history if not skip.intersection(h.rel.split("/")[:-1]))
            self._virtual = found
        return self._virtual

    def _walk(self) -> list[tuple[Path, int]]:
        skip = skipped_dirs(self.include_vendored)
        found: list[tuple[Path, int]] = []
        pending = [self.root]
        while pending:
            current = pending.pop()
            try:
                entries = list(os.scandir(current))
            except OSError:
                continue
            for entry in entries:
                rel = os.path.relpath(entry.path, self.root).replace(os.sep, "/")
                try:
                    if entry.is_symlink():
                        self.skipped_links.add(rel)
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name in SKIP_DIRS:
                            continue
                        if entry.name in skip or Path(current).name == "node_modules":
                            # opted in, ``node_modules/`` still contributes only its loose files: the packages
                            # under it are dependencies (the dependency lane's subject), not this project's code
                            self.skipped_vendored.add(rel)
                            continue
                        pending.append(Path(entry.path))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue  # FIFO, socket, device
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
                found.append((Path(entry.path), size))
        return sorted(found)

    def files(
        self, keep: Callable[[Path], bool] | None = None, *, max_bytes: int = MAX_FILE_BYTES
    ) -> list[Path]:
        """Regular files under the root (sorted like ``sorted(root.rglob("*"))``) that ``keep`` selects and that
        fit ``max_bytes``; a selected file over the limit is recorded as skipped."""
        if self._files is None:
            self._files = self._walk()
        out: list[Path] = []
        for path, size in self._files:
            if keep is not None and not keep(path):
                continue
            # a notebook's JSON carries its images; its size limit applies to the code read from it (read_text)
            if size > (max(max_bytes, MAX_NOTEBOOK_BYTES) if is_notebook(path.name) else max_bytes):
                self.skipped_oversized.add(self.rel(path))
                continue
            out.append(path)
        return out

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def read_bytes(self, path: Path, max_bytes: int = MAX_FILE_BYTES) -> bytes | None:
        return read_bytes(path, max_bytes)

    def read_text(self, path: Path, max_bytes: int = MAX_FILE_BYTES) -> str | None:
        """Decoded source text, or None when the file is unreadable or binary (counted as skipped). A notebook
        reads as its virtual source (:mod:`aibom.cbom.notebook`)."""
        if is_notebook(path.name):
            text = read_notebook(path)
            if text is not None and len(text.encode("utf-8", "ignore")) > max_bytes:
                self.skipped_oversized.add(self.rel(path))
                return None
            return text
        raw = read_bytes(path, max_bytes)
        if raw is None:
            return None
        if looks_binary(raw):
            self.skipped_binary.add(self.rel(path))
            return None
        return decode_text(raw)

    def coverage(self) -> dict[str, str]:
        """Scan properties naming what the walk left out (only the non-zero counts)."""
        out: dict[str, str] = {}
        for name, items in (
            ("crypto:coverage:skippedSymlinks", self.skipped_links),
            ("crypto:coverage:skippedOversized", self.skipped_oversized),
            ("crypto:coverage:skippedBinary", self.skipped_binary),
            ("crypto:coverage:skippedVendoredDirs", self.skipped_vendored),
        ):
            if items:
                out[name] = str(len(items))
        if self.include_vendored:
            out["crypto:coverage:vendoredIncluded"] = "true"
        out.update(self.archive_budget.coverage())
        out.update(self.history_coverage)
        return out


def file_walk(ctx: object) -> FileWalk:
    """The scan's shared walk (created on first use for a plain ``ScanContext``)."""
    walk = getattr(ctx, "file_walk", None)
    if not isinstance(walk, FileWalk):
        walk = FileWalk(ctx.root)  # type: ignore[attr-defined]
        ctx.file_walk = walk  # type: ignore[attr-defined]
    return walk


__all__ = [
    "MAX_FILE_BYTES",
    "SKIP_DIRS",
    "VENDORED_DIRS",
    "FileWalk",
    "decode_text",
    "file_walk",
    "is_vendored",
    "looks_binary",
    "read_bytes",
    "read_notebook",
    "skipped_dirs",
]
