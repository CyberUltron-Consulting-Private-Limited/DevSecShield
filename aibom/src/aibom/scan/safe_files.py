"""The files an AI-BOM scan reads: never through a symbolic link.

A cloned repository or an uploaded archive is attacker-controlled. A committed
``key.pem -> /proc/self/environ`` would put the worker's environment into the BOM,
and a link to a directory outside the tree would walk the host. The CBOM lanes read
through :mod:`aibom.cbom.files`; the AI-BOM scanners follow the same rules:

* :func:`walk_files` never follows a link (file or directory) and never yields one;
  the directory names a scanner skips are not entered; every yielded path resolves
  inside the scan root;
* :func:`read_text` / :func:`open_regular` open with ``O_NOFOLLOW`` and accept only
  a regular file (a link, FIFO or device swapped in after the walk is refused too),
  reusing :func:`aibom.cbom.files.read_bytes`;
* :func:`is_regular_file` replaces ``Path.is_file()`` for one known path such as
  ``root / "requirements.txt"``: true only for a regular file that is not a link.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import BinaryIO

from aibom.cbom.files import decode_text, read_bytes

#: Largest text file an AI-BOM scanner reads (manifests, cards, configuration, source).
MAX_TEXT_BYTES = 8_000_000
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def walk_files(
    root: Path,
    skip_dirs: Iterable[str] = (),
    keep: Callable[[Path], bool] | None = None,
) -> list[Path]:
    """Regular files under ``root`` that ``keep`` selects, sorted like
    ``sorted(root.rglob("*"))``. Links are neither followed nor yielded; a directory
    whose name is in ``skip_dirs`` is not entered."""
    root = Path(root)
    skip = frozenset(skip_dirs)
    try:
        resolved_root = root.resolve()
    except (OSError, RuntimeError):
        return []
    found: list[Path] = []
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in skip:
                        pending.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue  # FIFO, socket, device
            except OSError:
                continue
            path = Path(entry.path)
            if (keep is None or keep(path)) and _inside(path, resolved_root):
                found.append(path)
    return sorted(found)


def is_regular_file(path: Path) -> bool:
    """``path`` is a regular file and not a link (``Path.is_file()`` follows links)."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except (OSError, ValueError):
        return False


def read_text(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> str | None:
    """Decoded text of a regular, non-link file of at most ``max_bytes``, else None."""
    raw = read_bytes(Path(path), max_bytes)
    return None if raw is None else decode_text(raw)


def open_regular(path: Path) -> BinaryIO:
    """A binary file object for a regular, non-link file of any size (for streaming).

    Raises ``OSError`` for a link, FIFO, device or missing file."""
    fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {Path(path).name}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


__all__ = [
    "MAX_TEXT_BYTES",
    "is_regular_file",
    "open_regular",
    "read_text",
    "walk_files",
]
