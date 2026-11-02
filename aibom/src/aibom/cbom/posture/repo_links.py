"""Code the scan cannot see: Git submodules that were not checked out and Git LFS objects left as pointers.

A clone without ``--recurse-submodules`` (or an upload made from one) leaves each submodule directory empty, and a
clone without ``git lfs pull`` leaves each LFS-tracked file as a small pointer (``version
https://git-lfs.github.com/spec/v1`` / ``oid sha256:…`` / ``size …``, https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md).
Neither is scanned, so each is reported (a ``submodule_not_scanned`` / ``lfs_object_not_scanned`` diagnostic and a
``crypto:coverage:*`` count on the scan) instead of the inventory silently looking complete. Nothing is fetched.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

from aibom.cbom.files import FileWalk

_SUBMODULE_PATH = re.compile(r"^\s*path\s*=\s*(.{1,512}?)\s*$")
_LFS_FILTER = re.compile(r"(?:^|\s)filter=lfs(?:\s|$)")
_LFS_HEAD = b"version https://git-lfs.github.com/spec/v1"
_POINTER_MAX = 1024  # the spec caps a pointer file at 1024 bytes
_CAP = 200

SUBMODULES_PROPERTY = "crypto:coverage:submodulesNotScanned"
LFS_PROPERTY = "crypto:coverage:lfsObjectsNotScanned"


def _checked_out(root: Path, rel: str) -> bool:
    """True when the submodule directory holds files (anything besides its ``.git`` link)."""
    path = root / rel
    if path.is_symlink() or not path.is_dir():
        return False
    try:
        return any(entry.name != ".git" for entry in os.scandir(path))
    except OSError:
        return False


def missing_submodules(walk: FileWalk) -> list[str]:
    """Submodule paths declared in any ``.gitmodules`` of the tree whose content is absent."""
    found: list[str] = []
    for gitmodules in walk.files(lambda p: p.name == ".gitmodules"):
        text = walk.read_text(gitmodules)
        if text is None:
            continue
        base = PurePosixPath(walk.rel(gitmodules)).parent
        for line in text.splitlines():
            matched = _SUBMODULE_PATH.match(line)
            if not matched:
                continue
            raw = matched.group(1).strip().strip('"')
            rel = str(base / raw) if str(base) != "." else raw
            if ".." in PurePosixPath(rel).parts or rel.startswith("/"):
                continue
            if not _checked_out(walk.root, rel) and rel not in found:
                found.append(rel)
    return found[:_CAP]


def lfs_pointers(walk: FileWalk) -> list[str]:
    """Files that are still Git LFS pointers (only looked for when a ``.gitattributes`` routes files through LFS)."""
    uses_lfs = False
    for attributes in walk.files(lambda p: p.name == ".gitattributes"):
        text = walk.read_text(attributes)
        if text is not None and any(_LFS_FILTER.search(line) for line in text.splitlines()):
            uses_lfs = True
            break
    if not uses_lfs:
        return []
    found: list[str] = []

    def small(path: Path) -> bool:
        try:
            return path.lstat().st_size <= _POINTER_MAX
        except OSError:
            return False

    for path in walk.files(small, max_bytes=_POINTER_MAX):
        raw = walk.read_bytes(path, _POINTER_MAX)
        if raw is not None and raw.startswith(_LFS_HEAD):
            found.append(walk.rel(path))
            if len(found) >= _CAP:
                break
    return found


__all__ = ["LFS_PROPERTY", "SUBMODULES_PROPERTY", "lfs_pointers", "missing_submodules"]
