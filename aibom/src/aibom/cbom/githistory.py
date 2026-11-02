"""Key and certificate files that exist only in a repository's git history.

A key committed and later deleted is still in every clone: ``git log --all -- config/deploy.key`` gives it back.
When the scanned tree carries its ``.git`` directory (an uploaded archive of a working copy, or a clone made with
history), this module reads the object store directly — loose objects and pack files (``.idx`` v2 + ``.pack`` with
offset / reference deltas), zlib only — and returns the blobs whose PATH looks like key or certificate material and
that differ from what the working tree holds at that path.

It never runs the git binary and never reads ``.git/config`` (a hostile config can run commands through git);
only ``HEAD``, ``packed-refs``, ``refs/`` and ``objects/`` are opened, each without following symbolic links.
Bounded: commits walked, tree objects read, blob bytes read; what was left out is reported as coverage.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import struct
import zlib
from collections import deque
from pathlib import Path

from aibom.cbom.archives import KEY_SUFFIXES, VirtualFile

MAX_COMMITS = 1_000
MAX_TREES = 50_000
MAX_BLOB_BYTES = 2_000_000
MAX_TOTAL_BYTES = 32_000_000
MAX_PACK_BYTES = 2_000_000_000
_MAX_REF_FILES = 5_000
_MAX_DELTA_DEPTH = 64
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_SHA = re.compile(rb"^[0-9a-f]{40}$")
_TYPES = {1: b"commit", 2: b"tree", 3: b"blob", 4: b"tag"}


def _read(path: Path, limit: int) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        with os.fdopen(os.dup(fd), "rb") as fh:
            return fh.read(limit + 1)
    except OSError:
        return None
    finally:
        os.close(fd)


def _is_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


class _Pack:
    def __init__(self, idx: bytes, pack_path: Path) -> None:
        if idx[:4] != b"\xfftOc" or struct.unpack(">I", idx[4:8])[0] != 2:
            raise ValueError("unsupported pack index")
        count = struct.unpack(">I", idx[8 + 255 * 4: 8 + 256 * 4])[0]
        names = 8 + 256 * 4
        offsets32 = names + 20 * count + 4 * count
        offsets64 = offsets32 + 4 * count
        self.offsets: dict[bytes, int] = {}
        for i in range(count):
            sha = idx[names + 20 * i: names + 20 * (i + 1)].hex().encode()
            off = struct.unpack(">I", idx[offsets32 + 4 * i: offsets32 + 4 * (i + 1)])[0]
            if off & 0x80000000:
                j = off & 0x7FFFFFFF
                off = struct.unpack(">Q", idx[offsets64 + 8 * j: offsets64 + 8 * (j + 1)])[0]
            self.offsets[sha] = off
        self.path = pack_path
        self.fh = None

    def open(self):
        if self.fh is None:
            fd = os.open(self.path, os.O_RDONLY | _O_NOFOLLOW)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PACK_BYTES:
                os.close(fd)
                raise ValueError("not a pack file")
            self.fh = os.fdopen(fd, "rb")
        return self.fh


class GitObjects:
    """Read-only object store of one ``.git`` directory (see the module docstring)."""

    def __init__(self, git_dir: Path) -> None:
        self.git_dir = git_dir
        self.objects = git_dir / "objects"
        self.packs: list[_Pack] = []
        pack_dir = self.objects / "pack"
        if _is_dir(pack_dir):
            for idx_path in sorted(pack_dir.glob("pack-*.idx")):
                idx = _read(idx_path, 512_000_000)
                pack_path = idx_path.with_suffix(".pack")
                if idx is None:
                    continue
                try:
                    self.packs.append(_Pack(idx, pack_path))
                except (ValueError, struct.error):
                    continue
        self.bytes_read = 0

    def close(self) -> None:
        for pack in self.packs:
            if pack.fh is not None:
                pack.fh.close()

    def get(self, sha: bytes, depth: int = 0) -> tuple[bytes, bytes] | None:
        """(type, content) of object ``sha`` (40 hex bytes), or None."""
        if not _SHA.match(sha) or depth > _MAX_DELTA_DEPTH:
            return None
        fan = self.objects / sha[:2].decode()
        raw = _read(fan / sha[2:].decode(), 64_000_000) if _is_dir(fan) else None  # a linked fan-out dir: no
        if raw is not None:
            try:
                data = zlib.decompressobj().decompress(raw, MAX_TOTAL_BYTES)
            except zlib.error:
                return None
            head, _, body = data.partition(b"\0")
            kind = head.split(b" ", 1)[0]
            self.bytes_read += len(body)
            return kind, body
        for pack in self.packs:
            off = pack.offsets.get(sha)
            if off is not None:
                return self._from_pack(pack, off, depth)
        return None

    def _from_pack(self, pack: _Pack, offset: int, depth: int) -> tuple[bytes, bytes] | None:
        if depth > _MAX_DELTA_DEPTH:
            return None
        try:
            fh = pack.open()
            fh.seek(offset)
            byte = fh.read(1)[0]
            kind = (byte >> 4) & 7
            size = byte & 15
            shift = 4
            while byte & 0x80:
                byte = fh.read(1)[0]
                size |= (byte & 0x7F) << shift
                shift += 7
            if size > MAX_TOTAL_BYTES:
                return None
            base: tuple[bytes, bytes] | None = None
            if kind == 6:  # OFS_DELTA: base at a negative offset
                byte = fh.read(1)[0]
                rel = byte & 0x7F
                while byte & 0x80:
                    byte = fh.read(1)[0]
                    rel = ((rel + 1) << 7) | (byte & 0x7F)
                here = fh.tell()
                base = self._from_pack(pack, offset - rel, depth + 1)
                fh.seek(here)
            elif kind == 7:  # REF_DELTA: base by name
                base_sha = fh.read(20).hex().encode()
                here = fh.tell()
                base = self.get(base_sha, depth + 1)
                fh.seek(here)
            elif kind not in _TYPES:
                return None
            d = zlib.decompressobj()
            out = bytearray()
            while len(out) < size:
                chunk = fh.read(1 << 16)
                if not chunk:
                    break
                out += d.decompress(chunk, size - len(out))
                if d.eof:
                    break
            data = bytes(out)
            self.bytes_read += len(data)
            if kind in (6, 7):
                if base is None:
                    return None
                return base[0], _apply_delta(base[1], data)
            return _TYPES[kind], data
        except (OSError, ValueError, IndexError, zlib.error):
            return None


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def _apply_delta(base: bytes, delta: bytes) -> bytes:
    _, pos = _varint(delta, 0)  # source size
    size, pos = _varint(delta, pos)
    if size > MAX_TOTAL_BYTES:
        raise ValueError("delta too large")
    out = bytearray()
    while pos < len(delta):
        op = delta[pos]
        pos += 1
        if op & 0x80:  # copy from base
            off = length = 0
            for i in range(4):
                if op & (1 << i):
                    off |= delta[pos] << (8 * i)
                    pos += 1
            for i in range(3):
                if op & (1 << (4 + i)):
                    length |= delta[pos] << (8 * i)
                    pos += 1
            out += base[off: off + (length or 0x10000)]
        elif op:  # insert literal
            out += delta[pos: pos + op]
            pos += op
        else:
            raise ValueError("bad delta opcode")
    return bytes(out)


def _heads(git_dir: Path) -> list[bytes]:
    """Commit names of HEAD, every branch / tag ref and packed-refs (no config, no remotes' URLs)."""
    shas: list[bytes] = []
    head = _read(git_dir / "HEAD", 4096) or b""
    if _SHA.match(head.strip()):
        shas.append(head.strip())
    packed = _read(git_dir / "packed-refs", 64_000_000) or b""
    for line in packed.splitlines():
        part = line.split(b" ", 1)[0].strip()
        if _SHA.match(part):
            shas.append(part)
    refs = git_dir / "refs"
    seen = 0
    if _is_dir(refs):
        for dirpath, _dirnames, filenames in os.walk(refs, followlinks=False):
            for name in sorted(filenames):
                seen += 1
                if seen > _MAX_REF_FILES:
                    break
                value = (_read(Path(dirpath) / name, 4096) or b"").strip()
                if _SHA.match(value):
                    shas.append(value)
    return list(dict.fromkeys(shas))


def _tree_entries(data: bytes) -> list[tuple[bytes, str, bytes]]:
    out: list[tuple[bytes, str, bytes]] = []
    pos = 0
    while pos < len(data):
        sp = data.index(b" ", pos)
        nul = data.index(b"\0", sp)
        mode = data[pos:sp]
        name = data[sp + 1: nul].decode("utf-8", "replace")
        sha = data[nul + 1: nul + 21].hex().encode()
        out.append((mode, name, sha))
        pos = nul + 21
    return out


def _git_blob_sha(data: bytes) -> bytes:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest().encode()  # noqa: S324 (git object name)


def history_key_files(
    root: Path, tree_files: dict[str, Path] | None = None, *, force: bool = False
) -> tuple[list[VirtualFile], dict[str, str]]:
    """Key/certificate blobs from the history of ``root/.git`` that the working tree does not hold as they were.

    ``tree_files`` maps the working tree's key/certificate paths (from the scan's walk, which never follows a
    link) to their files; a history path is only compared against those, never opened by name. A shallow
    repository (``.git/shallow``: the worker's depth-1 clone) is read only with ``force``. Returns the files and
    coverage properties."""
    tree_files = tree_files or {}
    git_dir = root / ".git"
    coverage: dict[str, str] = {}
    if not _is_dir(git_dir) or not _is_dir(git_dir / "objects"):
        return [], coverage
    if os.path.lexists(git_dir / "shallow") and not force:
        coverage["crypto:coverage:gitHistory"] = "shallow clone: history not read"
        return [], coverage
    store = GitObjects(git_dir)
    found: dict[tuple[str, bytes], VirtualFile] = {}
    try:
        queue = deque(_heads(git_dir))
        commits_seen: set[bytes] = set()
        trees_seen: set[bytes] = set()
        total = 0
        while queue and len(commits_seen) < MAX_COMMITS:
            sha = queue.popleft()
            if sha in commits_seen:
                continue
            commits_seen.add(sha)
            obj = store.get(sha)
            if obj is None or obj[0] != b"commit":
                continue
            tree = None
            for line in obj[1].split(b"\n"):
                if not line:
                    break
                if line.startswith(b"tree "):
                    tree = line[5:].strip()
                elif line.startswith(b"parent "):
                    queue.append(line[7:].strip())
            stack = [(tree, "")] if tree else []
            while stack and len(trees_seen) < MAX_TREES:
                tsha, prefix = stack.pop()
                if tsha in trees_seen:
                    continue
                trees_seen.add(tsha)
                tobj = store.get(tsha)
                if tobj is None or tobj[0] != b"tree":
                    continue
                for mode, name, esha in _tree_entries(tobj[1]):
                    if name in ("", ".", "..") or "/" in name or "\\" in name or "\0" in name:
                        continue  # not a name git writes; never part of a path
                    path = f"{prefix}{name}"
                    if mode in (b"40000", b"040000"):
                        stack.append((esha, path + "/"))
                    elif mode.startswith(b"100") and name.lower().endswith(KEY_SUFFIXES) and \
                            (path, esha) not in found and total < MAX_TOTAL_BYTES:
                        blob = store.get(esha)
                        if blob is None or blob[0] != b"blob" or len(blob[1]) > MAX_BLOB_BYTES:
                            continue
                        on_disk = tree_files.get(path)
                        current = _read(on_disk, MAX_BLOB_BYTES) if on_disk is not None else None
                        if current is not None and _git_blob_sha(current) == esha:
                            continue  # the working tree holds this exact file: scanned there
                        total += len(blob[1])
                        rel = path if current is None else f"{path}@{sha[:12].decode()}"
                        found[(path, esha)] = VirtualFile(rel, blob[1], {
                            "crypto:gitCommit": sha.decode(),
                            "crypto:historyOnly": "true" if current is None else "false",
                        })
        if queue:
            coverage["crypto:coverage:gitHistoryCommitsNotRead"] = str(len(queue))
        if len(trees_seen) >= MAX_TREES or total >= MAX_TOTAL_BYTES:
            coverage["crypto:coverage:gitHistoryBudgetExceeded"] = "true"
        coverage["crypto:coverage:gitHistoryCommits"] = str(len(commits_seen))
    finally:
        store.close()
    return sorted(found.values(), key=lambda v: v.rel), coverage


__all__ = ["GitObjects", "history_key_files"]
