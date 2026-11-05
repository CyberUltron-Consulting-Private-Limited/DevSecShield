"""Key and certificate files that exist only in a repository's git history.

A key committed and later deleted is still in every clone: ``git log --all -- config/deploy.key`` gives it back.
When the scanned tree carries its ``.git`` directory (an uploaded archive of a working copy, or a clone made with
history), this module reads the object store directly — loose objects and pack files (``.idx`` v2 + ``.pack`` with
offset / reference deltas), zlib only — and returns the blobs whose PATH looks like key or certificate material and
that differ from what the working tree holds at that path.

It never runs the git binary and never reads ``.git/config`` (a hostile config can run commands through git);
only ``HEAD``, ``packed-refs``, ``refs/`` and ``objects/`` are opened, each without following symbolic links.

The ``.git`` of an uploaded archive is attacker-controlled, so the reader is bounded in memory and work, never by
trust in what the objects declare: commits walked, refs and parents waiting, tree objects read, history files and
their bytes, the size of one object (inflated or rebuilt from a delta, which must match the size it declares and
copy only from inside its base) and the total work of the read (bytes inflated plus bytes rebuilt). Pack indexes
(at most :data:`_MAX_PACKS`) are searched in place (memory-mapped), never loaded into a table. A corrupt object is
skipped and counted; what was left out is reported as coverage (``crypto:coverage:gitHistory*``), never as a failed
scan.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import re
import stat
import struct
import zlib
from collections import deque
from pathlib import Path
from typing import BinaryIO

from aibom.cbom.archives import KEY_SUFFIXES, VirtualFile

MAX_COMMITS = 1_000
MAX_TREES = 50_000
MAX_BLOB_BYTES = 2_000_000
MAX_TOTAL_BYTES = 32_000_000  # key/certificate blob bytes returned
MAX_FILES = 20_000  # (path, blob) pairs of key/certificate files looked at
MAX_OBJECT_BYTES = 32_000_000  # one object, inflated or rebuilt from a delta
#: Work of one history read: bytes inflated plus bytes rebuilt from deltas plus _DELTA_OP_COST per delta
#: instruction (a delta chain is rebuilt from its base on every read). A 1,000-commit history of a 3,000-file
#: repository packed with ``gc --aggressive`` costs about 400 MB (1.3 s); a hostile chain of 1-byte
#: instructions is stopped after about 2 s.
MAX_READ_BYTES = 1_000_000_000
MAX_PACK_BYTES = 2_000_000_000
MAX_INDEX_BYTES = 512_000_000
_MAX_PACKS = 64  # git repacks past 50 (gc.autoPackLimit)
_MAX_PENDING = 10 * MAX_COMMITS  # refs and parents waiting to be read
_MAX_NAME_BYTES = 1_024  # an entry name no file system holds is not part of a path (NAME_MAX is 255)
_MAX_PATH_BYTES = 4_096  # PATH_MAX
_MAX_REF_FILES = 5_000
_MAX_DELTA_DEPTH = 64
_MAX_VARINT_BYTES = 10  # a 64-bit size or offset
_DELTA_OP_COST = 256  # an instruction costs the interpreter about what a few KB of memcpy do
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_SHA = re.compile(rb"^[0-9a-f]{40}$")
_TYPES = {1: b"commit", 2: b"tree", 3: b"blob", 4: b"tag"}
#: What a malformed object raises while it is parsed (it is then skipped and counted, never fatal).
_CORRUPT = (ValueError, IndexError, OverflowError, struct.error, zlib.error)


class HistoryBudgetExceeded(Exception):
    """The read reached :data:`MAX_READ_BYTES`; what was found so far is kept."""


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
            return fh.read(info.st_size + 1)  # read(limit) would allocate ``limit`` bytes for every object
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
    """One ``.idx`` v2 + ``.pack`` pair. The index is memory-mapped and binary-searched, so a large (or hostile)
    index costs page cache, not a table of every object name."""

    _NAMES = 8 + 256 * 4

    def __init__(self, idx_path: Path, pack_path: Path) -> None:
        fd = os.open(idx_path, os.O_RDONLY | _O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not self._NAMES <= info.st_size <= MAX_INDEX_BYTES:
                raise ValueError("not a pack index")
            self.idx = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        finally:
            os.close(fd)
        try:
            if self.idx[:4] != b"\xfftOc" or struct.unpack_from(">I", self.idx, 4)[0] != 2:
                raise ValueError("unsupported pack index")
            self.count = self._fan(255)
            self.offsets32 = self._NAMES + 24 * self.count
            self.offsets64 = self.offsets32 + 4 * self.count
            if len(self.idx) < self.offsets64:
                raise ValueError("truncated pack index")
        except (ValueError, struct.error):
            self.idx.close()
            raise
        self.path = pack_path
        self.fh: BinaryIO | None = None

    def _fan(self, byte: int) -> int:
        return struct.unpack_from(">I", self.idx, 8 + 4 * byte)[0]

    def find(self, sha: bytes) -> int | None:
        """Pack offset of object ``sha`` (40 hex bytes), or None. Raises struct.error for a corrupt index."""
        name = bytes.fromhex(sha.decode())
        hi = min(self._fan(name[0]), self.count)
        lo = min(self._fan(name[0] - 1), hi) if name[0] else 0
        while lo < hi:
            mid = (lo + hi) // 2
            at = self._NAMES + 20 * mid
            here = self.idx[at: at + 20]
            if here < name:
                lo = mid + 1
            elif here > name:
                hi = mid
            else:
                off = struct.unpack_from(">I", self.idx, self.offsets32 + 4 * mid)[0]
                if off & 0x80000000:
                    off = struct.unpack_from(">Q", self.idx, self.offsets64 + 8 * (off & 0x7FFFFFFF))[0]
                return off
        return None

    def open(self) -> BinaryIO:
        if self.fh is None:
            fd = os.open(self.path, os.O_RDONLY | _O_NOFOLLOW)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PACK_BYTES:
                os.close(fd)
                raise ValueError("not a pack file")
            self.fh = os.fdopen(fd, "rb")
        return self.fh

    def close(self) -> None:
        if self.fh is not None:
            self.fh.close()
        self.idx.close()


class GitObjects:
    """Read-only object store of one ``.git`` directory (see the module docstring).

    ``bytes_read`` is the work spent (bytes inflated plus bytes rebuilt from deltas); passing
    :data:`MAX_READ_BYTES` raises :class:`HistoryBudgetExceeded`. ``corrupt`` counts the objects (and pack
    indexes) that could not be parsed or were larger than :data:`MAX_OBJECT_BYTES`."""

    def __init__(self, git_dir: Path) -> None:
        self.git_dir = git_dir
        self.objects = git_dir / "objects"
        self.packs: list[_Pack] = []
        self.bytes_read = 0
        self.corrupt = 0
        self.packs_not_read = 0
        pack_dir = self.objects / "pack"
        if _is_dir(pack_dir):
            for idx_path in sorted(pack_dir.glob("pack-*.idx")):
                if len(self.packs) >= _MAX_PACKS:  # each holds a mapping (and a descriptor) until close()
                    self.packs_not_read += 1
                    continue
                try:
                    self.packs.append(_Pack(idx_path, idx_path.with_suffix(".pack")))
                except OSError:
                    continue  # unreadable or a link
                except (ValueError, struct.error):
                    self.corrupt += 1

    def close(self) -> None:
        for pack in self.packs:
            pack.close()

    def _spend(self, n: int) -> None:
        if self.bytes_read + n > MAX_READ_BYTES:
            raise HistoryBudgetExceeded
        self.bytes_read += n

    def get(self, sha: bytes, depth: int = 0) -> tuple[bytes, bytes] | None:
        """(type, content) of object ``sha`` (40 hex bytes), or None when it is absent or unreadable."""
        if not _SHA.match(sha) or depth > _MAX_DELTA_DEPTH:
            return None
        fan = self.objects / sha[:2].decode()
        raw = _read(fan / sha[2:].decode(), 64_000_000) if _is_dir(fan) else None  # a linked fan-out dir: no
        if raw is not None:
            return self._loose(raw)
        for pack in self.packs:
            try:
                off = pack.find(sha)
            except _CORRUPT:
                self.corrupt += 1
                continue
            if off is not None:
                return self._from_pack(pack, off, depth)
        return None

    def _loose(self, raw: bytes) -> tuple[bytes, bytes] | None:
        try:
            d = zlib.decompressobj()
            data = d.decompress(raw, MAX_OBJECT_BYTES + 64)
            self._spend(len(data))
            head, nul, body = data.partition(b"\0")
            kind, _, length = head.partition(b" ")
            if not d.eof or not nul or not length.isdigit() or int(length) != len(body):
                raise ValueError("loose object of another size than it declares (or over the cap)")
        except _CORRUPT:
            self.corrupt += 1
            return None
        return kind, body

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
                if shift > 7 * _MAX_VARINT_BYTES:
                    raise ValueError("object size too long")
                byte = fh.read(1)[0]
                size |= (byte & 0x7F) << shift
                shift += 7
            if size > MAX_OBJECT_BYTES:
                raise ValueError("object over the size cap")
            base: tuple[bytes, bytes] | None = None
            if kind == 6:  # OFS_DELTA: base at a negative offset
                byte = fh.read(1)[0]
                rel = byte & 0x7F
                for _ in range(_MAX_VARINT_BYTES):
                    if not byte & 0x80:
                        break
                    byte = fh.read(1)[0]
                    rel = ((rel + 1) << 7) | (byte & 0x7F)
                else:
                    raise ValueError("delta base offset too long")
                if not 0 < rel <= offset:
                    raise ValueError("delta base outside the pack")
                here = fh.tell()
                base = self._from_pack(pack, offset - rel, depth + 1)
                fh.seek(here)
            elif kind == 7:  # REF_DELTA: base by name
                base_sha = fh.read(20).hex().encode()
                here = fh.tell()
                base = self.get(base_sha, depth + 1)
                fh.seek(here)
            elif kind not in _TYPES:
                raise ValueError("unknown object type")
            if kind in (6, 7) and base is None:
                return None  # absent (a partial clone) or already counted where it failed
            self._spend(size)
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
            del out
            if base is not None:
                rebuilt, work = _apply_delta(base[1], data, MAX_READ_BYTES - self.bytes_read)
                self._spend(work)
                return base[0], rebuilt
            return _TYPES[kind], data
        except OSError:
            return None  # the pack file is missing or unreadable
        except _CORRUPT:
            self.corrupt += 1
            return None


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if shift > 7 * _MAX_VARINT_BYTES:
            raise ValueError("delta size too long")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def _apply_delta(base: bytes, delta: bytes, work: int) -> tuple[bytes, int]:
    """The object rebuilt from ``base`` and a git delta, and the work it cost (the bytes rebuilt plus
    :data:`_DELTA_OP_COST` per instruction).

    Raises ValueError for a delta git itself would refuse: a base of another size than the delta names, a copy
    outside the base, a result larger (or smaller) than the size it declares; and :class:`HistoryBudgetExceeded`
    when the work would pass ``work``, before doing it. Memory is bounded by the declared size."""
    src_size, pos = _varint(delta, 0)
    if src_size != len(base):
        raise ValueError("delta base of another size")
    size, pos = _varint(delta, pos)
    if size > MAX_OBJECT_BYTES:
        raise ValueError("delta result over the size cap")
    if size > work:
        raise HistoryBudgetExceeded
    max_ops = (work - size) // _DELTA_OP_COST
    out = bytearray()
    ops = 0
    end = len(delta)
    while pos < end:
        op = delta[pos]
        pos += 1
        ops += 1
        if ops > max_ops:
            raise HistoryBudgetExceeded
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
            length = length or 0x10000
            if off + length > src_size or len(out) + length > size:
                raise ValueError("delta copy outside the base or past the declared size")
            out += base[off: off + length]
        elif op:  # insert literal
            if pos + op > end or len(out) + op > size:
                raise ValueError("delta insert past the delta or the declared size")
            out += delta[pos: pos + op]
            pos += op
        else:
            raise ValueError("bad delta opcode")
    if len(out) != size:
        raise ValueError("delta result of another size than declared")
    return bytes(out), size + ops * _DELTA_OP_COST


def _heads(git_dir: Path) -> tuple[list[bytes], int]:
    """Commit names of HEAD, every branch / tag ref and packed-refs (no config, no remotes' URLs), at most
    :data:`_MAX_PENDING` of them, and how many more there were."""
    shas: dict[bytes, None] = {}
    more = 0

    def add(sha: bytes) -> None:
        nonlocal more
        if sha in shas:
            return
        if len(shas) >= _MAX_PENDING:
            more += 1
        else:
            shas[sha] = None

    head = (_read(git_dir / "HEAD", 4096) or b"").strip()
    if _SHA.match(head):
        add(head)
    packed = _read(git_dir / "packed-refs", 64_000_000) or b""
    pos = 0
    while pos < len(packed):  # line by line: a split would hold every line at once
        end = packed.find(b"\n", pos)
        end = len(packed) if end < 0 else end
        part = packed[pos: min(end, pos + 41)].split(b" ", 1)[0].strip()
        if _SHA.match(part):
            add(part)
        pos = end + 1
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
                    add(value)
    return list(shas), more


def _tree_entries(data: bytes):
    """(mode, name, sha) of each entry of a tree object, in order; ValueError where it is malformed."""
    pos = 0
    while pos < len(data):
        sp = data.index(b" ", pos)
        nul = data.index(b"\0", sp)
        if nul + 21 > len(data):
            raise ValueError("truncated tree entry")
        yield data[pos:sp], data[sp + 1: nul], data[nul + 1: nul + 21].hex().encode()
        pos = nul + 21


def _commit_links(body: bytes, max_parents: int) -> tuple[bytes | None, list[bytes], int]:
    """The tree and at most ``max_parents`` parents named in a commit's header (the lines before the first blank
    line), and how many parents more it names. Read line by line: a split would hold every line at once."""
    tree = None
    parents: list[bytes] = []
    more = pos = 0
    while pos < len(body):
        end = body.find(b"\n", pos)
        end = len(body) if end < 0 else end
        if end == pos:
            break
        line = body[pos:end] if end - pos <= 64 else b""  # a longer line names no object
        if line.startswith(b"tree ") and tree is None:
            tree = line[5:].strip()
        elif line.startswith(b"parent "):
            if len(parents) < max_parents:
                parents.append(line[7:].strip())
            else:
                more += 1
        pos = end + 1
    return tree, parents, more


def _path(node: tuple | None) -> str:
    parts: list[str] = []
    while node is not None:
        node, name = node[0], node[1]
        parts.append(name)
    return "/".join(reversed(parts))


def _git_blob_sha(data: bytes) -> bytes:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest().encode()  # noqa: S324 (git object name)


def history_key_files(
    root: Path, tree_files: dict[str, Path] | None = None, *, force: bool = False
) -> tuple[list[VirtualFile], dict[str, str]]:
    """Key/certificate blobs from the history of ``root/.git`` that the working tree does not hold as they were.

    ``tree_files`` maps the working tree's key/certificate paths (from the scan's walk, which never follows a
    link) to their files; a history path is only compared against those, never opened by name. A shallow
    repository (``.git/shallow``: the worker's depth-1 clone) is read only with ``force``. Returns the files and
    coverage properties. Never raises for what the ``.git`` holds: a corrupt object is skipped and counted
    (``gitHistoryObjectsUnreadable``), a cap or the work budget ends the read with what was found
    (``gitHistoryBudgetExceeded``, ``gitHistoryCommitsNotRead``)."""
    tree_files = tree_files or {}
    git_dir = root / ".git"
    coverage: dict[str, str] = {}
    if not _is_dir(git_dir) or not _is_dir(git_dir / "objects"):
        return [], coverage
    if os.path.lexists(git_dir / "shallow") and not force:
        coverage["crypto:coverage:gitHistory"] = "shallow clone: history not read"
        return [], coverage
    store = GitObjects(git_dir)
    found: list[VirtualFile] = []
    examined: set[tuple[str, bytes]] = set()  # (path, blob) pairs already looked at
    commits_seen: set[bytes] = set()
    trees_seen: set[bytes] = set()
    total = 0
    cut = store.packs_not_read > 0  # a cap or the work budget stopped the read early
    try:
        heads, not_queued = _heads(git_dir)
        queue = deque(heads)
        try:
            while queue and len(commits_seen) < MAX_COMMITS:
                sha = queue.popleft()
                if sha in commits_seen:
                    continue
                commits_seen.add(sha)
                obj = store.get(sha)
                if obj is None or obj[0] != b"commit":
                    continue
                tree, parents, more = _commit_links(obj[1], _MAX_PENDING)
                not_queued += more
                for parent in parents:
                    if parent in commits_seen:
                        continue
                    if len(queue) >= _MAX_PENDING:
                        not_queued += 1
                    else:
                        queue.append(parent)
                # A path is a chain of (parent, name, length) nodes: a pending tree holds only its own name.
                stack: list[tuple[bytes, tuple | None]] = [(tree, None)] if tree else []
                while stack:
                    if len(trees_seen) >= MAX_TREES:
                        cut = True
                        break
                    tsha, node = stack.pop()
                    if tsha in trees_seen:
                        continue
                    trees_seen.add(tsha)
                    tobj = store.get(tsha)
                    if tobj is None or tobj[0] != b"tree":
                        continue
                    try:
                        for mode, raw_name, esha in _tree_entries(tobj[1]):
                            name = raw_name.decode("utf-8", "replace")
                            length = (node[2] + 1 if node else 0) + len(raw_name)
                            if name in ("", ".", "..") or "/" in name or "\\" in name or "\0" in name or \
                                    len(raw_name) > _MAX_NAME_BYTES or length > _MAX_PATH_BYTES:
                                continue  # not a name git writes or a file system holds; never part of a path
                            if mode in (b"40000", b"040000"):
                                if esha in trees_seen:
                                    continue
                                if len(stack) >= MAX_TREES:
                                    cut = True
                                    continue
                                stack.append((esha, (node, name, length)))
                                continue
                            if not mode.startswith(b"100") or not name.lower().endswith(KEY_SUFFIXES):
                                continue
                            path = _path((node, name, length))
                            if (path, esha) in examined:
                                continue
                            if len(examined) >= MAX_FILES or total >= MAX_TOTAL_BYTES:
                                cut = True
                                continue
                            examined.add((path, esha))
                            blob = store.get(esha)
                            if blob is None or blob[0] != b"blob" or len(blob[1]) > MAX_BLOB_BYTES:
                                continue
                            on_disk = tree_files.get(path)
                            current = _read(on_disk, MAX_BLOB_BYTES) if on_disk is not None else None
                            if current is not None and _git_blob_sha(current) == esha:
                                continue  # the working tree holds this exact file: scanned there
                            total += len(blob[1])
                            rel = path if current is None else f"{path}@{sha[:12].decode()}"
                            found.append(VirtualFile(rel, blob[1], {
                                "crypto:gitCommit": sha.decode(),
                                "crypto:historyOnly": "true" if current is None else "false",
                            }))
                    except ValueError:
                        store.corrupt += 1  # a malformed tree: the entries before the fault were read
        except HistoryBudgetExceeded:
            cut = True
        if queue or not_queued:
            coverage["crypto:coverage:gitHistoryCommitsNotRead"] = str(len(queue) + not_queued)
        if cut:
            coverage["crypto:coverage:gitHistoryBudgetExceeded"] = "true"
        if store.corrupt:
            coverage["crypto:coverage:gitHistoryObjectsUnreadable"] = str(store.corrupt)
        coverage["crypto:coverage:gitHistoryCommits"] = str(len(commits_seen))
    finally:
        store.close()
    return sorted(found, key=lambda v: v.rel), coverage


__all__ = ["GitObjects", "HistoryBudgetExceeded", "history_key_files"]
