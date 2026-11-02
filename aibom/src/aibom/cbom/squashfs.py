"""A minimal, read-only squashfs 4.0 reader (pure Python) for the firmware lane.

Follows the on-disk format of the Linux kernel's ``fs/squashfs/squashfs_fs.h`` (and
``Documentation/filesystems/squashfs.rst``): a 96-byte little-endian superblock, metadata blocks of at most 8 KiB
(2-byte header, bit 15 = stored uncompressed), inode references ``block << 16 | offset``, directory headers and
entries, regular-file block lists (bit 24 = stored uncompressed, size 0 = sparse) and the fragment table.

Only what an inventory needs is read: the directory tree, regular files (data, capped by the caller) and symbolic
link targets (reported as links, never followed). Compression: zlib (id 1), LZMA (2, the "alone" format
squashfs-tools writes) and xz (4); LZO, LZ4 and zstd images are refused as unsupported (counted). Every
decompressed byte is taken from the scan's :class:`~aibom.cbom.archives.ArchiveBudget`; a block that would
decompress to more than the block size is refused as a bomb, a directory that loops back to an ancestor is
refused, and the tree depth is capped.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from collections.abc import Iterator

from aibom.cbom.archives import ArchiveBudget
from aibom.cbom.unpack import Member, Refused, safe_name

MAGIC = 0x73717368
METADATA_SIZE = 8192
INVALID_FRAG = 0xFFFFFFFF
MAX_TREE_DEPTH = 64
_COMPRESSION = {1: "zlib", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
# inode types
_DIR, _REG, _SYMLINK, _LDIR, _LREG, _LSYMLINK = 1, 2, 3, 8, 9, 10
_SPECIAL = {4, 5, 6, 7, 11, 12, 13, 14}


class SquashFS:
    def __init__(self, data: bytes, budget: ArchiveBudget) -> None:
        if len(data) < 96:
            raise Refused("corruptHeader")
        (magic, self.inodes, _mkfs, self.block_size, self.fragments, comp, block_log, _flags, _ids, major, minor,
         self.root, self.bytes_used, _id_table, _xattr, self.inode_table, self.dir_table, self.frag_table,
         _lookup) = struct.unpack_from("<IIIIIHHHHHHQQQQQQQQ", data, 0)
        if magic != MAGIC or major != 4:
            raise Refused("unsupportedSquashfsVersion")
        if self.block_size not in {1 << n for n in range(12, 21)} or (1 << block_log) != self.block_size:
            raise Refused("corruptHeader")
        name = _COMPRESSION.get(comp, f"id{comp}")
        if name not in ("zlib", "lzma", "xz"):
            raise Refused(f"unsupportedCompression:squashfs-{name}")
        self.comp = name
        self.data = data
        self.budget = budget
        self._meta: dict[int, tuple[bytes, int]] = {}
        self._frag_cache: dict[int, bytes] = {}

    # ------------------------------------------------------------------ blocks
    def _decompress(self, raw: bytes, limit: int) -> bytes:
        try:
            if self.comp == "zlib":
                dec = zlib.decompressobj()
                out = dec.decompress(raw, limit)
                if dec.unconsumed_tail:
                    raise Refused("compressionBomb")
            else:
                dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ if self.comp == "xz" else lzma.FORMAT_ALONE)
                out = dec.decompress(raw, max_length=limit)
                if not dec.eof and not dec.needs_input:
                    raise Refused("compressionBomb")
        except (zlib.error, lzma.LZMAError, EOFError, ValueError):
            raise Refused("corruptStream") from None
        if not self.budget.take(len(out)):
            raise Refused("budgetExceeded")
        return out

    def _metablock(self, pos: int) -> tuple[bytes, int]:
        """(uncompressed bytes, position of the next block) of the metadata block at absolute ``pos``."""
        hit = self._meta.get(pos)
        if hit is not None:
            return hit
        if pos < 0 or pos + 2 > len(self.data):
            raise Refused("corruptHeader")
        (header,) = struct.unpack_from("<H", self.data, pos)
        size = header & 0x7FFF
        raw = self.data[pos + 2:pos + 2 + size]
        if len(raw) != size or size == 0:
            raise Refused("corruptHeader")
        out = raw if header & 0x8000 else self._decompress(raw, METADATA_SIZE)
        if len(out) > METADATA_SIZE:
            raise Refused("compressionBomb")
        hit = (out, pos + 2 + size)
        if len(self._meta) > 4096:
            self._meta.clear()
        self._meta[pos] = hit
        return hit

    def _read_meta(self, block: int, offset: int, n: int) -> tuple[bytes, int, int]:
        """``n`` bytes of metadata from (absolute block position, offset in it); also the position after them."""
        out = bytearray()
        guard = 0
        while len(out) < n:
            data, nxt = self._metablock(block)
            if offset > len(data):
                raise Refused("corruptHeader")
            take = data[offset:offset + n - len(out)]
            out += take
            offset += len(take)
            if len(out) < n:
                block, offset = nxt, 0
                guard += 1
                if guard > (n // METADATA_SIZE) + 2:
                    raise Refused("corruptHeader")
        return bytes(out), block, offset

    # ------------------------------------------------------------------ inodes
    def _inode(self, ref: int) -> dict:
        block = self.inode_table + (ref >> 16)
        offset = ref & 0xFFFF
        head, block, offset = self._read_meta(block, offset, 16)
        itype, mode = struct.unpack_from("<HH", head, 0)
        (ino,) = struct.unpack_from("<I", head, 12)
        out: dict = {"type": itype, "mode": mode, "ino": ino}
        if itype == _DIR:
            body, _b, _o = self._read_meta(block, offset, 16)
            start, _nlink, size, off, _parent = struct.unpack("<IIHHI", body)
            out.update(start=start, size=size, offset=off)
        elif itype == _LDIR:
            body, _b, _o = self._read_meta(block, offset, 24)
            _nlink, size, start, _parent, _icount, off, _xattr = struct.unpack("<IIIIHHI", body)
            out.update(start=start, size=size, offset=off)
        elif itype in (_REG, _LREG):
            if itype == _REG:
                body, block, offset = self._read_meta(block, offset, 16)
                start, frag, frag_off, size = struct.unpack("<IIII", body)
            else:
                body, block, offset = self._read_meta(block, offset, 40)
                start, size, _sparse, _nlink, frag, frag_off, _xattr = struct.unpack("<QQQIIII", body)
            whole = size // self.block_size
            blocks = whole + (1 if size % self.block_size and frag == INVALID_FRAG else 0)
            if blocks > (len(self.data) // 2 + 1):  # more blocks than the image could hold
                raise Refused("corruptHeader")
            sizes, _b, _o = self._read_meta(block, offset, 4 * blocks)
            out.update(start=start, size=size, frag=frag, frag_off=frag_off,
                       blocks=list(struct.unpack(f"<{blocks}I", sizes)) if blocks else [])
        elif itype in (_SYMLINK, _LSYMLINK):
            body, block, offset = self._read_meta(block, offset, 8)
            _nlink, length = struct.unpack("<II", body)
            if length > 4096:
                raise Refused("nameTooLong")
            target, _b, _o = self._read_meta(block, offset, length)
            out.update(target=target.decode("utf-8", "surrogateescape"))
        elif itype not in _SPECIAL:
            raise Refused("corruptHeader")
        return out

    def _entries(self, inode: dict) -> Iterator[tuple[str, int, int]]:
        """(name, inode reference, type) of each entry of a directory inode."""
        left = inode["size"] - 3  # "." and ".." are not stored; file_size counts them as 3 bytes
        block = self.dir_table + inode["start"]
        offset = inode["offset"]
        while left > 0:
            head, block, offset = self._read_meta(block, offset, 12)
            left -= 12
            count, start, _ino = struct.unpack("<III", head)
            if count >= 256:
                raise Refused("corruptHeader")
            for _ in range(count + 1):
                ent, block, offset = self._read_meta(block, offset, 8)
                ioff, _delta, etype, nsize = struct.unpack("<HhHH", ent)
                name, block, offset = self._read_meta(block, offset, nsize + 1)
                left -= 8 + nsize + 1
                yield name.decode("utf-8", "surrogateescape"), (start << 16) | ioff, etype

    # ------------------------------------------------------------------ file data
    def _fragment(self, index: int) -> bytes:
        cached = self._frag_cache.get(index)
        if cached is not None:
            return cached
        if index >= self.fragments:
            raise Refused("corruptHeader")
        pos = self.frag_table + 8 * (index // 512)
        if pos + 8 > len(self.data):
            raise Refused("corruptHeader")
        (meta_pos,) = struct.unpack_from("<Q", self.data, pos)
        entry, _b, _o = self._read_meta(meta_pos, (index % 512) * 16, 16)
        start, size, _unused = struct.unpack("<QII", entry)
        out = self._block(start, size)
        if len(self._frag_cache) > 64:
            self._frag_cache.clear()
        self._frag_cache[index] = out
        return out

    def _block(self, start: int, size_field: int) -> bytes:
        size = size_field & ~(1 << 24)
        if size == 0:
            return b"\x00" * self.block_size  # sparse block
        raw = self.data[start:start + size]
        if len(raw) != size:
            raise Refused("corruptHeader")
        if size_field & (1 << 24):
            if not self.budget.take(size):
                raise Refused("budgetExceeded")
            return raw
        out = self._decompress(raw, self.block_size)
        return out

    def file_reader(self, inode: dict):
        """A read(n) function over a regular file's bytes (blocks decompressed on demand)."""
        state = {"pos": 0, "index": 0, "buf": b"", "disk": inode["start"]}
        total = inode["size"]

        def read(n: int) -> bytes:
            out = bytearray()
            while len(out) < n and state["pos"] < total:
                if not state["buf"]:
                    i = state["index"]
                    if i < len(inode["blocks"]):
                        field_ = inode["blocks"][i]
                        state["buf"] = self._block(state["disk"], field_)
                        state["disk"] += field_ & ~(1 << 24)
                        state["index"] += 1
                    else:
                        frag = self._fragment(inode["frag"])
                        tail = total - state["pos"]
                        state["buf"] = frag[inode["frag_off"]:inode["frag_off"] + tail]
                        if not state["buf"]:
                            raise Refused("corruptHeader")
                take = state["buf"][: min(n - len(out), total - state["pos"])]
                state["buf"] = state["buf"][len(take):]
                state["pos"] += len(take)
                out += take
            return bytes(out)

        return read

    # ------------------------------------------------------------------ tree
    def walk(self) -> Iterator[Member]:
        root = self._inode(self.root)
        if root["type"] not in (_DIR, _LDIR):
            raise Refused("corruptHeader")
        stack: list[tuple[str, dict, int, frozenset[int]]] = [("", root, 0, frozenset({self.root}))]
        while stack:
            prefix, inode, depth, ancestors = stack.pop()
            for name, ref, _etype in self._entries(inode):
                self.budget.members += 1
                if self.budget.members > self.budget.max_members:
                    self.budget.skipped_budget += 1
                    return
                try:
                    path = safe_name(f"{prefix}/{name}" if prefix else name)
                except Refused as exc:
                    self.budget.refuse(exc.reason)
                    continue
                if "/" in name or not name:
                    self.budget.refuse("pathTraversal")
                    continue
                child = self._inode(ref)
                kind = child["type"]
                if kind in (_DIR, _LDIR):
                    if ref in ancestors:
                        self.budget.refuse("directoryLoop")
                        continue
                    if depth + 1 > MAX_TREE_DEPTH:
                        self.budget.skipped_depth += 1
                        continue
                    stack.append((path, child, depth + 1, ancestors | {ref}))
                elif kind in (_REG, _LREG):
                    yield Member(path, "file", child["size"], child["mode"], _reader=self.file_reader(child))
                elif kind in (_SYMLINK, _LSYMLINK):
                    yield Member(path, "symlink", 0, child["mode"], child["target"])
                else:
                    self.budget.refuse("specialFile")


def iter_squashfs(data: bytes, budget: ArchiveBudget) -> Iterator[Member]:
    """The regular files and links of a squashfs 4.0 image held in ``data``."""
    yield from SquashFS(data, budget).walk()


__all__ = ["SquashFS", "iter_squashfs"]
