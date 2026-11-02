"""Safe, streaming unpacking for the binary, container-image and firmware lane (scan option ``scan_binaries``).

Everything here reads attacker-controlled bytes, so:

* nothing is ever written to disk and no external tool runs (no ``tar``, ``unsquashfs`` or ``binwalk``);
* tar and cpio headers are parsed by this module, not by :mod:`tarfile` (whose extraction filters had bypasses in
  CPython 3.12.3 and whose pax parser had a ReDoS, CVE-2024-6232); members are only ever *read*, by name;
* a member name is accepted only as a relative path without ``..``, NUL or an absolute root; anything else is
  refused and counted (``crypto:coverage:unpackRefused:<reason>``);
* links are never followed: a symbolic link is counted, a hard link is resolved only to a member already seen in
  the same archive under its normalized name (never outside the archive root);
* device files, FIFOs and sockets are refused;
* decompression (gzip RFC 1952, xz, LZMA-alone, bzip2) is streamed with a capped output: every byte produced counts
  against the scan's one :class:`~aibom.cbom.archives.ArchiveBudget` (total bytes and members across every level),
  a stream whose output grows past :data:`MAX_RATIO` times its input is refused as a bomb, and nesting stops at
  :data:`MAX_DEPTH` containers. zstd, LZO and LZ4 have no decompressor in the standard library: such a stream is
  counted as ``unsupportedCompression:<name>`` and not read.

Formats (with the specification each parser follows):

* tar: POSIX.1-1988 ustar headers, GNU ``L``/``K`` long names and base-256 sizes, POSIX.1-2001 pax ``x``/``g``
  records (``path``, ``linkpath``, ``size``); GNU sparse members are refused (``unsupportedMember``).
* cpio: ``newc``/``crc`` (``070701``/``070702``, 110-byte hex header, 4-byte alignment) and portable ``odc``
  (``070707``, 76-byte octal header), as GNU cpio's manual and the Linux initramfs buffer format describe them;
  ``newc`` hard links store their data once, with the last name (size-0 entries share it).
* U-Boot legacy uImage: the 64-byte big-endian ``legacy_img_hdr`` (magic ``0x27051956``, header CRC-32 checked),
  single and multi-file images, payload compression from ``ih_comp``.
* squashfs 4.0: :mod:`aibom.cbom.squashfs`.
* zip: :mod:`zipfile`, members read through :func:`aibom.cbom.archives._read_member` (capped, encrypted refused).
"""

from __future__ import annotations

import bz2
import io
import lzma
import struct
import zipfile
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from aibom.cbom.archives import ArchiveBudget

MAX_DEPTH = 6  # containers and compression layers, counted together (uImage -> gzip -> cpio -> squashfs ...)
MAX_RATIO = 200  # output bytes per input byte above which a stream is a bomb (zlib's own maximum is ~1032)
RATIO_FLOOR = 1 << 20  # small outputs are never judged by ratio (a 4 KB file of zeros is not a bomb)
MAX_BLOB_BYTES = 128 * 1024 * 1024  # a nested container is held in memory up to this size
MAX_HEADER_DATA = 64 * 1024  # GNU long name / pax record block
MAX_NAME_BYTES = 4096
MAX_NAME_PARTS = 128
_CHUNK = 1 << 16


class Refused(Exception):
    """A stream or member the unpacker will not read (the reason is a coverage key)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------------------------- format detection
def sniff(head: bytes) -> str | None:
    """The container / compression format named by the first bytes of a stream (at least 512 bytes for tar)."""
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"BZh") and head[3:4] and head[3:4] in b"123456789":
        return "bzip2"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if head.startswith(b"\x89LZO\x00"):
        return "lzo"
    if head.startswith(b"\x04\x22\x4d\x18"):
        return "lz4"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head[:6] in (b"070701", b"070702", b"070707"):
        return "cpio"
    if head[:4] == b"\x27\x05\x19\x56":
        return "uimage"
    if head[:4] == b"hsqs":
        return "squashfs"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if len(head) >= 13 and head[0] == 0x5D and head[1:5] in (b"\x00\x00\x80\x00", b"\x00\x00\x00\x01",
                                                              b"\x00\x00\x00\x02", b"\x00\x00\x00\x04",
                                                              b"\x00\x00\x00\x08", b"\x00\x00\x40\x00",
                                                              b"\x00\x00\x10\x00", b"\x00\x00\x20\x00"):
        # LZMA-alone: properties byte 0x5D (lc=3 lp=0 pb=2, the encoder default) and a power-of-two dictionary
        return "lzma"
    return None


COMPRESSIONS = frozenset({"gzip", "xz", "bzip2", "lzma", "zstd", "lzo", "lz4"})
CONTAINERS = frozenset({"tar", "cpio", "uimage", "squashfs", "zip"})


# --------------------------------------------------------------------------------------------- capped decompression
class Inflate(io.RawIOBase):
    """A read-only stream that decompresses ``raw`` (gzip, xz, LZMA-alone or bzip2) with a capped output.

    Every byte produced is taken from ``budget``; past it, or past ``MAX_RATIO`` times the compressed bytes read
    (once more than ``RATIO_FLOOR`` was produced), :class:`Refused` is raised. Concatenated gzip / bzip2 / xz
    members are read one after the other, as their tools do."""

    def __init__(self, raw, kind: str, budget: ArchiveBudget) -> None:
        super().__init__()
        if kind not in ("gzip", "xz", "lzma", "bzip2"):
            raise Refused(f"unsupportedCompression:{kind}")
        self._raw = raw
        self._kind = kind
        self._budget = budget
        self._dec = self._new()
        self._pending = b""  # compressed input not yet given to the decoder
        self._in = 0
        self._out = 0
        self._eof = False

    _MAGIC = {"gzip": b"\x1f\x8b", "xz": b"\xfd7zXZ\x00", "bzip2": b"BZh"}

    def _new(self):
        if self._kind == "gzip":
            return zlib.decompressobj(16 + zlib.MAX_WBITS)
        if self._kind == "xz":
            return lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        if self._kind == "lzma":
            return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        return bz2.BZ2Decompressor()

    def readable(self) -> bool:
        return True

    def _fill(self) -> bool:
        """More compressed input into ``_pending``; False at the end of the raw stream."""
        chunk = self._raw.read(_CHUNK)
        if not chunk:
            return False
        self._in += len(chunk)
        self._pending += chunk
        return True

    def _decoder_wants_input(self) -> bool:
        if self._kind == "gzip":
            return True  # zlib keeps unconsumed input in unconsumed_tail (handed back into _pending)
        return bool(self._dec.needs_input)

    def _between_members(self) -> bool:
        """After a member ended: start the next concatenated member, or end the stream (zero padding / garbage)."""
        while not self._pending.strip(b"\x00"):
            self._pending = b""
            if not self._fill():
                return False
        magic = self._MAGIC.get(self._kind)
        if magic is None or not self._pending.lstrip(b"\x00").startswith(magic[:2]):
            return False  # LZMA-alone has one member; trailing bytes are not ours
        self._pending = self._pending.lstrip(b"\x00")
        self._dec = self._new()
        return True

    def readinto(self, buf) -> int:
        want = len(buf)
        got = 0
        while got < want and not self._eof:
            if self._dec is None:
                if not self._between_members():
                    self._eof = True
                    break
            if not self._pending and self._decoder_wants_input() and not self._fill():
                self._eof = True  # truncated stream: what was decoded stands
                break
            dec = self._dec
            try:
                if self._kind == "gzip":
                    out = dec.decompress(self._pending, want - got)
                    self._pending = dec.unconsumed_tail
                else:
                    out = dec.decompress(self._pending, max_length=want - got)
                    self._pending = b""
            except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError):
                raise Refused("corruptStream") from None
            if dec.eof:
                self._pending = dec.unused_data + self._pending
                self._dec = None
            if out:
                self._out += len(out)
                if not self._budget.take(len(out)):
                    raise Refused("budgetExceeded")
                if self._out > RATIO_FLOOR and self._out > MAX_RATIO * max(self._in, 1):
                    raise Refused("compressionBomb")
                buf[got:got + len(out)] = out
                got += len(out)
        return got


def read_exact(stream, n: int) -> bytes:
    """``n`` bytes or fewer at the end of the stream."""
    parts: list[bytes] = []
    left = n
    while left > 0:
        chunk = stream.read(min(left, _CHUNK))
        if not chunk:
            break
        parts.append(chunk)
        left -= len(chunk)
    return b"".join(parts)


def skip(stream, n: int) -> int:
    """Read and drop ``n`` bytes (a seekable file seeks); the number actually skipped."""
    if n <= 0:
        return 0
    if hasattr(stream, "seekable") and stream.seekable() and not isinstance(stream, Inflate):
        here = stream.tell()
        end = stream.seek(0, io.SEEK_END)
        target = min(here + n, end)
        stream.seek(target)
        return target - here
    done = 0
    while done < n:
        chunk = stream.read(min(n - done, _CHUNK))
        if not chunk:
            break
        done += len(chunk)
    return done


# --------------------------------------------------------------------------------------------- names
def safe_name(raw: str) -> str:
    """A member name as a relative ``a/b/c`` path, or :class:`Refused` (absolute path, ``..``, NUL, too long)."""
    if "\x00" in raw:
        raise Refused("nulInName")
    text = raw.replace("\\", "/")
    if len(text.encode("utf-8", "surrogateescape")) > MAX_NAME_BYTES:
        raise Refused("nameTooLong")
    if text.startswith("/"):
        raise Refused("absolutePath")
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise Refused("pathTraversal")
    if len(parts) > MAX_NAME_PARTS:
        raise Refused("nameTooLong")
    return "/".join(parts)


def resolve_link(target: str) -> str | None:
    """A hard-link target (a name relative to the archive root, as tar stores it) as a normalized path inside the
    root, or None when it is absolute or climbs out of the root."""
    text = target.replace("\\", "/")
    if text.startswith("/"):
        return None
    parts: list[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    return "/".join(parts) if parts else None


# --------------------------------------------------------------------------------------------- members
@dataclass
class Member:
    """One archive entry. ``kind``: file | dir | symlink | hardlink | special."""

    name: str
    kind: str
    size: int
    mode: int = 0
    linkname: str | None = None
    ino: tuple[int, int] | None = None  # cpio (dev, ino) for size-0 hard links
    nlink: int = 1
    _reader: Callable[[int], bytes | None] | None = field(default=None, repr=False)
    _head: bytes = field(default=b"", repr=False)
    _consumed: int = field(default=0, repr=False)

    def peek(self, n: int) -> bytes:
        """The first ``n`` bytes (kept, so a later :meth:`read` still returns the whole member)."""
        if self.kind != "file" or self._reader is None:
            return b""
        if len(self._head) < n and self._consumed == len(self._head):
            more = self._reader(min(n, self.size) - len(self._head)) or b""
            self._head += more
            self._consumed += len(more)
        return self._head[:n]

    def read(self, limit: int) -> bytes | None:
        """The member's bytes, or None when it is larger than ``limit`` (not read)."""
        if self.kind != "file" or self._reader is None:
            return None
        if self.size > limit:
            return None
        rest = self._reader(self.size - self._consumed) or b""
        self._consumed += len(rest)
        data = self._head + rest
        self._head = data
        return data


class _Sequential:
    """Member data from a forward-only stream: what a visitor did not read is skipped before the next header."""

    def __init__(self, stream) -> None:
        self.stream = stream
        self.left = 0

    def reader(self, size: int) -> Callable[[int], bytes | None]:
        self.left = size

        def read(n: int) -> bytes:
            n = min(n, self.left)
            data = read_exact(self.stream, n)
            self.left -= len(data)
            return data

        return read

    def finish(self) -> None:
        if self.left:
            skip(self.stream, self.left)
            self.left = 0


# --------------------------------------------------------------------------------------------- tar
def _tar_number(field_: bytes) -> int:
    if field_ and field_[0] & 0x80:  # GNU base-256 (big-endian, high bit set)
        value = field_[0] & 0x7F
        for byte in field_[1:]:
            value = (value << 8) | byte
        return value
    text = field_.split(b"\x00", 1)[0].strip(b" \x00")
    if not text:
        return 0
    try:
        return int(text, 8)
    except ValueError:
        raise Refused("corruptHeader") from None


def _tar_checksum_ok(block: bytes) -> bool:
    try:
        stored = _tar_number(block[148:156])
    except Refused:
        return False
    data = block[:148] + b" " * 8 + block[156:]
    unsigned = sum(data)
    signed = sum(b - 256 if b > 127 else b for b in data)  # some old tars sum signed chars
    return stored in (unsigned, signed)


def _pax(data: bytes) -> dict[str, str]:
    """POSIX.1-2001 extended header records ``"%d %s=%s\\n"`` (length includes itself)."""
    out: dict[str, str] = {}
    pos = 0
    while pos < len(data):
        space = data.find(b" ", pos, pos + 20)
        if space < 0:
            break
        try:
            length = int(data[pos:space])
        except ValueError:
            break
        if length <= 0 or pos + length > len(data):
            break
        record = data[space + 1:pos + length]
        pos += length
        if not record.endswith(b"\n") or b"=" not in record:
            continue
        key, value = record[:-1].split(b"=", 1)
        out[key.decode("utf-8", "replace")] = value.decode("utf-8", "surrogateescape")
    return out


def _cstr(field_: bytes) -> str:
    return field_.split(b"\x00", 1)[0].decode("utf-8", "surrogateescape")


_TAR_KIND = {b"0": "file", b"\x00": "file", b"7": "file", b"1": "hardlink", b"2": "symlink", b"3": "special",
             b"4": "special", b"5": "dir", b"6": "special"}


def iter_tar(stream, budget: ArchiveBudget) -> Iterator[Member]:
    """The members of a tar stream, in order (see the module docstring). A refused member is counted and skipped;
    a corrupt header ends the archive (counted)."""
    seq = _Sequential(stream)
    long_name: str | None = None
    long_link: str | None = None
    pax: dict[str, str] = {}
    global_pax: dict[str, str] = {}
    while True:
        seq.finish()
        block = read_exact(stream, 512)
        if len(block) < 512:
            return
        if block == b"\x00" * 512:
            return
        if not _tar_checksum_ok(block):
            budget.refuse("corruptHeader")
            return
        budget.members += 1
        if budget.members > budget.max_members:
            budget.skipped_budget += 1
            return
        typeflag = block[156:157]
        try:
            size = _tar_number(block[124:136])
        except Refused as exc:
            budget.refuse(exc.reason)
            return
        padded = (size + 511) // 512 * 512
        if typeflag in (b"L", b"K", b"x", b"g"):
            if size > MAX_HEADER_DATA:
                budget.refuse("headerTooLarge")
                return
            data = read_exact(stream, padded)[:size]
            if typeflag == b"L":
                long_name = _cstr(data)
            elif typeflag == b"K":
                long_link = _cstr(data)
            elif typeflag == b"x":
                pax = _pax(data)
            else:
                global_pax.update(_pax(data))
            continue
        name = _cstr(block[0:100])
        if block[257:262] == b"ustar":
            prefix = _cstr(block[345:500])
            if prefix:
                name = f"{prefix}/{name}"
        linkname = _cstr(block[157:257])
        merged = {**global_pax, **pax}
        name = long_name or merged.get("path") or name
        linkname = long_link or merged.get("linkpath") or linkname
        if "size" in merged:
            try:
                size = int(merged["size"])
            except ValueError:
                budget.refuse("corruptHeader")
                return
            padded = (size + 511) // 512 * 512
        long_name = long_link = None
        pax = {}
        kind = _TAR_KIND.get(typeflag)
        read = seq.reader(padded)  # whatever is not read below is skipped at the top of the loop
        if kind is None:
            budget.refuse("unsupportedMember")  # GNU sparse 'S', multi-volume, vendor types
            continue
        try:
            clean = safe_name(name)
        except Refused as exc:
            budget.refuse(exc.reason)
            continue
        if not clean:
            continue
        if kind == "special":
            budget.refuse("specialFile")
            continue
        try:
            mode = _tar_number(block[100:108])
        except Refused:
            mode = 0
        member = Member(clean, kind, size if kind == "file" else 0, mode, linkname or None,
                        _reader=(lambda n, _r=read: _r(n)) if kind == "file" else None)
        yield member


# --------------------------------------------------------------------------------------------- cpio
_S_IFMT = 0o170000
_CPIO_KIND = {0o100000: "file", 0o040000: "dir", 0o120000: "symlink", 0o020000: "special", 0o060000: "special",
              0o010000: "special", 0o140000: "special"}


def iter_cpio(stream, budget: ArchiveBudget) -> Iterator[Member]:
    """The members of a cpio stream (newc / crc / odc). ``newc`` size-0 entries that share an inode with a later
    entry are hard links to it (``Member.ino``)."""
    seq = _Sequential(stream)
    while True:
        seq.finish()
        magic = read_exact(stream, 6)
        if len(magic) < 6:
            return
        if magic in (b"070701", b"070702"):
            head = read_exact(stream, 104)
            if len(head) < 104:
                budget.refuse("corruptHeader")
                return
            try:
                f = [int(head[i * 8:(i + 1) * 8], 16) for i in range(13)]
            except ValueError:
                budget.refuse("corruptHeader")
                return
            ino, mode, _uid, _gid, nlink, _mtime, size, devmaj, devmin, _rmaj, _rmin, namesize, _check = f
            align = 4
            name_pad = (-(110 + namesize)) % 4
            dev = (devmaj << 32) | devmin
        elif magic == b"070707":
            head = read_exact(stream, 70)
            if len(head) < 70:
                budget.refuse("corruptHeader")
                return
            try:
                dev, ino, mode = int(head[0:6], 8), int(head[6:12], 8), int(head[12:18], 8)
                nlink = int(head[36:42], 8)
                namesize, size = int(head[53:59], 8), int(head[59:70], 8)
            except ValueError:
                budget.refuse("corruptHeader")
                return
            align, name_pad = 1, 0
        else:
            if magic.strip(b"\x00"):
                budget.refuse("corruptHeader")
            return  # padding after the trailer
        if namesize > MAX_NAME_BYTES or namesize == 0:
            budget.refuse("nameTooLong")
            return
        raw_name = read_exact(stream, namesize + name_pad)[:namesize]
        name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "surrogateescape")
        data_pad = (-size) % align if align > 1 else 0
        if name == "TRAILER!!!":
            return
        budget.members += 1
        if budget.members > budget.max_members:
            budget.skipped_budget += 1
            return
        read = seq.reader(size + data_pad)
        kind = _CPIO_KIND.get(mode & _S_IFMT)
        try:
            clean = safe_name(name)
        except Refused as exc:
            budget.refuse(exc.reason)
            continue
        if not clean:
            continue
        if kind is None or kind == "special":
            budget.refuse("specialFile")
            continue
        if kind == "symlink":
            target = read(min(size, MAX_NAME_BYTES)).decode("utf-8", "surrogateescape") if size else ""
            yield Member(clean, "symlink", 0, mode, target)
            continue
        yield Member(clean, kind, size if kind == "file" else 0, mode, None, ino=(dev, ino), nlink=nlink,
                     _reader=(lambda n, _r=read: _r(n)) if kind == "file" else None)


# --------------------------------------------------------------------------------------------- uImage
_UIMAGE_COMP = {0: None, 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}
_IH_TYPE_MULTI = 4


def uimage_parts(data: bytes) -> tuple[str | None, list[bytes]]:
    """(payload compression, payload parts) of a legacy U-Boot image; :class:`Refused` when the header is invalid.
    A multi-file image (``ih_type`` 4) lists its part sizes after the header, ending with a zero."""
    if len(data) < 64:
        raise Refused("corruptHeader")
    header = bytearray(data[:64])
    magic, hcrc, _time, size = struct.unpack(">IIII", header[:16])
    if magic != 0x27051956:
        raise Refused("corruptHeader")
    header[4:8] = b"\x00\x00\x00\x00"
    if zlib.crc32(bytes(header)) & 0xFFFFFFFF != hcrc:
        raise Refused("uimageHeaderCrc")
    image_type, comp = data[30], data[31]
    if comp not in _UIMAGE_COMP:
        raise Refused(f"unsupportedCompression:uimage-{comp}")
    payload = data[64:64 + size]
    if image_type != _IH_TYPE_MULTI:
        return _UIMAGE_COMP[comp], [payload]
    sizes: list[int] = []
    pos = 0
    while pos + 4 <= len(payload) and len(sizes) < 64:
        (n,) = struct.unpack(">I", payload[pos:pos + 4])
        pos += 4
        if n == 0:
            break
        sizes.append(n)
    parts = []
    for n in sizes:
        parts.append(payload[pos:pos + n])
        pos += (n + 3) // 4 * 4
    return _UIMAGE_COMP[comp], parts


# --------------------------------------------------------------------------------------------- recursion
FileVisitor = Callable[[str, Member], None]


@dataclass
class Walk:
    """One recursive unpack: ``visit(path, member)`` is called for every regular file that is not itself a
    container; ``links`` collects symbolic links (never followed). Hard links resolve to the earlier member's path
    (``aliases``)."""

    budget: ArchiveBudget
    visit: FileVisitor
    max_member: int = 64 * 1024 * 1024
    aliases: dict[str, str] = field(default_factory=dict)
    symlinks: int = 0

    def blob(self, label: str, data: bytes, depth: int) -> bool:
        """Unpack ``data`` (named ``label``) when it is a container or a compressed stream; False when it is not."""
        kind = sniff(data[:512])
        if kind is None:
            return False
        if depth >= MAX_DEPTH:
            self.budget.skipped_depth += 1
            return True
        try:
            if kind in COMPRESSIONS:
                self._compressed(label, io.BytesIO(data), kind, depth)
            elif kind == "uimage":
                comp, parts = uimage_parts(data)
                for i, part in enumerate(parts):
                    name = f"{label}!part{i}" if len(parts) > 1 else f"{label}!payload"
                    if comp is None:
                        if not self.blob(name, part, depth + 1):
                            self._file(name, Member(name, "file", len(part), _reader=_bytes_reader(part)))
                    else:
                        self._compressed(name, io.BytesIO(part), comp, depth + 1)
            elif kind == "squashfs":
                from aibom.cbom.squashfs import iter_squashfs

                self._members(label, iter_squashfs(data, self.budget), depth)
            elif kind == "zip":
                self._zip(label, data, depth)
            else:
                self._stream(label, io.BytesIO(data), kind, depth)
        except Refused as exc:
            self.budget.refuse(exc.reason)
        return True

    def stream(self, label: str, stream, depth: int) -> bool:
        """Like :meth:`blob` for a seekable file on disk (a top-level firmware image or image tarball)."""
        head = read_exact(stream, 512)
        stream.seek(0)
        kind = sniff(head)
        if kind is None:
            return False
        if kind in ("tar", "cpio"):
            try:
                self._stream(label, stream, kind, depth)
            except Refused as exc:
                self.budget.refuse(exc.reason)
            return True
        if kind in COMPRESSIONS:
            try:
                self._compressed(label, stream, kind, depth)
            except Refused as exc:
                self.budget.refuse(exc.reason)
            return True
        data = read_exact(stream, MAX_BLOB_BYTES + 1)
        if len(data) > MAX_BLOB_BYTES:
            self.budget.skipped_budget += 1
            return True
        if not self.budget.take(len(data)):
            return True
        return self.blob(label, data, depth)

    def _compressed(self, label: str, raw, kind: str, depth: int) -> None:
        if kind in ("zstd", "lzo", "lz4"):
            raise Refused(f"unsupportedCompression:{kind}")
        if depth + 1 >= MAX_DEPTH:
            self.budget.skipped_depth += 1
            return
        stream = io.BufferedReader(Inflate(raw, kind, self.budget), buffer_size=_CHUNK)
        head = stream.peek(512)[:512]
        inner = sniff(head)
        if inner in ("tar", "cpio"):
            self._stream(label, stream, inner, depth + 1)
            return
        data = read_exact(stream, MAX_BLOB_BYTES + 1)
        if len(data) > MAX_BLOB_BYTES:
            self.budget.skipped_budget += 1
            return
        if inner is not None and self.blob(label, data, depth + 1):
            return
        stripped = label.rsplit(".", 1)[0] if label.lower().endswith((".gz", ".xz", ".bz2", ".lzma", ".tgz")) else label
        self._file(stripped, Member(stripped, "file", len(data), _reader=_bytes_reader(data)))

    def _stream(self, label: str, stream, kind: str, depth: int) -> None:
        members = iter_tar(stream, self.budget) if kind == "tar" else iter_cpio(stream, self.budget)
        self._members(label, members, depth + 1)

    def _members(self, label: str, members: Iterator[Member], depth: int) -> None:
        seen: set[str] = set()
        pending: dict[tuple[int, int], list[str]] = {}  # cpio size-0 hard links waiting for their data entry
        for member in members:
            path = f"{label}!{member.name}"
            if member.kind == "dir":
                continue
            if member.kind == "symlink":
                self.symlinks += 1
                continue
            if member.kind == "hardlink":
                target = resolve_link(member.linkname or "")
                if target is None:
                    self.budget.refuse("linkEscape")
                elif target not in seen:
                    self.budget.refuse("linkTargetMissing")
                else:
                    self.aliases[path] = f"{label}!{target}"
                continue
            if member.ino is not None and member.nlink > 1 and member.size == 0:
                pending.setdefault(member.ino, []).append(path)
                continue
            seen.add(member.name)
            if member.ino is not None and member.ino in pending:
                for other in pending.pop(member.ino):
                    self.aliases[other] = path
            self._member(path, member, depth)
        for paths in pending.values():  # never got their data entry: empty files
            self.budget.refuse("linkTargetMissing", len(paths))

    def _member(self, path: str, member: Member, depth: int) -> None:
        head = member.peek(512)
        if sniff(head) is not None:  # a nested container or compressed stream: unpacked in memory (depth-capped)
            if member.size > MAX_BLOB_BYTES:
                self.budget.skipped_budget += 1
                return
            data = member.read(MAX_BLOB_BYTES)
            if data is None:
                return
            if self.blob(path, data, depth):
                return
            member = Member(member.name, "file", len(data), member.mode, _reader=_bytes_reader(data))
        self._file(path, member)

    def _zip(self, label: str, data: bytes, depth: int) -> None:
        from aibom.cbom.archives import _member_name, _read_member

        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            infos = zf.infolist()
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
            raise Refused("corruptArchive") from None
        for info in infos:
            if info.is_dir():
                continue
            self.budget.members += 1
            if self.budget.members > self.budget.max_members:
                self.budget.skipped_budget += 1
                return
            try:
                name = safe_name(info.filename)
            except Refused as exc:
                self.budget.refuse(exc.reason)
                continue
            mode = (info.external_attr >> 16) & _S_IFMT
            if mode == 0o120000:
                self.symlinks += 1
                continue
            if mode and mode not in (0o100000,):
                self.budget.refuse("specialFile")
                continue
            body = _read_member(zf, info, self.max_member, self.budget)
            if body is None:
                continue
            path = f"{label}!{_member_name(name)}"
            if not self.blob(path, body, depth + 1):
                self._file(path, Member(name, "file", len(body), _reader=_bytes_reader(body)))

    def _file(self, path: str, member: Member) -> None:
        if member.size > self.max_member:
            self.budget.skipped_budget += 1
            return
        self.visit(path, member)


def _bytes_reader(data: bytes) -> Callable[[int], bytes]:
    pos = [0]

    def read(n: int) -> bytes:
        chunk = data[pos[0]:pos[0] + n]
        pos[0] += len(chunk)
        return chunk

    return read


__all__ = [
    "COMPRESSIONS",
    "CONTAINERS",
    "Inflate",
    "MAX_DEPTH",
    "Member",
    "Refused",
    "Walk",
    "iter_cpio",
    "iter_tar",
    "read_exact",
    "resolve_link",
    "safe_name",
    "skip",
    "sniff",
    "uimage_parts",
]
