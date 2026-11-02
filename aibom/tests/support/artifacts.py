"""Builders for the binary / image / firmware lane tests: spec-shaped ELF, PE and Mach-O files, OCI / docker-save
image tarballs, cpio archives and a synthetic RSA private key (random modulus, never a usable key)."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import struct
import tarfile


# --------------------------------------------------------------------------------------------- ASN.1 / keys
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return b"\x02" + _der_len(len(raw)) + raw


def fake_rsa_der(bits: int = 1024) -> bytes:
    """A well-formed PKCS#1 RSAPrivateKey with a random ``bits``-bit modulus (not a real key pair)."""
    def rnd(size: int) -> int:
        return int.from_bytes(os.urandom(size // 8), "big") | (1 << (size - 1)) | 1

    n = rnd(bits)
    # version, n, e, d, p, q, dp, dq, qinv: sized like a real key (the DER is ~600 bytes for 1024 bits)
    body = b"".join(_int(v) for v in (0, n, 65537, rnd(bits), rnd(bits // 2), rnd(bits // 2), rnd(bits // 2),
                                      rnd(bits // 2), rnd(bits // 2)))
    return b"\x30" + _der_len(len(body)) + body


def pem(label: str, der: bytes) -> bytes:
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n".encode()


# --------------------------------------------------------------------------------------------- ELF
def elf(needed: list[str] = (), imports: list[str] = (), extra: bytes = b"", soname: str | None = None) -> bytes:
    """A 64-bit little-endian ELF with .dynstr / .dynsym / .dynamic / .rodata / .shstrtab sections."""
    dynstr = bytearray(b"\x00")

    def add(s: str) -> int:
        off = len(dynstr)
        dynstr.extend(s.encode() + b"\x00")
        return off

    syms = bytearray(b"\x00" * 24)  # the null symbol
    for name in imports:
        syms += struct.pack("<IBBHQQ", add(name), 0x12, 0, 0, 0, 0)  # GLOBAL FUNC, SHN_UNDEF
    dyn = bytearray()
    for lib in needed:
        dyn += struct.pack("<qQ", 1, add(lib))
    if soname:
        dyn += struct.pack("<qQ", 14, add(soname))
    dyn += struct.pack("<qQ", 0, 0)
    shstr = b"\x00.dynstr\x00.dynsym\x00.dynamic\x00.rodata\x00.shstrtab\x00"
    blobs = [bytes(dynstr), bytes(syms), bytes(dyn), extra, shstr]
    offset = 64
    placed = []
    for blob in blobs:
        placed.append((offset, len(blob)))
        offset += (len(blob) + 7) // 8 * 8
    shoff = offset
    header = bytearray(b"\x7fELF\x02\x01\x01" + b"\x00" * 9)
    header += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 6, 5)
    body = bytearray(header)
    for (off, _), blob in zip(placed, blobs, strict=True):
        body += b"\x00" * (off - len(body)) + blob
    body += b"\x00" * (shoff - len(body))
    names = {".dynstr": 1, ".dynsym": 9, ".dynamic": 17, ".rodata": 26, ".shstrtab": 34}
    sections = [b"\x00" * 64,
                struct.pack("<IIQQQQIIQQ", names[".dynstr"], 3, 2, 0, *placed[0], 0, 0, 1, 0),
                struct.pack("<IIQQQQIIQQ", names[".dynsym"], 11, 2, 0, *placed[1], 1, 1, 8, 24),
                struct.pack("<IIQQQQIIQQ", names[".dynamic"], 6, 3, 0, *placed[2], 1, 0, 8, 16),
                struct.pack("<IIQQQQIIQQ", names[".rodata"], 1, 2, 0, *placed[3], 0, 0, 1, 0),
                struct.pack("<IIQQQQIIQQ", names[".shstrtab"], 3, 0, 0, *placed[4], 0, 0, 1, 0)]
    return bytes(body + b"".join(sections))


# --------------------------------------------------------------------------------------------- PE
def pe(dll_imports: dict[str, list[str]], extra: bytes = b"") -> bytes:
    """A PE32+ image with one section holding the import directory (Microsoft PE format)."""
    sec_rva, sec_raw = 0x1000, 0x200
    data = bytearray()
    descs_at = 0
    data += b"\x00" * (20 * (len(dll_imports) + 1))
    entries = []
    for dll, names in dll_imports.items():
        name_rva = sec_rva + len(data)
        data += dll.encode() + b"\x00"
        hint_rvas = []
        for n in names:
            hint_rvas.append(sec_rva + len(data))
            data += b"\x00\x00" + n.encode() + b"\x00"
        while len(data) % 8:
            data += b"\x00"
        thunk_rva = sec_rva + len(data)
        for r in hint_rvas:
            data += struct.pack("<Q", r)
        data += struct.pack("<Q", 0)
        entries.append((thunk_rva, name_rva))
    for i, (thunk, name) in enumerate(entries):
        data[descs_at + 20 * i:descs_at + 20 * (i + 1)] = struct.pack("<IIIII", thunk, 0, 0, name, thunk)
    data += extra
    raw_size = (len(data) + 0x1FF) // 0x200 * 0x200
    dos = bytearray(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40))
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 112 + 8, sec_rva, len(dll_imports) * 20)  # data directory 1: imports
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, len(opt), 0x22)
    section = b".idata\x00\x00" + struct.pack("<IIIIIIHHI", len(data), sec_rva, raw_size, sec_raw, 0, 0, 0, 0, 0)
    head = dos + b"PE\x00\x00" + coff + opt + section
    head += b"\x00" * (sec_raw - len(head))
    return bytes(head + data + b"\x00" * (raw_size - len(data)))


# --------------------------------------------------------------------------------------------- Mach-O
def macho(dylibs: list[str], undefined: list[str]) -> bytes:
    """A 64-bit Mach-O with LC_LOAD_DYLIB commands and an LC_SYMTAB of undefined external symbols."""
    cmds = bytearray()
    for lib in dylibs:
        name = lib.encode() + b"\x00"
        size = (24 + len(name) + 7) // 8 * 8
        cmds += struct.pack("<IIIIII", 0xC, size, 24, 0, 0, 0) + name + b"\x00" * (size - 24 - len(name))
    strtab = bytearray(b"\x00")
    nlist = bytearray()
    for sym in undefined:
        off = len(strtab)
        strtab += b"_" + sym.encode() + b"\x00"
        nlist += struct.pack("<IBBHQ", off, 0x01, 0, 0, 0)  # N_UNDF | N_EXT
    symtab_size = 24
    header_size = 32
    symoff = header_size + len(cmds) + symtab_size
    stroff = symoff + len(nlist)
    cmds += struct.pack("<IIIIII", 0x2, symtab_size, symoff, len(undefined), stroff, len(strtab))
    header = struct.pack("<IiiIIII", 0xFEEDFACF, 0x01000007, 3, 2, len(dylibs) + 1, len(cmds), 0) + b"\x00" * 4
    return bytes(header + cmds + nlist + strtab)


# --------------------------------------------------------------------------------------------- tar / images
def tar_bytes(members: list[tuple], gz: bool = False) -> bytes:
    """``members``: (name, data) files, (name, None) directories, (name, "symlink", target),
    (name, "hardlink", target), (name, "chr") character devices. Names are written verbatim (hostile ones too)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for m in members:
            info = tarfile.TarInfo(m[0])
            if len(m) == 2 and m[1] is None:
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            elif len(m) == 2 and m[1] == "chr":
                info.type, info.devmajor, info.devminor = tarfile.CHRTYPE, 1, 3
                tf.addfile(info)
            elif len(m) == 3:
                info.type = tarfile.SYMTYPE if m[1] == "symlink" else tarfile.LNKTYPE
                info.linkname = m[2]
                tf.addfile(info)
            else:
                info.size = len(m[1])
                tf.addfile(info, io.BytesIO(m[1]))
    raw = buf.getvalue()
    return gzip.compress(raw, mtime=0) if gz else raw


def docker_save(layers: list[bytes], tag: str = "zs-test/app:1", oci_index: bool = False) -> bytes:
    """A ``docker save`` style tar: OCI layout blobs + ``manifest.json`` (or only ``index.json`` -> a manifest list
    -> an amd64 manifest when ``oci_index``)."""
    blobs: dict[str, bytes] = {}

    def put(data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        blobs[f"blobs/sha256/{digest}"] = data
        return digest

    layer_digests = [put(layer) for layer in layers]
    config = put(json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers"}}).encode())
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": f"sha256:{config}"},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": f"sha256:{d}",
                            "size": len(blobs[f'blobs/sha256/{d}'])} for d in layer_digests]}
    mdig = put(json.dumps(manifest).encode())
    arm = put(json.dumps({**manifest, "layers": []}).encode())
    index_list = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
        {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": f"sha256:{arm}", "size": 1,
         "platform": {"os": "linux", "architecture": "arm64"}},
        {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": f"sha256:{mdig}", "size": 1,
         "platform": {"os": "linux", "architecture": "amd64"}}]}
    ldig = put(json.dumps(index_list).encode())
    index = {"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json",
                                                "digest": f"sha256:{ldig}", "size": 1,
                                                "annotations": {"io.containerd.image.name": tag}}]}
    members: list[tuple] = [(name, data) for name, data in blobs.items()]
    members += [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", json.dumps(index).encode())]
    if not oci_index:
        members.append(("manifest.json", json.dumps([{"Config": f"blobs/sha256/{config}", "RepoTags": [tag],
                                                       "Layers": [f"blobs/sha256/{d}" for d in layer_digests]}]).encode()))
    return tar_bytes(members)


def cpio_newc(entries: list[tuple[str, int, bytes, int, int]]) -> bytes:
    """newc archive from (name, mode, data, ino, nlink) entries plus the trailer."""
    out = bytearray()
    for name, mode, data, ino, nlink in entries + [("TRAILER!!!", 0, b"", 0, 1)]:
        raw = name.encode() + b"\x00"
        fields = [ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(raw), 0]
        head = b"070701" + b"".join(b"%08X" % f for f in fields)
        out += head + raw + b"\x00" * ((-(len(head) + len(raw))) % 4)
        out += data + b"\x00" * ((-len(data)) % 4)
    return bytes(out)
