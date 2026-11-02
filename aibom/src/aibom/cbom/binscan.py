"""What crypto a compiled binary carries: ELF, PE and Mach-O read from their bytes (no ``readelf``/``objdump``).

Facts, per file (never executed, never written anywhere):

* **Linked crypto libraries and imported crypto functions.** ELF: ``DT_NEEDED`` entries and undefined ``.dynsym``
  symbols (System V gABI, "Dynamic Section" / "Symbol Table"); PE: import directory DLL names and imported names
  (Microsoft "PE Format", data directory 1); Mach-O: ``LC_LOAD_DYLIB`` names and undefined external ``nlist``
  entries (``<mach-o/loader.h>``, ``<mach-o/nlist.h>``). Mapped to algorithms only where the function names one
  (``MD5_Init`` -> MD5, ``DES_ecb_encrypt`` -> DES, ``EVP_aes_128_ecb`` -> AES in ECB mode, ``CC_SHA1`` -> SHA-1);
  ``CryptAcquireContext`` / ``BCrypt*`` / ``CCCrypt`` name the platform API (the algorithm is a run-time argument).
* **Statically linked crypto, by constants** a compiler cannot hide: the AES S-box and inverse S-box (FIPS 197
  Fig. 7/14) and the first T-table words; DES S-box 1 (FIPS 46-3) and the combined SP tables of OpenSSL and of
  Outerbridge's d3des; MD5's 64 sine constants (RFC 1321 3.4, computed here); SHA-1's H4 and round constants
  (FIPS 180-4 4.2.1/5.3.1); SHA-256 and SHA-512 round constants and initial values (FIPS 180-4 4.2.2/4.2.3/5.3,
  computed here with integer roots); the Blowfish P-array (hex digits of pi); the ChaCha/Salsa20 constant
  "expand 32-byte k". Word constants are searched as little- and big-endian 4/8-byte values anywhere in the file,
  because compilers keep many of them as instruction immediates rather than tables; a match needs several
  distinct constants. RC4 has no constants and cannot be found this way.
* **Library version strings**: OpenSSL / LibreSSL ``OPENSSL_VERSION_TEXT``, Mbed TLS, wolfSSL, the BoringSSL
  marker.
* **Go build information** (Go >= 1.18 inline format of ``debug/buildinfo``: magic ``"\\xff Go buildinf:"``,
  varint-prefixed version and module strings with their 16-byte sentinels): the Go version and every module
  version, for the advisory match.
* **Embedded keys and certificates**: PEM blocks, and DER certificates / private keys found by their ASN.1 prefix
  (parsed with :mod:`aibom.cbom.x509`; only facts are kept, never key bytes).
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from functools import cache

MAX_BINARY_BYTES = 64 * 1024 * 1024
_MAX_SYMBOLS = 200_000
_MAX_PEM = 50
_MAX_DER_TRIES = 400


# --------------------------------------------------------------------------------------------- results
@dataclass
class Embedded:
    """A key or certificate found inside a binary: the PEM label / DER kind and its bytes (DER)."""

    label: str
    der: bytes
    offset: int


@dataclass
class BinaryFacts:
    format: str  # elf | pe | macho
    needed: list[str] = field(default_factory=list)
    soname: str = ""  # ELF DT_SONAME: the shared library's own name
    imports: set[str] = field(default_factory=set)
    algorithms: dict[str, dict[str, str]] = field(default_factory=dict)  # display name -> {how, mode?}
    versions: list[tuple[str, str]] = field(default_factory=list)  # (library, version)
    apis: set[str] = field(default_factory=set)  # platform crypto APIs (Microsoft CryptoAPI, CNG, CommonCrypto)
    go_version: str | None = None
    go_modules: list[tuple[str, str]] = field(default_factory=list)
    go_old_format: bool = False
    embedded: list[Embedded] = field(default_factory=list)
    self_test_keys: int = 0  # private keys inside a crypto library (its self-test vectors), not reported
    truncated_parse: bool = False


def binary_format(head: bytes) -> str | None:
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ" and len(head) >= 0x40:
        return "pe"
    if head[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return "macho"
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        # a fat Mach-O lists a few architectures; a Java class file has its version (>= 45) here
        (count,) = struct.unpack(">I", head[4:8])
        return "macho" if 0 < count < 32 else None
    return None


# --------------------------------------------------------------------------------------------- ELF
def _elf(data: bytes, facts: BinaryFacts, symbols: bool = True) -> None:
    cls, enc = data[4], data[5]
    if cls not in (1, 2) or enc not in (1, 2):
        return
    e = "<" if enc == 1 else ">"
    is64 = cls == 2
    try:
        if is64:
            shoff, = struct.unpack_from(e + "Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
        else:
            shoff, = struct.unpack_from(e + "I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x2E)
        if not shoff or shnum == 0 or shnum > 4096 or shentsize < (64 if is64 else 40):
            facts.truncated_parse = True
            return
        sections = []
        for i in range(shnum):
            off = shoff + i * shentsize
            if is64:
                name, typ, _flags, _addr, offset, size, link, _info, _align, entsize = struct.unpack_from(
                    e + "IIQQQQIIQQ", data, off)
            else:
                name, typ, _flags, _addr, offset, size, link, _info, _align, entsize = struct.unpack_from(
                    e + "IIIIIIIIII", data, off)
            sections.append((name, typ, offset, size, link, entsize))
    except struct.error:
        facts.truncated_parse = True
        return

    def strtab(index: int) -> tuple[int, int]:
        if 0 <= index < len(sections):
            return sections[index][2], sections[index][3]
        return 0, 0

    def cstr(base: int, size: int, off: int) -> str:
        if off >= size:
            return ""
        end = data.find(b"\x00", base + off, base + size)
        return data[base + off:end if end >= 0 else base + size][:256].decode("utf-8", "replace")

    for _name, typ, offset, size, link, entsize in sections:
        if offset + size > len(data):
            facts.truncated_parse = True
            continue
        if typ == 6:  # SHT_DYNAMIC
            base, ssize = strtab(link)
            step = 16 if is64 else 8
            for pos in range(offset, offset + size - step + 1, step):
                tag, val = struct.unpack_from(e + ("qQ" if is64 else "iI"), data, pos)
                if tag == 0:
                    break
                if tag == 1:  # DT_NEEDED
                    lib = cstr(base, ssize, val)
                    if lib:
                        facts.needed.append(lib)
                elif tag == 14:  # DT_SONAME
                    facts.soname = cstr(base, ssize, val)
        elif typ == 11 and symbols:  # SHT_DYNSYM
            base, ssize = strtab(link)
            step = entsize or (24 if is64 else 16)
            count = 0
            for pos in range(offset, offset + size - step + 1, step):
                if is64:
                    st_name, _info, _other, shndx = struct.unpack_from(e + "IBBH", data, pos)
                else:
                    st_name, = struct.unpack_from(e + "I", data, pos)
                    shndx, = struct.unpack_from(e + "H", data, pos + 14)
                if shndx == 0 and st_name:
                    sym = cstr(base, ssize, st_name)
                    if sym:
                        facts.imports.add(sym.split("@", 1)[0])
                count += 1
                if count > _MAX_SYMBOLS:
                    facts.truncated_parse = True
                    break


# --------------------------------------------------------------------------------------------- PE
def _pe(data: bytes, facts: BinaryFacts) -> None:
    try:
        (lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[lfanew:lfanew + 4] != b"PE\x00\x00":
            return
        coff = lfanew + 4
        _machine, nsections, _ts, _symptr, _nsyms, opt_size, _chars = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        (magic,) = struct.unpack_from("<H", data, opt)
        pe32plus = magic == 0x20B
        dirs = opt + (112 if pe32plus else 96)
        (ndirs,) = struct.unpack_from("<I", data, opt + (108 if pe32plus else 92))
        if ndirs < 2:
            return
        imp_rva, _imp_size = struct.unpack_from("<II", data, dirs + 8)
        sec_table = opt + opt_size
        sections = []
        for i in range(min(nsections, 96)):
            s = sec_table + 40 * i
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
            sections.append((va, max(vsize, rawsize), rawptr))
    except struct.error:
        facts.truncated_parse = True
        return

    def off(rva: int) -> int | None:
        for va, size, raw in sections:
            if va <= rva < va + size:
                return rva - va + raw
        return None

    def cstr(pos: int | None) -> str:
        if pos is None or pos >= len(data):
            return ""
        end = data.find(b"\x00", pos, pos + 512)
        return data[pos:end if end >= 0 else pos + 512].decode("ascii", "replace")

    desc = off(imp_rva) if imp_rva else None
    if desc is None:
        return
    count = 0
    try:
        while count < 512:
            oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, desc + 20 * count)
            if not (oft or name_rva or ft):
                break
            dll = cstr(off(name_rva))
            if dll:
                facts.needed.append(dll)
            thunk = off(oft or ft)
            step = 8 if pe32plus else 4
            ordinal_bit = 1 << 63 if pe32plus else 1 << 31
            n = 0
            while thunk is not None and n < 4096:
                (value,) = struct.unpack_from("<Q" if pe32plus else "<I", data, thunk + step * n)
                if value == 0:
                    break
                if not value & ordinal_bit:
                    name = cstr((off(value & 0x7FFFFFFF) or 0) + 2)  # IMAGE_IMPORT_BY_NAME: hint, then name
                    if name:
                        facts.imports.add(name)
                n += 1
            count += 1
    except struct.error:
        facts.truncated_parse = True


# --------------------------------------------------------------------------------------------- Mach-O
def _macho(data: bytes, facts: BinaryFacts, depth: int = 0) -> None:
    magic = data[:4]
    try:
        if magic == b"\xca\xfe\xba\xbe":  # fat: read the first slice
            (count,) = struct.unpack_from(">I", data, 4)
            if count and depth == 0:
                _cpu, _sub, offset, size, _align = struct.unpack_from(">IIIII", data, 8)
                _macho(data[offset:offset + size], facts, depth + 1)
            return
        e = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
        is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
        _m, _cpu, _sub, _ftype, ncmds, _sizeofcmds, _flags = struct.unpack_from(e + "IiiIIII", data, 0)
        pos = 32 if is64 else 28
        for _ in range(min(ncmds, 4096)):
            cmd, size = struct.unpack_from(e + "II", data, pos)
            if size < 8:
                facts.truncated_parse = True
                return
            if cmd in (0xC, 0x80000018, 0x8000001F, 0x80000023):  # LC_LOAD_DYLIB, _WEAK_, REEXPORT, LAZY
                (name_off,) = struct.unpack_from(e + "I", data, pos + 8)
                raw = data[pos + name_off:pos + size].split(b"\x00", 1)[0]
                facts.needed.append(raw.decode("utf-8", "replace")[:256])
            elif cmd == 0x2:  # LC_SYMTAB
                symoff, nsyms, stroff, strsize = struct.unpack_from(e + "IIII", data, pos + 8)
                step = 16 if is64 else 12
                for i in range(min(nsyms, _MAX_SYMBOLS)):
                    strx, ntype = struct.unpack_from(e + "IB", data, symoff + i * step)
                    if (ntype & 0x0E) == 0 and ntype & 0x01 and 0 < strx < strsize:  # N_UNDF | N_EXT
                        end = data.find(b"\x00", stroff + strx, stroff + strsize)
                        name = data[stroff + strx:end].decode("utf-8", "replace")
                        facts.imports.add(name[1:] if name.startswith("_") else name)
            pos += size
    except struct.error:
        facts.truncated_parse = True


# --------------------------------------------------------------------------------------------- imports -> crypto
_IMPORT_RULES: tuple[tuple[re.Pattern[str], str, str | None], ...] = (
    (re.compile(r"^(?:MD5_(?:Init|Update|Final)|MD5|EVP_md5|CC_MD5(?:_Init)?)$"), "MD5", None),
    (re.compile(r"^(?:MD4_Init|MD4|EVP_md4)$"), "MD4", None),
    (re.compile(r"^(?:SHA1_(?:Init|Update|Final)|SHA1|EVP_sha1|CC_SHA1(?:_Init)?)$"), "SHA-1", None),
    (re.compile(r"^(?:EVP_des_ede3\w*|DES_ede3_\w+)$"), "3DES", None),
    (re.compile(r"^(?:DES_(?:set_key\w*|ecb_encrypt|ncbc_encrypt|cbc_encrypt|key_sched)|EVP_des_(?:cbc|ecb|cfb\w*|ofb))$"),
     "DES", None),
    (re.compile(r"^(?:RC4|RC4_set_key|EVP_rc4\w*)$"), "RC4", None),
    (re.compile(r"^(?:RC2_\w+|EVP_rc2_\w+)$"), "RC2", None),
    (re.compile(r"^(?:BF_\w+|EVP_bf_\w+)$"), "Blowfish", None),
    (re.compile(r"^EVP_aes_\d+_ecb$"), "AES", "ECB"),
    (re.compile(r"^EVP_aes_\d+_(gcm|cbc|ctr|ccm|xts|ofb|cfb\d*)$"), "AES", "from-name"),
    (re.compile(r"^(?:AES_set_encrypt_key|AES_encrypt|EVP_aes_\d+_\w+)$"), "AES", None),
    (re.compile(r"^(?:RSA_generate_key(?:_ex)?|RSA_(?:public|private)_(?:en|de)crypt|RSA_sign|RSA_verify)$"), "RSA", None),
    (re.compile(r"^(?:EVP_chacha20(?:_poly1305)?)$"), "ChaCha20", None),
    (re.compile(r"^(?:SHA256(?:_Init)?|EVP_sha256|CC_SHA256)$"), "SHA-256", None),
)
_API_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^Crypt(?:AcquireContext[AW]?|Encrypt|Decrypt|CreateHash|DeriveKey|GenKey|ImportKey)$"),
     "Microsoft CryptoAPI (legacy)"),
    (re.compile(r"^BCrypt\w+$"), "Microsoft CNG (bcrypt.dll)"),
    (re.compile(r"^NCrypt\w+$"), "Microsoft CNG key storage (ncrypt.dll)"),
    (re.compile(r"^CCCrypt\w*$"), "Apple CommonCrypto"),
)
# .NET framework crypto classes (UTF-8 in the metadata #Strings heap of a managed assembly)
_DOTNET = ((b"MD5CryptoServiceProvider", "MD5"), (b"SHA1CryptoServiceProvider", "SHA-1"), (b"SHA1Managed", "SHA-1"),
           (b"DESCryptoServiceProvider", "DES"), (b"TripleDESCryptoServiceProvider", "3DES"),
           (b"RC2CryptoServiceProvider", "RC2"), (b"RijndaelManaged", "AES"), (b"AesCryptoServiceProvider", "AES"))
_CRYPTO_LIBS = re.compile(r"(?i)^(?:.*/)?(lib(?:crypto|ssl|gnutls|nettle|gcrypt|sodium|mbedcrypto|mbedtls|wolfssl|"
                          r"nss3|botan[-\w.]*)[.-]\S*|bcrypt\.dll|ncrypt\.dll|advapi32\.dll|crypt32\.dll|"
                          r"libcommonCrypto\.dylib|Security(?:\.framework)?.*)$")


def is_crypto_library(name: str) -> bool:
    return bool(_CRYPTO_LIBS.match(name))


def _import_algorithms(facts: BinaryFacts) -> None:
    for sym in sorted(facts.imports):
        for pattern, display, mode in _IMPORT_RULES:
            m = pattern.match(sym)
            if not m:
                continue
            entry = facts.algorithms.setdefault(display, {"how": f"imports {sym}"})
            if mode == "ECB":
                entry["mode"] = "ECB"
            elif mode == "from-name" and "mode" not in entry:
                entry["mode"] = m.group(1).upper().rstrip("0123456789") or m.group(1).upper()
            break
        for pattern, api in _API_RULES:
            if pattern.match(sym):
                facts.apis.add(api)


# --------------------------------------------------------------------------------------------- constants
def _icbrt(n: int) -> int:
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            break
        x = y
    while x * x * x > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x


def _primes(n: int) -> list[int]:
    out: list[int] = []
    k = 2
    while len(out) < n:
        if all(k % p for p in out if p * p <= k):
            out.append(k)
        k += 1
    return out


@cache
def _word_sets() -> dict[str, tuple[int, tuple[bytes, ...]]]:
    """Algorithm -> (matches needed, distinct byte patterns) for constants searched one by one."""
    md5 = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]  # RFC 1321 3.4
    p64, p80 = _primes(64), _primes(80)
    sha256_k = [_icbrt(p << 96) & 0xFFFFFFFF for p in p64]  # FIPS 180-4 4.2.2
    sha256_h = [math.isqrt(p << 64) & 0xFFFFFFFF for p in p64[:8]]  # FIPS 180-4 5.3.3
    sha512_k = [_icbrt(p << 192) & 0xFFFFFFFFFFFFFFFF for p in p80]  # FIPS 180-4 4.2.3
    sha1 = [0xC3D2E1F0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]  # FIPS 180-4 5.3.1 H4, 4.2.1 K

    def w32(values: list[int]) -> tuple[bytes, ...]:
        return tuple(struct.pack("<I", v) for v in values) + tuple(struct.pack(">I", v) for v in values)

    def w64(values: list[int]) -> tuple[bytes, ...]:
        return tuple(struct.pack("<Q", v) for v in values) + tuple(struct.pack(">Q", v) for v in values)

    return {
        "MD5": (12, w32(md5)),
        "SHA-1": (4, w32(sha1)),
        "SHA-256": (16, w32(sha256_k + sha256_h)),
        "SHA-512": (16, w64(sha512_k)),
    }


def _words(values: tuple[int, ...], size: str = "I") -> tuple[bytes, bytes]:
    return b"".join(struct.pack("<" + size, v) for v in values), b"".join(struct.pack(">" + size, v) for v in values)


# contiguous tables: (algorithm, signature name, byte patterns)
_TABLES: tuple[tuple[str, str, tuple[bytes, ...]], ...] = (
    ("AES", "AES S-box", (bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),)),
    ("AES", "AES inverse S-box", (bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),)),
    ("AES", "AES T-table", _words((0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D))),
    ("DES", "DES S-box 1", (bytes([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]),)),
    ("DES", "DES SP table (OpenSSL)", _words((0x02080800, 0x00080000, 0x02000002, 0x02080802))),
    ("DES", "DES SP table (d3des)", _words((0x01010400, 0x00000000, 0x00010000, 0x01010404))),
    ("Blowfish", "Blowfish P-array", _words((0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344))),
    ("ChaCha20", "ChaCha/Salsa20 constant", (b"expand 32-byte k",)),
)


def _constants(data: bytes, facts: BinaryFacts) -> None:
    for display, signature, patterns in _TABLES:
        if any(p in data for p in patterns):
            facts.algorithms.setdefault(display, {"how": f"constant {signature}"})
    for display, (needed, patterns) in _word_sets().items():
        if display in facts.algorithms:
            continue
        hits = 0
        for p in patterns:
            if p in data:
                hits += 1
                if hits >= needed:
                    facts.algorithms[display] = {"how": f"{display} constants ({needed}+ of the standard values)"}
                    break


# --------------------------------------------------------------------------------------------- version strings
_VERSIONS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("openssl", re.compile(rb"OpenSSL (\d\.\d{1,2}\.\d{1,2}[a-z]{0,2})(?:-[A-Za-z0-9.]{1,16})? {1,2}"
                           rb"\d{1,2} [A-Z][a-z]{2} \d{4}")),
    ("libressl", re.compile(rb"LibreSSL (\d\.\d{1,2}\.\d{1,2})")),
    ("mbedtls", re.compile(rb"[Mm]bed TLS (\d\.\d{1,2}\.\d{1,2})")),
    ("wolfssl", re.compile(rb"wolfSSL (\d\.\d{1,2}\.\d{1,2})")),
)


def _version_strings(data: bytes, facts: BinaryFacts) -> None:
    for lib, pattern in _VERSIONS:
        found = {m.group(1).decode() for m in pattern.finditer(data)}
        for version in sorted(found)[:3]:
            facts.versions.append((lib, version))
    if b"BoringSSL" in data and not any(lib == "openssl" for lib, _ in facts.versions):
        facts.versions.append(("boringssl", ""))


# --------------------------------------------------------------------------------------------- Go build info
_GO_MAGIC = b"\xff Go buildinf:"


def _uvarint(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while pos < len(data) and shift < 64:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    raise ValueError("bad varint")


def go_buildinfo(data: bytes) -> tuple[str | None, list[tuple[str, str]], bool]:
    """(Go version, [(module path, version)], old format) from a Go binary's build info; (None, [], False) when
    the binary has none."""
    pos = data.find(_GO_MAGIC)
    while pos >= 0 and pos % 16:
        pos = data.find(_GO_MAGIC, pos + 1)
    if pos < 0 or pos + 32 > len(data):
        return None, [], False
    flags = data[pos + 15]
    if not flags & 0x2:
        return None, [], True  # pointer-based header (Go < 1.18): addresses would need the loader's view
    try:
        n, p = _uvarint(data, pos + 32)
        version = data[p:p + n].decode("utf-8", "replace")
        p += n
        n, p = _uvarint(data, p)
        mod = data[p:p + n]
    except ValueError:
        return None, [], False
    if len(mod) >= 33 and mod[-17:-16] == b"\n":
        mod = mod[16:-16]  # cmd/go's infoStart / infoEnd sentinels
    else:
        mod = b""
    modules: list[tuple[str, str]] = []
    for line in mod.decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if parts[0] in ("dep", "mod") and len(parts) >= 3:
            modules.append((parts[1], parts[2]))
        elif parts[0] == "=>" and len(parts) >= 3 and modules:
            modules[-1] = (modules[-1][0], parts[2])  # a replacement: the version actually built in
    return version[:64] or None, modules[:5000], False


# --------------------------------------------------------------------------------------------- embedded material
_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----\r?\n([A-Za-z0-9+/=\r\n:,\- ]{40,40000}?)-----END \1-----")
_DER_PREFIX = re.compile(rb"\x30\x82(..)(?=\x30\x82|\x02\x01\x00)", re.S)


def _embedded(data: bytes, facts: BinaryFacts) -> None:
    import base64
    import binascii

    from aibom.cbom.x509 import parse_certificate, parse_private_key

    covered: list[tuple[int, int]] = []
    for m in _PEM.finditer(data):
        if len(facts.embedded) >= _MAX_PEM:
            break
        label = m.group(1).decode()
        body = re.sub(rb"(?m)^[A-Za-z-]+: .*$", b"", m.group(2))  # Proc-Type / DEK-Info headers
        try:
            der = base64.b64decode(b"".join(body.split()), validate=True)
        except (binascii.Error, ValueError):
            continue
        facts.embedded.append(Embedded(label, der, m.start()))
        covered.append((m.start(), m.end()))
    tries = 0
    for m in _DER_PREFIX.finditer(data):
        if tries >= _MAX_DER_TRIES or len(facts.embedded) >= _MAX_PEM:
            break
        start = m.start()
        if any(a <= start < b for a, b in covered):
            continue
        tries += 1
        (length,) = struct.unpack(">H", m.group(1))
        der = data[start:start + 4 + length]
        if len(der) != 4 + length or length < 64:
            continue
        if parse_certificate(der) is not None:
            facts.embedded.append(Embedded("CERTIFICATE", der, start))
        elif der[4:7] == b"\x02\x01\x00":
            for label in ("RSA PRIVATE KEY", "PRIVATE KEY"):
                if parse_private_key(der, label) is not None:
                    facts.embedded.append(Embedded(label, der, start))
                    break


# --------------------------------------------------------------------------------------------- entry point
def scan_binary(data: bytes, *, imports: bool = True, constants: bool = True) -> BinaryFacts | None:
    """Facts about one compiled binary (None when ``data`` is not ELF, PE or Mach-O)."""
    fmt = binary_format(data[:64])
    if fmt is None:
        return None
    facts = BinaryFacts(fmt)
    if not imports and fmt == "elf":
        _elf(data, facts, symbols=False)  # linked libraries only (decides what a version string means)
    if imports:
        if fmt == "elf":
            _elf(data, facts)
        elif fmt == "pe":
            _pe(data, facts)
            if "mscoree.dll" in {n.lower() for n in facts.needed}:
                for marker, display in _DOTNET:
                    if marker in data:
                        facts.algorithms.setdefault(display, {"how": f"uses {marker.decode()}"})
        else:
            _macho(data, facts)
        _import_algorithms(facts)
    if constants:
        _constants(data, facts)
    _version_strings(data, facts)
    if facts.versions and not is_crypto_library(facts.soname) and any(
            soname_branch(n) or is_crypto_library(n) and re.match(r"(?i)lib(?:ssl|crypto)", n) for n in facts.needed):
        # an OpenSSL version text inside a program that links libssl / libcrypto dynamically is the version it was
        # built against (``nginx -V``), not the code that runs: the linked library is inventoried instead
        facts.versions = [(lib, v) for lib, v in facts.versions if lib not in ("openssl", "libressl", "boringssl")]
    facts.go_version, facts.go_modules, facts.go_old_format = go_buildinfo(data)
    _embedded(data, facts)
    if facts.embedded and is_crypto_library(facts.soname):
        # a crypto library carries known-answer-test keys for its own self-tests (GnuTLS / OpenSSL FIPS POST):
        # they protect nothing, so they are counted, not reported as hard-coded keys
        facts.self_test_keys = sum(1 for e in facts.embedded if "PRIVATE KEY" in e.label)
        facts.embedded = [e for e in facts.embedded if "PRIVATE KEY" not in e.label]
    return facts


def soname_branch(name: str) -> tuple[str, str] | None:
    """(library, version branch) pinned by a linked library's soname: ``libssl.so.1.1`` -> ("openssl", "1.1"),
    ``libcrypto.so.1.0.0`` -> ("openssl", "1.0"), ``libcrypto-1_1-x64.dll`` -> ("openssl", "1.1")."""
    m = re.match(r"(?i)^(?:.*/)?lib(?:ssl|crypto)(?:\.so\.|-)(\d)[._](\d)", name)
    if m:
        return "openssl", f"{m.group(1)}.{m.group(2)}"
    return None


__all__ = ["BinaryFacts", "Embedded", "MAX_BINARY_BYTES", "binary_format", "go_buildinfo", "is_crypto_library",
           "scan_binary", "soname_branch"]
