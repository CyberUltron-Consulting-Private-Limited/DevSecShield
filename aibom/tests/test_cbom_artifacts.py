"""Binary / container-image / firmware lane (scan option ``scan_binaries``): safe unpacking, package databases,
binary parsing, image layers and the scan rows they produce.

The squashfs fixtures under ``fixtures/artifacts/`` were made with squashfs-tools 4.6.1 (no keys inside):
``mksquashfs root rootfs-gzip.sqfs -comp gzip -noappend -all-root -p "dev d 755 0 0" -p "dev/zero c 666 0 0 1 5"``
and the same with ``-comp xz`` (root: ``bin/app`` (an ELF importing MD5_Init), ``etc/os-release``,
``deep/a/b/c/f.txt``, ``link -> /etc/os-release``).
"""

from __future__ import annotations

import gzip
import io
import lzma
import os
import sqlite3
import struct
import zlib
from pathlib import Path

import pytest
from support.artifacts import cpio_newc, docker_save, elf, fake_rsa_der, macho, pe, pem, tar_bytes

from aibom.cbom import pkgdb
from aibom.cbom.archives import ArchiveBudget
from aibom.cbom.binscan import _word_sets, go_buildinfo, scan_binary
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.squashfs import iter_squashfs
from aibom.cbom.unpack import Inflate, Refused, Walk, iter_cpio, iter_tar, safe_name, sniff, uimage_parts

FIX = Path(__file__).resolve().parent / "fixtures" / "artifacts"


def _walk(data: bytes, label: str = "fw.bin"):
    budget = ArchiveBudget.for_binaries()
    seen: dict[str, bytes] = {}
    walker = Walk(budget, lambda path, m: seen.__setitem__(path, m.read(1 << 24)))
    walker.blob(label, data, 0)
    return seen, budget, walker


# ============================================================================================ unpack
def test_tar_names_ustar_gnu_long_and_pax() -> None:
    long = "a/" + "b" * 150 + "/c.txt"
    buf = io.BytesIO()
    import tarfile

    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name in ("./etc/x.conf", long):
            info = tarfile.TarInfo(name)
            info.size = 3
            tf.addfile(info, io.BytesIO(b"abc"))
    names = [m.name for m in iter_tar(io.BytesIO(buf.getvalue()), ArchiveBudget())]
    assert names == ["etc/x.conf", long]
    gnu = tar_bytes([(long, b"xyz")])
    assert [(m.name, m.read(10)) for m in iter_tar(io.BytesIO(gnu), ArchiveBudget())] == [(long, b"xyz")]


@pytest.mark.parametrize("name, reason", [("../etc/passwd", "pathTraversal"), ("a/../../x", "pathTraversal"),
                                          ("/etc/shadow", "absolutePath"), ("a\x00b", "nulInName")])
def test_safe_name_refuses(name: str, reason: str) -> None:
    with pytest.raises(Refused) as exc:
        safe_name(name)
    assert exc.value.reason == reason


def test_hostile_tar_members_are_refused_and_counted() -> None:
    data = tar_bytes([("ok.txt", b"fine"), ("../escape.txt", b"x"), ("/abs.txt", b"y"), ("dev/null", "chr"),
                      ("link", "symlink", "/etc/shadow"), ("hard-in", "hardlink", "ok.txt"),
                      ("hard-out", "hardlink", "../../etc/shadow"), ("hard-abs", "hardlink", "/etc/shadow")])
    seen, budget, walker = _walk(data, "t.tar")
    assert seen == {"t.tar!ok.txt": b"fine"}
    assert walker.aliases == {"t.tar!hard-in": "t.tar!ok.txt"}
    assert walker.symlinks == 1
    assert budget.refused == {"pathTraversal": 1, "absolutePath": 1, "specialFile": 1, "linkEscape": 2}
    cov = budget.coverage()
    assert cov["crypto:coverage:unpackRefused:pathTraversal"] == "1"
    assert cov["crypto:coverage:unpackRefused:specialFile"] == "1"


def test_gzip_bomb_is_refused() -> None:
    bomb = gzip.compress(b"\x00" * (64 * 1024 * 1024), compresslevel=9)
    assert len(bomb) < 100_000
    budget = ArchiveBudget.for_binaries()
    with pytest.raises(Refused) as exc:
        Inflate(io.BytesIO(bomb), "gzip", budget).read()
    assert exc.value.reason == "compressionBomb"
    _seen, budget, _w = _walk(bomb, "bomb.gz")
    assert budget.refused.get("compressionBomb") == 1


def test_one_budget_across_levels() -> None:
    inner = tar_bytes([(f"f{i}.bin", os.urandom(200_000)) for i in range(5)])
    outer = tar_bytes([("a.tar", inner), ("b.tar", inner)])
    budget = ArchiveBudget(max_total_bytes=1_500_000, max_members=1000)
    seen: dict[str, bytes] = {}
    Walk(budget, lambda p, m: seen.__setitem__(p, m.read(1 << 24) or b"")).blob("o.tar", gzip.compress(outer), 0)
    assert budget.skipped_budget >= 1 or budget.refused.get("budgetExceeded")
    assert len(seen) < 10


def test_nested_depth_is_capped() -> None:
    data = b"deep secret"
    for _ in range(9):
        data = gzip.compress(data, mtime=0)
    _seen, budget, _w = _walk(data, "n.gz")
    assert budget.skipped_depth >= 1
    assert budget.coverage()["crypto:coverage:archiveTooDeep"]


def test_unsupported_and_corrupt_streams_are_counted() -> None:
    _s, budget, _w = _walk(b"\x28\xb5\x2f\xfd" + b"\x00" * 600, "x.zst")
    assert budget.refused == {"unsupportedCompression:zstd": 1}
    _s, budget, _w = _walk(b"\x1f\x8b\x08\x00" + b"\xff" * 600, "x.gz")
    assert budget.refused == {"corruptStream": 1}


def test_gzip_concatenated_members_and_xz_bz2_lzma() -> None:
    two = gzip.compress(b"one ") + gzip.compress(b"two")
    assert Inflate(io.BytesIO(two), "gzip", ArchiveBudget()).read() == b"one two"
    import bz2

    for kind, packed in (("xz", lzma.compress(b"payload")), ("bzip2", bz2.compress(b"payload")),
                         ("lzma", lzma.compress(b"payload", format=lzma.FORMAT_ALONE))):
        assert sniff(packed) == kind
        assert Inflate(io.BytesIO(packed), kind, ArchiveBudget()).read() == b"payload"


def test_cpio_newc_size0_hardlinks_odc_and_hostile() -> None:
    data = cpio_newc([("etc", 0o040755, b"", 1, 2), ("etc/a.key", 0o100600, b"", 7, 2),
                      ("etc/b.key", 0o100600, b"KEYDATA", 7, 2), ("dev/console", 0o020600, b"", 9, 1),
                      ("../up", 0o100644, b"x", 10, 1), ("lnk", 0o120777, b"/etc/b.key", 11, 1)])
    seen, budget, walker = _walk(data, "initrd")
    assert seen == {"initrd!etc/b.key": b"KEYDATA"}
    assert walker.aliases == {"initrd!etc/a.key": "initrd!etc/b.key"}
    assert walker.symlinks == 1
    assert budget.refused == {"specialFile": 1, "pathTraversal": 1}
    odc = b"070707" + b"000001000002100644000000000000000001000000" + b"00000000000" + b"000006" + b"00000000003" \
        + b"a.txt\x00" + b"abc"
    assert [(m.name, m.read(10)) for m in iter_cpio(io.BytesIO(odc), ArchiveBudget())] == [("a.txt", b"abc")]


def _uimage(payload: bytes, comp: int, image_type: int = 3) -> bytes:
    header = bytearray(64)
    struct.pack_into(">IIIIIII", header, 0, 0x27051956, 0, 0, len(payload), 0, 0, zlib.crc32(payload))
    header[28:32] = bytes([5, 2, image_type, comp])
    header[32:40] = b"zs-test\x00"
    struct.pack_into(">I", header, 4, zlib.crc32(bytes(header)))
    return bytes(header) + payload


def test_uimage_header_crc_payload_and_multi() -> None:
    inner = cpio_newc([("bin/x", 0o100755, b"hello", 1, 1)])
    img = _uimage(gzip.compress(inner), 1)
    seen, _budget, _w = _walk(img, "fw.uimg")
    assert seen == {"fw.uimg!payload!bin/x": b"hello"}
    bad = bytearray(img)
    bad[40] ^= 0xFF  # name byte: header CRC no longer matches
    with pytest.raises(Refused):
        uimage_parts(bytes(bad))
    parts = struct.pack(">III", 3, 5, 0) + b"abc\x00" + b"defgh"
    comp, got = uimage_parts(_uimage(parts, 0, image_type=4))
    assert comp is None and got == [b"abc", b"defgh"]


# ============================================================================================ squashfs
@pytest.mark.parametrize("name", ["rootfs-gzip.sqfs", "rootfs-xz.sqfs"])
def test_squashfs_reader(name: str) -> None:
    budget = ArchiveBudget.for_binaries()
    found = {m.name: (m.kind, m.read(1 << 20) if m.kind == "file" else m.linkname)
             for m in iter_squashfs((FIX / name).read_bytes(), budget)}
    assert found["deep/a/b/c/f.txt"] == ("file", b"deep\n")
    assert found["link"] == ("symlink", "/etc/os-release")
    assert found["etc/os-release"][1].startswith(b"ID=")
    assert found["bin/app"][1][:4] == b"\x7fELF"
    assert budget.refused == {"specialFile": 1}  # dev/zero


def test_squashfs_corrupt_and_unsupported() -> None:
    data = bytearray((FIX / "rootfs-gzip.sqfs").read_bytes())
    data[20:22] = struct.pack("<H", 6)  # zstd
    with pytest.raises(Refused) as exc:
        list(iter_squashfs(bytes(data), ArchiveBudget()))
    assert exc.value.reason == "unsupportedCompression:squashfs-zstd"
    data = bytearray((FIX / "rootfs-gzip.sqfs").read_bytes())
    data[28:30] = struct.pack("<H", 3)  # squashfs 3.x
    with pytest.raises(Refused):
        list(iter_squashfs(bytes(data), ArchiveBudget()))
    truncated = (FIX / "rootfs-gzip.sqfs").read_bytes()[:200]
    _seen, budget, _w = _walk(truncated, "t.sqfs")
    assert budget.refused  # counted, not raised out of the walk


# ============================================================================================ package databases
def test_dpkg_apk_and_os_release() -> None:
    status = ("Package: libssl1.1\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.1.0j-1~deb9u1\n"
              "Description: SSL\n multi line\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n\n")
    assert pkgdb.dpkg_status(status) == [{"name": "libssl1.1", "version": "1.1.0j-1~deb9u1", "arch": "amd64"}]
    apk = "C:Q1abc=\nP:libcrypto3\nV:3.3.2-r0\nA:x86_64\no:openssl\n\nP:musl\nV:1.2.5-r0\n"
    assert pkgdb.apk_installed(apk)[0] == {"name": "libcrypto3", "version": "3.3.2-r0", "arch": "x86_64",
                                           "source": "openssl"}
    rel = pkgdb.os_release('PRETTY_NAME="Debian GNU/Linux 9 (stretch)"\nID=debian\nVERSION_ID="9"\n')
    assert rel["id"] == "debian" and rel["version_id"] == "9"
    assert pkgdb.purl("deb", "libssl1.1", "1.1.0j-1~deb9u1", rel, "amd64") == \
        "pkg:deb/debian/libssl1.1@1.1.0j-1~deb9u1?arch=amd64&distro=debian-9"


def _rpm_blob(tags: dict[int, object]) -> bytes:
    index, store = b"", b""
    for tag, value in tags.items():
        if isinstance(value, int):
            store += b"\x00" * ((-len(store)) % 4)
            index += struct.pack(">iiii", tag, 4, len(store), 1)
            store += struct.pack(">i", value)
        else:
            index += struct.pack(">iiii", tag, 6, len(store), 1)
            store += str(value).encode() + b"\x00"
    return struct.pack(">ii", len(tags), len(store)) + index + store


def _rpmdb(blobs: list[bytes], view: bool = False) -> bytes:
    con = sqlite3.connect(":memory:")
    if view:
        con.execute("CREATE TABLE P (hnum INTEGER, blob BLOB)")
        con.execute("CREATE VIEW Packages AS SELECT * FROM P")
        table = "P"
    else:
        con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
        table = "Packages"
    for i, blob in enumerate(blobs, 1):
        con.execute(f"INSERT INTO {table} VALUES (?, ?)", (i, blob))
    con.commit()
    data = con.serialize()
    con.close()
    return data


def test_rpm_sqlite_headers_and_view_refused() -> None:
    blobs = [_rpm_blob({1000: "openssl-libs", 1001: "3.0.7", 1002: "27.el9", 1003: 1, 1022: "x86_64"}),
             _rpm_blob({1000: "gpg-pubkey", 1001: "abc", 1002: "1"}), b"\x00\x00\x00\x09garbage"]
    assert pkgdb.rpm_sqlite(_rpmdb(blobs)) == [{"name": "openssl-libs", "version": "1:3.0.7-27.el9", "arch": "x86_64"}]
    with pytest.raises(ValueError):
        pkgdb.rpm_sqlite(_rpmdb(blobs[:1], view=True))
    with pytest.raises(ValueError):
        pkgdb.rpm_sqlite(b"not sqlite")


# ============================================================================================ binaries
def test_elf_needed_imports_and_algorithms() -> None:
    facts = scan_binary(elf(["libcrypto.so.1.1", "libc.so.6"],
                            ["MD5_Init", "DES_ecb_encrypt", "EVP_aes_128_ecb", "EVP_aes_256_gcm", "printf"]))
    assert facts.format == "elf"
    assert facts.needed == ["libcrypto.so.1.1", "libc.so.6"]
    assert {"MD5_Init", "DES_ecb_encrypt", "printf"} <= facts.imports
    assert set(facts.algorithms) == {"MD5", "DES", "AES"}
    assert facts.algorithms["AES"]["mode"] == "ECB"


def test_pe_and_macho_imports() -> None:
    facts = scan_binary(pe({"ADVAPI32.dll": ["CryptAcquireContextW", "CryptCreateHash"],
                            "libcrypto-1_1-x64.dll": ["MD5", "EVP_des_ede3_cbc"]}))
    assert facts.format == "pe"
    assert facts.needed == ["ADVAPI32.dll", "libcrypto-1_1-x64.dll"]
    assert {"MD5", "3DES"} <= set(facts.algorithms)
    assert "Microsoft CryptoAPI (legacy)" in facts.apis
    facts = scan_binary(macho(["/usr/lib/libSystem.B.dylib"], ["CCCrypt", "CC_SHA1", "printf"]))
    assert facts.format == "macho"
    assert facts.needed == ["/usr/lib/libSystem.B.dylib"]
    assert "SHA-1" in facts.algorithms and "Apple CommonCrypto" in facts.apis


def test_constants_are_the_published_values() -> None:
    sets = _word_sets()
    md5 = sets["MD5"][1]
    assert md5[0] == struct.pack("<I", 0xD76AA478) and md5[63] == struct.pack("<I", 0xEB86D391)  # RFC 1321 T1, T64
    sha256 = sets["SHA-256"][1]
    assert sha256[0] == struct.pack("<I", 0x428A2F98) and sha256[63] == struct.pack("<I", 0xC67178F2)
    assert sha256[64] == struct.pack("<I", 0x6A09E667)  # H0
    sha512 = sets["SHA-512"][1]
    assert sha512[0] == struct.pack("<Q", 0x428A2F98D728AE22) and sha512[79] == struct.pack("<Q", 0x6C44198C4A475817)


def test_constant_signatures() -> None:
    sbox = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
    sp = struct.pack("<4I", 0x02080800, 0x00080000, 0x02000002, 0x02080802)
    bf = struct.pack(">4I", 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344)
    md5 = b"".join(_word_sets()["MD5"][1][:16])
    sha256 = b"".join(_word_sets()["SHA-256"][1][:20])
    facts = scan_binary(elf(extra=sbox + sp + bf + b"expand 32-byte k" + md5 + sha256))
    assert set(facts.algorithms) == {"AES", "DES", "Blowfish", "ChaCha20", "MD5", "SHA-256"}
    assert scan_binary(elf(extra=b"".join(_word_sets()["MD5"][1][:5]))).algorithms == {}  # too few constants


def test_version_strings_and_build_time_rule() -> None:
    text = b"OpenSSL 1.1.0j  20 Nov 2018\x00"
    static = scan_binary(elf(extra=text))
    assert static.versions == [("openssl", "1.1.0j")]
    linked = scan_binary(elf(["libssl.so.1.1"], ["SSL_new"], extra=text))
    assert linked.versions == []  # the version it was built against; the linked library is what runs
    library = scan_binary(elf(["libcrypto.so.1.1"], extra=text, soname="libssl.so.1.1"))
    assert library.versions == [("openssl", "1.1.0j")]
    assert scan_binary(elf(extra=b"LibreSSL 2.8.3\x00mbed TLS 2.16.3")).versions == [("libressl", "2.8.3"),
                                                                                    ("mbedtls", "2.16.3")]


def _go_blob(version: str, mod: str) -> bytes:
    def uv(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    framed = b"0" * 16 + mod.encode() + b"1" * 16
    head = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16
    return head + uv(len(version)) + version.encode() + uv(len(framed)) + framed


def test_go_buildinfo() -> None:
    mod = ("path\tzs/app\nmod\tzs/app\t(devel)\t\ndep\tgolang.org/x/crypto\tv0.0.0-20200622213623-75b288015ac9\th1:x=\n"
           "dep\tgithub.com/a/b\tv1.0.0\th1:y=\n=>\tgithub.com/a/b\tv1.0.1\th1:z=\n")
    data = b"\x00" * 32 + _go_blob("go1.21.3", mod)
    version, modules, old = go_buildinfo(data)
    assert version == "go1.21.3" and not old
    assert ("golang.org/x/crypto", "v0.0.0-20200622213623-75b288015ac9") in modules
    assert ("github.com/a/b", "v1.0.1") in modules  # the replacement is what was built in
    assert go_buildinfo(b"\x00" * 16 + b"\xff Go buildinf:" + bytes([8, 0]) + b"\x00" * 64) == (None, [], True)


@pytest.mark.skipif(not Path("/usr/local/go/bin/go").exists() and not Path("/usr/bin/go").exists(),
                    reason="no Go toolchain")
def test_go_buildinfo_matches_go_version_m(tmp_path: Path) -> None:
    import shutil
    import subprocess

    go = shutil.which("go") or ("/usr/local/go/bin/go" if Path("/usr/local/go/bin/go").exists() else "/usr/bin/go")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
    (tmp_path / "go.mod").write_text("module zs/t\n\ngo 1.21\n")
    env = {**os.environ, "GOFLAGS": "-mod=mod", "GOCACHE": str(tmp_path / ".cache"), "CGO_ENABLED": "0"}
    subprocess.run([go, "build", "-o", str(tmp_path / "t"), "."], cwd=tmp_path, check=True, env=env)
    want = subprocess.run([go, "version", str(tmp_path / "t")], capture_output=True, text=True, check=True)
    version, _mods, _old = go_buildinfo((tmp_path / "t").read_bytes())
    assert version and version == want.stdout.split(": ", 1)[1].strip()


def test_embedded_pem_and_der_keys() -> None:
    key = fake_rsa_der(1024)
    facts = scan_binary(elf(extra=b"junk" + pem("RSA PRIVATE KEY", key) + b"\x00\x01" + key))
    labels = sorted(e.label for e in facts.embedded)
    assert labels == ["RSA PRIVATE KEY", "RSA PRIVATE KEY"]
    gnutls = scan_binary(elf(extra=pem("RSA PRIVATE KEY", key), soname="libgnutls.so.30"))
    assert gnutls.embedded == [] and gnutls.self_test_keys == 1  # a crypto library's self-test vectors


# ============================================================================================ images and scan rows
def _image_layers() -> list[bytes]:
    os_release = b'PRETTY_NAME="Debian GNU/Linux 9 (stretch)"\nID=debian\nVERSION_ID="9"\n'
    status = b"Package: libssl1.1\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.1.0j-1~deb9u1\n\n"
    base = tar_bytes([("etc/os-release", os_release), ("var/lib/dpkg/status", status),
                      ("opt/app/old.pem", pem("RSA PRIVATE KEY", fake_rsa_der(2048))),
                      ("opt/conf/old.key", pem("RSA PRIVATE KEY", fake_rsa_der(2048))),
                      ("opt/conf/keep-not.txt", b"x")], gz=True)
    meta = b"Metadata-Version: 2.1\nName: cryptography\nVersion: 3.3.2\n\nbody"
    app = tar_bytes([("usr/lib/python3/site-packages/cryptography-3.3.2.dist-info/METADATA", meta),
                     ("opt/app/node_modules/node-forge/package.json", b'{"name":"node-forge","version":"0.9.0"}'),
                     ("usr/local/bin/tool", elf(extra=b"OpenSSL 1.0.2k  26 Jan 2017\x00")),
                     ("opt/app/server.key", pem("RSA PRIVATE KEY", fake_rsa_der(1024))),
                     ("../../escape", b"x"), ("dev/kmsg", "chr"), ("etc/alt", "symlink", "/etc/os-release")])
    whiteouts = tar_bytes([("opt/app/.wh.old.pem", b""), ("opt/conf/.wh..wh..opq", b""),
                           ("opt/conf/new.txt", b"new")], gz=True)
    return [base, app, whiteouts]


def _rows(tree: Path, **kw):
    from aibom.integrations.cbom_devsecshield import normalize_to_devsecshield

    result = scan_crypto(tree, level=4, **kw)
    return normalize_to_devsecshield(result, duration_of_scan=0.0), result


def test_image_layers_whiteouts_packages_and_hostile_members(tmp_path: Path) -> None:
    (tmp_path / "image.tar").write_bytes(docker_save(_image_layers()))
    run, result = _rows(tmp_path, scan_binaries=True)
    by = {(r["title"], r["location"]): r for r in run["results"]}
    codes = {r["title"]: set(r["finding_codes"]) for r in run["results"]}
    assert codes["Debian GNU/Linux 9 (stretch) (base OS)"] == {"EOL_BASE_IMAGE"}
    assert {"EOL_CRYPTO_LIBRARY", "LIBRARY_CVE_RANGE"} <= codes["libssl1.1@1.1.0j-1~deb9u1"]
    assert codes["cryptography@3.3.2"] == {"VULNERABLE_CRYPTO_LIBRARY"}
    assert codes["node-forge@0.9.0"] == {"VULNERABLE_CRYPTO_LIBRARY"}
    assert {"EOL_CRYPTO_LIBRARY", "LIBRARY_CVE_RANGE"} <= codes["openssl@1.0.2k"]
    key = by[("private-key (server.key)", "image.tar!opt/app/server.key")]
    assert key["finding_codes"] == ["HARDCODED_KEY"]
    assert ("RSA", "image.tar!opt/app/server.key") in by  # 1024-bit
    assert "WEAK_KEY_SIZE" in by[("RSA", "image.tar!opt/app/server.key")]["finding_codes"]
    locations = {r["location"] for r in run["results"]}
    assert not any("old.pem" in loc or "old.key" in loc for loc in locations)  # whiteout + opaque directory
    purls = {c.get("purl") for c in run["cbom_json"]["components"]}
    assert "pkg:deb/debian/libssl1.1@1.1.0j-1~deb9u1?arch=amd64&distro=debian-9" in purls
    assert "pkg:pypi/cryptography@3.3.2" in purls and "pkg:npm/node-forge@0.9.0" in purls
    props = result.properties
    assert props["crypto:coverage:unpackRefused:pathTraversal"] == "1"
    assert props["crypto:coverage:unpackRefused:specialFile"] == "1"
    assert props["crypto:coverage:image:symlinksNotFollowed"] == "1"


def test_oci_index_picks_amd64_and_bad_digests_are_ignored(tmp_path: Path) -> None:
    from aibom.cbom.image import _images

    class Blobs:
        def __init__(self, data: bytes) -> None:
            import tarfile

            self.tf = tarfile.open(fileobj=io.BytesIO(data))

        def has(self, name: str) -> bool:
            try:
                self.tf.getmember(name)
                return True
            except KeyError:
                return False

        def open(self, name: str):
            return self.tf.extractfile(name)

    images = _images(Blobs(docker_save(_image_layers(), oci_index=True)))
    assert len(images) == 1 and len(images[0][1]) == 3  # the amd64 manifest, not the empty arm64 one
    (tmp_path / "oci.tar").write_bytes(docker_save(_image_layers(), oci_index=True))
    run, _result = _rows(tmp_path, scan_binaries=True)
    assert any(r["title"] == "libssl1.1@1.1.0j-1~deb9u1" for r in run["results"])


def test_scan_binaries_off_reads_no_artifact(tmp_path: Path) -> None:
    (tmp_path / "image.tar").write_bytes(docker_save(_image_layers()))
    (tmp_path / "app").write_bytes(elf(["libcrypto.so.1.0.0"], ["MD5_Init"]))
    run, result = _rows(tmp_path)
    assert run["results"] == []
    assert not any("binaries" in k or "unpack" in k or "image" in k for k in result.properties)


def test_binaries_and_firmware_rows(tmp_path: Path) -> None:
    key = pem("RSA PRIVATE KEY", fake_rsa_der(1024))
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "legacy").write_bytes(elf(["libcrypto.so.1.0.0"], ["MD5_Init", "DES_ecb_encrypt"]))
    rootfs = cpio_newc([("etc/ssl/private/device.key", 0o100600, key, 1, 1),
                        ("usr/lib/opkg/status", 0o100644, b"Package: libopenssl1.0.0\nVersion: 1.0.2k-1\n"
                                                          b"Status: install user installed\n\n", 2, 1),
                        ("bin/init", 0o100755, elf(extra=bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")), 3, 1)])
    (tmp_path / "firmware.bin").write_bytes(_uimage(gzip.compress(rootfs), 1))
    run, result = _rows(tmp_path, scan_binaries=True)
    got = {(r["title"], r["location"]): set(r["finding_codes"]) for r in run["results"]}
    assert got[("MD5", "bin/legacy")] == {"WEAK_ALGORITHM"}
    assert got[("DES", "bin/legacy")] == {"WEAK_ALGORITHM"}
    assert got[("libcrypto.so.1.0.0", "bin/legacy")] == {"EOL_CRYPTO_LIBRARY"}
    fw = "firmware.bin!payload!"
    assert got[("private-key (device.key)", fw + "etc/ssl/private/device.key")] == {"HARDCODED_KEY"}
    assert "WEAK_KEY_SIZE" in got[("RSA", fw + "etc/ssl/private/device.key")]
    assert {"EOL_CRYPTO_LIBRARY", "LIBRARY_CVE_RANGE"} <= got[("libopenssl1.0.0@1.0.2k-1", fw + "usr/lib/opkg/status")]
    assert got[("AES", fw + "bin/init")] == set()  # inventory, no finding
    assert result.properties["crypto:coverage:firmwareImagesRead"] == "1"
    assert result.properties["crypto:coverage:binariesIncluded"] == "true"
