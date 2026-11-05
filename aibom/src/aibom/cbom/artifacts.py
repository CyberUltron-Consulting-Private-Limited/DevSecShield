"""The binary, container-image and firmware lane of a code scan (scan option ``scan_binaries``, default off).

One pass over the scan's shared :class:`~aibom.cbom.files.FileWalk` (no links followed), once per scan:

* **container images** (:mod:`aibom.cbom.image`): ``docker save`` / OCI archives and OCI layout directories. From
  the merged layers: the OS release (``/etc/os-release``), installed packages (dpkg, apk, rpm sqlite;
  :mod:`aibom.cbom.pkgdb`), Python distributions (``*.dist-info/METADATA``, ``*.egg-info/PKG-INFO``), Node
  packages (``node_modules/<pkg>/package.json``), Java archives (``META-INF/maven/**/pom.properties``, nested
  ``BOOT-INF/lib`` / ``WEB-INF/lib`` jars), Go build info and crypto-library version strings of every ELF file, and
  key / certificate files (the system CA trust stores are counted, not listed);
* **compiled binaries** (ELF, PE, Mach-O; :mod:`aibom.cbom.binscan`): linked crypto libraries, imported crypto
  functions, constant signatures, version strings, Go build info, embedded keys and certificates;
* **firmware and other packed blobs** (:mod:`aibom.cbom.unpack`): gzip / xz / LZMA / bzip2 streams, tar, cpio,
  U-Boot uImage, squashfs and zip, recursively under one budget; their files go through the same checks
  (binaries with imports and constants, package databases, key files).

Only crypto-relevant packages become inventory rows; everything left out is counted as coverage. Nothing is
written to disk except a compressed image tar's decompressed copy (a private temporary file, deleted at once).
"""

from __future__ import annotations

import io
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from aibom.cbom import pkgdb
from aibom.cbom.archives import ARCHIVE_SUFFIXES, KEY_SUFFIXES, VirtualFile
from aibom.cbom.binscan import MAX_BINARY_BYTES, BinaryFacts, binary_format, is_crypto_library, scan_binary
from aibom.cbom.unpack import Member, Refused, Walk, read_exact, safe_name, sniff

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_DB_BYTES = 64 * 1024 * 1024
MAX_SMALL = 1024 * 1024
MAX_JAR_DEPTH = 3
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

#: System CA bundles: hundreds of public CA certificates, counted instead of listed (the scan node does the same).
TRUST_STORE_DIRS = ("etc/ssl/certs/", "usr/share/ca-certificates/", "etc/pki/ca-trust/", "etc/pki/tls/certs/",
                    "usr/local/share/ca-certificates/", "etc/ca-certificates/", "usr/share/pki/",
                    "usr/lib/ssl/certs/", "var/lib/ca-certificates/",
                    # package-signing keys of the distribution (apt, rpm, apk)
                    "etc/apt/trusted.gpg.d/", "usr/share/keyrings/", "etc/pki/rpm-gpg/", "etc/apk/keys/",
                    "usr/share/apk/keys/")
TRUST_STORE_FILES = ("etc/apt/trusted.gpg",)
#: OS packages that are crypto libraries or tools (the knowledge base's tracked packages are added at run time).
_OS_CRYPTO = re.compile(r"^(?:openssl\S*|libopenssl\S*|libssl\S*|libcrypto\S*|\S*gnutls\S*|libgcrypt\S*|libnss3|nss|nss-\S+|"
                        r"libsodium\S*|\S*mbedtls\S*|libmbedcrypto\S*|wolfssl\S*|libwolfssl\S*|nettle|libnettle\S*|"
                        r"libhogweed\S*|openssh\S*|libssh\S*|botan\S*|libbotan\S*|libgpg-error\S*|gnupg\S*|gpg|"
                        r"libk5crypto\S*|krb5-libs|libkrb5\S*|cryptsetup\S*|libcryptsetup\S*|ca-certificates\S*|"
                        r"python3?-cryptography|py3-cryptography|libxcrypt\S*|libcrypt1|boringssl\S*|libressl\S*)$")
_PYPI_CRYPTO = frozenset({"cryptography", "pycryptodome", "pycryptodomex", "pycrypto", "pyopenssl", "pynacl",
                          "bcrypt", "pyjwt", "python-jose", "jwcrypto", "passlib", "argon2-cffi", "paramiko", "rsa",
                          "ecdsa", "tink", "m2crypto", "oscrypto", "cryptg", "tinyec", "pysodium", "libnacl"})
_NODE_PKG = re.compile(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/@][^/]*)/package\.json$")


@dataclass
class Package:
    ecosystem: str  # deb | apk | rpm | opkg | pypi | npm | maven | go | generic
    name: str
    version: str
    where: str  # upload path, with ``!`` between containers
    origin: str  # dpkg | apk | rpm | opkg | python | npm | maven | go | binary | soname
    image: str | None = None
    distro: dict[str, str] | None = None
    arch: str = ""
    library: str | None = None  # knowledge-base library (openssl ...) for a version string / soname


@dataclass
class BinaryRecord:
    where: str
    facts: BinaryFacts
    detail: bool  # imports and constants were read (standalone binaries, firmware); False inside an image
    image: str | None = None


@dataclass
class OsRecord:
    where: str
    release: dict[str, str]
    image: str | None = None


@dataclass
class PrivateKey:
    where: str
    algorithm: str | None
    key_size: int | None
    curve: str | None
    container: str  # pem | der


@dataclass
class ArtifactReport:
    packages: list[Package] = field(default_factory=list)
    binaries: list[BinaryRecord] = field(default_factory=list)
    systems: list[OsRecord] = field(default_factory=list)
    key_files: list[VirtualFile] = field(default_factory=list)
    private_keys: list[PrivateKey] = field(default_factory=list)
    images: list[tuple[str, str, int]] = field(default_factory=list)  # (where, name, layers)
    counts: dict[str, int] = field(default_factory=dict)

    def count(self, key: str, n: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + n

    def coverage(self) -> dict[str, str]:
        return {f"crypto:coverage:{k}": str(v) for k, v in sorted(self.counts.items()) if v}


def _crypto_os_package(name: str) -> bool:
    from aibom.cbom import crypto_kb

    return bool(_OS_CRYPTO.match(name.lower())) or crypto_kb.library_for(name) is not None


def _advisory_names(ecosystem: str) -> frozenset[str]:
    from aibom.cbom.advisories import load_advisories

    return frozenset(a.name.lower() for a in load_advisories() if a.ecosystem == ecosystem)


def crypto_language_package(ecosystem: str, name: str) -> bool:
    from aibom.cbom.rules import match_dep_coordinate

    low = name.lower()
    if low in _advisory_names(ecosystem):
        return True
    if ecosystem == "pypi":
        return low.replace("_", "-") in _PYPI_CRYPTO
    if ecosystem == "go":
        return match_dep_coordinate("go", low) is not None or any(low.startswith(n + "/") for n in _advisory_names("go"))
    return match_dep_coordinate(ecosystem, low) is not None


def _headers(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines()[:200]:
        if not line.strip():
            break
        if ":" in line and not line.startswith((" ", "\t")):
            key, value = line.split(":", 1)
            out.setdefault(key.strip().lower(), value.strip())
    return out


# --------------------------------------------------------------------------------------------- per-file checks
class Collector:
    """What one file inside an artifact contributes. ``detail``: read imports and constants of binaries."""

    def __init__(self, report: ArtifactReport, budget, *, detail: bool, image: str | None = None,
                 keys: bool = True) -> None:
        self.report = report
        self.budget = budget
        self.detail = detail
        self.image = image
        self.keys = keys  # False under a zip / jar: the archive key lane already reads those (archives.py)
        self.distro: dict[str, str] | None = None

    # results are lists of ("kind", payload); an image keeps them per path until its layers are merged
    def visit(self, where: str, path: str, member: Member) -> list[tuple[str, object]] | None:
        low = path.lower()
        try:
            if low in pkgdb.DPKG_STATUS or low.startswith(pkgdb.DPKG_STATUS_DIR) or low.endswith("usr/lib/opkg/status"):
                eco = "opkg" if low.endswith("opkg/status") else "deb"
                text = self._text(member, MAX_DB_BYTES)
                return [("pkgs", [(eco, row, eco if eco == "opkg" else "dpkg") for row in pkgdb.dpkg_status(text)])] \
                    if text is not None else None
            if low in pkgdb.APK_INSTALLED:
                text = self._text(member, MAX_DB_BYTES)
                return [("pkgs", [("apk", row, "apk") for row in pkgdb.apk_installed(text)])] if text is not None else None
            if low in pkgdb.RPM_SQLITE:
                data = member.read(MAX_DB_BYTES)
                if data is None:
                    return [("note", "rpmDatabaseTooLarge")]
                try:
                    return [("pkgs", [("rpm", row, "rpm") for row in pkgdb.rpm_sqlite(data)])]
                except ValueError:
                    return [("note", "rpmDatabaseUnreadable")]
            if low in pkgdb.RPM_UNPARSED:
                return [("note", "rpmBerkeleyDbNotParsed")]
            if low in pkgdb.OS_RELEASE:
                text = self._text(member, MAX_SMALL)
                return [("os", pkgdb.os_release(text))] if text is not None else None
            if low.endswith((".dist-info/metadata", ".egg-info/pkg-info")):
                text = self._text(member, MAX_SMALL)
                head = _headers(text or "")
                if head.get("name") and head.get("version"):
                    return [("lang", ("pypi", head["name"], head["version"], "python"))]
                return None
            m = _NODE_PKG.search(path)
            if m:
                text = self._text(member, MAX_SMALL)
                try:
                    doc = json.loads(text or "")
                except ValueError:
                    return None
                if isinstance(doc, dict) and isinstance(doc.get("name"), str) and isinstance(doc.get("version"), str):
                    return [("lang", ("npm", doc["name"], doc["version"], "npm"))]
                return None
            if low.endswith((".jar", ".war", ".ear")):
                data = member.read(MAX_DB_BYTES)
                return [("lang", item) for item in self._jar(data, 1, path)] if data is not None else None
            if low.endswith(KEY_SUFFIXES) or low.endswith(("/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519")):
                if low in TRUST_STORE_FILES or any(low.startswith(d) or f"/{d}" in low for d in TRUST_STORE_DIRS):
                    return [("note", "trustStoreFilesCounted")]
                if not self.keys:
                    return None
                data = member.read(MAX_SMALL)
                return self._key_file(where, data) if data is not None else None
            head = member.peek(64)
            if binary_format(head):
                if member.size > MAX_BINARY_BYTES:
                    return [("note", "binariesTooLarge")]
                data = member.read(MAX_BINARY_BYTES)
                if data is None:
                    return None
                facts = scan_binary(data, imports=self.detail, constants=self.detail)
                if facts is None:
                    return None
                out: list[tuple[str, object]] = [("note", "binariesRead")]
                if facts.self_test_keys:
                    out.append(("note", "cryptoLibrarySelfTestKeysNotReported"))
                if _interesting(facts, self.detail):
                    out.append(("binary", facts))
                for emb in facts.embedded:
                    out.extend(self._embedded(f"{where}!embedded-{emb.offset:x}", emb.label, emb.der))
                return out
        except Refused as exc:
            self.budget.refuse(exc.reason)
        return None

    def _text(self, member: Member, limit: int) -> str | None:
        data = member.read(limit)
        return data.decode("utf-8", "replace") if data is not None else None

    def _jar(self, data: bytes, depth: int, filename: str = "") -> list[tuple[str, str, str, str]]:
        """(maven, group:artifact, version, maven) of a Java archive and the archives nested in it. Coordinates come
        from ``META-INF/maven/<group>/<artifact>/pom.properties``; an archive built without Maven (Bouncy Castle's
        jars) is named from its manifest's ``Implementation-Vendor-Id`` and its file name ``<artifact>-<version>``."""
        from aibom.cbom.archives import _read_member, open_zip

        out: list[tuple[str, str, str, str]] = []
        try:
            zf = open_zip(io.BytesIO(data), self.budget)  # end record first (see archives.open_zip)
            if zf is None:
                return out
            infos = zf.infolist()
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
            self.budget.refuse("corruptArchive")
            return out
        has_pom = any(i.filename.startswith("META-INF/maven/") and i.filename.endswith("/pom.properties")
                      for i in infos[:20_000])
        m = re.match(r"^(?P<a>[A-Za-z][\w.\-]*?)-(?P<v>\d[\w.\-]*)\.(?:jar|war|ear)$", filename.rsplit("/", 1)[-1])
        if not has_pom and m:
            manifest = next((i for i in infos if i.filename == "META-INF/MANIFEST.MF"), None)
            body = _read_member(zf, manifest, MAX_SMALL, self.budget) if manifest is not None else None
            fields = _headers((body or b"").decode("utf-8", "replace").replace("\r\n", "\n").replace("\n ", ""))
            group = fields.get("implementation-vendor-id")
            if group and re.fullmatch(r"[\w.\-]{1,128}", group):
                out.append(("maven", f"{group}:{m.group('a')}", m.group("v"), "maven"))
        for info in infos[:20_000]:
            name = info.filename
            if name.endswith("/pom.properties") and name.startswith("META-INF/maven/"):
                body = _read_member(zf, info, MAX_SMALL, self.budget)
                if body is None:
                    continue
                props = {}
                for line in body.decode("utf-8", "replace").splitlines():
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        props[k.strip()] = v.strip()
                if props.get("groupId") and props.get("artifactId") and props.get("version"):
                    out.append(("maven", f"{props['groupId']}:{props['artifactId']}", props["version"], "maven"))
            elif name.lower().endswith(ARCHIVE_SUFFIXES) and depth < MAX_JAR_DEPTH:
                inner = _read_member(zf, info, MAX_DB_BYTES, self.budget)
                if inner is not None:
                    out.extend(self._jar(inner, depth + 1, name))
            elif name.lower().endswith(ARCHIVE_SUFFIXES):
                self.budget.skipped_depth += 1
        return out

    def _key_file(self, where: str, data: bytes) -> list[tuple[str, object]]:
        """A key / certificate file: private keys become material rows (they ship inside the artifact, so they are
        hard-coded); the rest (certificates, public keys) goes to the certificate lane with the private blocks cut
        out."""
        text = data.decode("latin-1")
        out: list[tuple[str, object]] = []
        rest = text
        for m in re.finditer(r"-----BEGIN ([A-Z0-9 ]{3,40})-----(.*?)-----END \1-----", text, re.S):
            label = m.group(1)
            if "PRIVATE KEY" in label:
                import base64
                import binascii

                body = re.sub(r"(?m)^[A-Za-z-]+: .*$", "", m.group(2))
                try:
                    der = base64.b64decode("".join(body.split()), validate=True)
                except (binascii.Error, ValueError):
                    der = b""
                out.extend(self._embedded(where, label, der, container="pem"))
                rest = rest.replace(m.group(0), "")
        if "PRIVATE KEY-----" not in text:
            from aibom.cbom.x509 import parse_private_key

            for label in ("RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY"):
                if data[:1] == b"\x30" and parse_private_key(data, label) is not None:  # a DER key file
                    return self._embedded(where, label, data, container="der")
        if rest.strip():
            out.append(("key", VirtualFile(where, rest.encode("latin-1"), {"crypto:artifact": where.split("!", 1)[0]})))
        return out

    def _embedded(self, where: str, label: str, der: bytes, container: str = "pem") -> list[tuple[str, object]]:
        from aibom.cbom.x509 import parse_private_key

        if "PRIVATE KEY" in label:
            if label == "ENCRYPTED PRIVATE KEY":
                return [("privkey", PrivateKey(where, None, None, None, "encrypted"))]
            info = parse_private_key(der, label if label in ("RSA PRIVATE KEY", "EC PRIVATE KEY") else "PRIVATE KEY")
            return [("privkey", PrivateKey(where, info.algorithm if info else None, info.key_size if info else None,
                                           info.curve if info else None, container))]
        if "CERTIFICATE" in label and "REQUEST" not in label:
            return [("key", VirtualFile(f"{where}.der", der, {"crypto:artifact": where.split("!", 1)[0]}))]
        return []

    def absorb(self, where: str, items: list[tuple[str, object]] | None) -> None:
        """Add one file's results to the report (images: only for files still visible after the merge)."""
        for kind, payload in items or ():
            if kind == "pkgs":
                for eco, row, origin in payload:  # type: ignore[union-attr]
                    if _crypto_os_package(row["name"]):
                        self.report.packages.append(Package(eco, row["name"], row["version"], where, origin,
                                                            self.image, self.distro, row.get("arch", "")))
                    else:
                        self.report.count("osPackagesNotCrypto")
            elif kind == "lang":
                eco, name, version, origin = payload  # type: ignore[misc]
                if crypto_language_package(eco, name):
                    self.report.packages.append(Package(eco, name, version, where, origin, self.image))
                else:
                    self.report.count("languagePackagesNotCrypto")
            elif kind == "os":
                self.report.systems.append(OsRecord(where, payload, self.image))  # type: ignore[arg-type]
            elif kind == "binary":
                facts: BinaryFacts = payload  # type: ignore[assignment]
                self.report.binaries.append(BinaryRecord(where, facts, self.detail, self.image))
                for path, version in facts.go_modules:
                    if crypto_language_package("go", path):
                        self.report.packages.append(Package("go", path, version, where, "go", self.image))
                for library, version in facts.versions:
                    if version:
                        self.report.packages.append(Package("generic", library, version, where, "binary", self.image,
                                                            library=library))
                if facts.go_old_format:
                    self.report.count("goBuildInfoBefore118NotRead")
            elif kind == "key":
                self.report.key_files.append(payload)  # type: ignore[arg-type]
            elif kind == "privkey":
                self.report.private_keys.append(payload)  # type: ignore[arg-type]
            elif kind == "note":
                self.report.count(str(payload))


def _interesting(facts: BinaryFacts, detail: bool = True) -> bool:
    """Whether a binary adds anything. Inside an image (``detail`` False) the linked libraries are the OS packages'
    own, already listed from the package database, so only version texts and Go modules count."""
    if not detail:
        return bool(facts.versions or facts.go_modules)
    return bool(facts.algorithms or facts.versions or facts.go_modules or facts.go_version or facts.apis
                or any(is_crypto_library(n) for n in facts.needed))


# --------------------------------------------------------------------------------------------- orchestration
def _open_head(path: Path, n: int = 512) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, n)
    except OSError:
        return None
    finally:
        os.close(fd)


def _image_visitors(report: ArtifactReport, budget, where_prefix: str):
    from aibom.cbom.image import ImageView

    def factory(view: ImageView):
        collector = Collector(report, budget, detail=False, image=view.name)

        def visit(path: str, member: Member):
            return collector.visit(f"{where_prefix}!{path}", path, member)

        visit.collector = collector  # type: ignore[attr-defined]
        factory.collectors.append((view, collector))  # type: ignore[attr-defined]
        return visit

    factory.collectors = []  # type: ignore[attr-defined]
    return factory


def _merge_images(report: ArtifactReport, factory, where: str) -> None:
    for view, collector in factory.collectors:
        report.images.append((where, view.name, view.layers))
        for key, value in view.coverage.items():
            report.count(f"image:{key}", value)
        # the OS release first, so package rows carry the distribution
        ordered = sorted(view.files.items(), key=lambda kv: 0 if any(k == "os" for k, _ in kv[1]) else 1)
        first = len(report.packages)
        for path, items in ordered:
            for kind, payload in items:
                if kind == "os":
                    collector.distro = payload  # type: ignore[assignment]
            collector.absorb(f"{where}!{path}", items)
        mine = report.packages[first:]
        if any(p.origin in ("dpkg", "apk", "rpm", "opkg") for p in mine):
            # the OS package database already lists the system libssl / libcrypto: their own version text is the
            # same library again (a library outside the package database, e.g. an app's bundled copy, stays)
            system_lib = re.compile(r"^(?:usr/)?lib(?:64|32)?/(?:[^/]+/)?lib(?:ssl|crypto)\.so[.\d]*$")
            report.packages[first:] = [p for p in mine if not (
                p.origin == "binary" and system_lib.match(p.where.rsplit("!", 1)[-1]))]


def collect(walk) -> ArtifactReport:
    """Every image, binary and firmware blob under the walk's root (see the module docstring)."""
    from aibom.cbom.image import read_image_file, read_layout_dir

    report = ArtifactReport()
    budget = walk.archive_budget
    layouts: list[Path] = []
    for path in walk.files(lambda p: p.name == "oci-layout", max_bytes=MAX_SMALL):
        layouts.append(path.parent)
    layout_dirs = {str(p) for p in layouts}
    for root in layouts:
        rel = walk.rel(root) if root != walk.root else "."
        factory = _image_visitors(report, budget, rel)
        try:
            read_layout_dir(root, rel, budget, factory)
        except Refused as exc:
            budget.refuse(exc.reason)
        _merge_images(report, factory, rel)
    for path in walk.files(max_bytes=MAX_ARTIFACT_BYTES):
        if any(str(path).startswith(d + os.sep) for d in layout_dirs):
            continue  # an OCI layout's blobs were read as layers
        head = _open_head(path)
        if not head:
            continue
        rel = walk.rel(path)
        kind = sniff(head)
        fmt = binary_format(head[:64])
        if kind in ("tar", "gzip", "xz", "bzip2") and (kind == "tar" or path.name.lower().endswith(
                (".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".oci", ".docker"))):
            factory = _image_visitors(report, budget, rel)
            try:
                views = read_image_file(path, rel, budget, factory)
            except (Refused, OSError) as exc:
                budget.refuse(getattr(exc, "reason", "unreadable"))
                views = []
            if views is not None:
                _merge_images(report, factory, rel)
                continue
        if fmt is not None:
            size = path.stat(follow_symlinks=False).st_size if not path.is_symlink() else 0
            if size > MAX_BINARY_BYTES:
                report.count("binariesTooLarge")
                continue
            data = walk.read_bytes(path, MAX_BINARY_BYTES)
            if data is None:
                continue
            report.count("binariesRead")
            facts = scan_binary(data)
            collector = Collector(report, budget, detail=True)
            if facts is not None:
                items: list[tuple[str, object]] = [("binary", facts)] if _interesting(facts) else []
                for emb in facts.embedded:
                    items.extend(collector._embedded(f"{rel}!embedded-{emb.offset:x}", emb.label, emb.der))
                collector.absorb(rel, items)
            continue
        if kind is None or kind == "zip" and path.name.lower().endswith(ARCHIVE_SUFFIXES[1:]):
            if kind == "zip":  # .jar / .war / .ear in the tree: their Maven coordinates
                data = walk.read_bytes(path, MAX_DB_BYTES)
                if data is not None:
                    collector = Collector(report, budget, detail=True)
                    collector.absorb(rel, [("lang", item) for item in collector._jar(data, 1, rel)])
            continue
        _firmware(report, budget, walk, path, rel, kind)
    return report


def _firmware(report: ArtifactReport, budget, walk, path: Path, rel: str, kind: str) -> None:
    """A packed blob (firmware image, compressed stream, tar, cpio, squashfs, uImage, zip): unpack it recursively
    and check every file inside it."""
    collector = Collector(report, budget, detail=True, keys=kind != "zip")

    def visit(where: str, member: Member) -> None:
        inner = where.rsplit("!", 1)[-1]
        collector.absorb(where, collector.visit(where, inner, member))

    walker = Walk(budget, visit)
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return
            if walker.stream(rel, fh, 0):
                report.count("firmwareImagesRead")
    except OSError:
        return
    if walker.symlinks:
        report.count("firmwareSymlinksNotFollowed", walker.symlinks)


__all__ = ["ArtifactReport", "BinaryRecord", "Collector", "OsRecord", "Package", "PrivateKey", "collect",
           "crypto_language_package"]
