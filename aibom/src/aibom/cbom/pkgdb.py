"""Installed-package databases and os-release, parsed from their bytes (no ``dpkg``/``rpm``/``apk`` binary).

Standard library only: this file is shared byte for byte by the code-scan engine (container image layers,
firmware) and the scan node's agent mode (the host's own ``/host`` mounts); a test keeps the two copies identical.

* dpkg: ``/var/lib/dpkg/status`` (and distroless ``/var/lib/dpkg/status.d/*``), RFC 822-style stanzas; a package
  counts when its ``Status`` ends in ``installed`` (deb-control(5), dpkg-query(1)).
* apk: ``/lib/apk/db/installed``, one stanza per package, ``P:`` name, ``V:`` version, ``A:`` arch, ``o:`` origin
  (Alpine's apk-spec "Installed Database").
* rpm: ``rpmdb.sqlite`` (RPM >= 4.16; Fedora 33+, RHEL/Alma/Rocky 9, Amazon Linux 2023), table ``Packages`` whose
  ``blob`` column is an RPM header without its 8-byte magic: ``il``/``dl`` (big-endian int32), ``il`` index
  entries of (tag, type, offset, count) and the data store (rpm's ``lib/header.c``; tags from ``rpmtag.h``:
  NAME 1000, VERSION 1001, RELEASE 1002, EPOCH 1003, ARCH 1022). The older Berkeley DB ``Packages`` file and the
  NDB ``Packages.db`` are not parsed (the caller reports them as not covered).
* os-release: ``/etc/os-release`` / ``/usr/lib/os-release`` (os-release(5)).
"""

from __future__ import annotations

import sqlite3
import struct

MAX_PACKAGES = 20_000
MAX_DB_BYTES = 64 * 1024 * 1024

DPKG_STATUS = ("var/lib/dpkg/status",)
DPKG_STATUS_DIR = "var/lib/dpkg/status.d/"
APK_INSTALLED = ("lib/apk/db/installed",)
RPM_SQLITE = ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite")
RPM_UNPARSED = ("var/lib/rpm/Packages", "var/lib/rpm/Packages.db", "usr/lib/sysimage/rpm/Packages.db")
OS_RELEASE = ("etc/os-release", "usr/lib/os-release")


def os_release(text: str) -> dict[str, str]:
    """KEY=value pairs of an os-release file (quotes removed); keys lower-cased (``id``, ``version_id`` ...)."""
    out: dict[str, str] = {}
    for line in text.splitlines()[:200]:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip().lower()[:64]] = value[:200]
    return out


def _stanzas(text: str):
    block: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            if block:
                yield block
                block = []
            continue
        block.append(line)
    if block:
        yield block


def dpkg_status(text: str) -> list[dict[str, str]]:
    """Installed packages of a dpkg status file: name, version, arch, source."""
    out: list[dict[str, str]] = []
    for block in _stanzas(text):
        fields: dict[str, str] = {}
        for line in block:
            if line[:1] in (" ", "\t") or ":" not in line:
                continue  # continuation line (descriptions, conffiles)
            key, value = line.split(":", 1)
            key = key.strip().lower()
            if key in ("package", "version", "architecture", "status", "source"):
                fields[key] = value.strip()
        status = fields.get("status", "install ok installed")
        if not fields.get("package") or not fields.get("version") or not status.endswith(" installed"):
            continue
        row = {"name": fields["package"][:128], "version": fields["version"][:128],
               "arch": fields.get("architecture", "")[:32]}
        if fields.get("source"):
            row["source"] = fields["source"].split(" ", 1)[0][:128]
        out.append(row)
        if len(out) >= MAX_PACKAGES:
            break
    return out


def apk_installed(text: str) -> list[dict[str, str]]:
    """Installed packages of an Alpine apk database: name, version, arch, origin."""
    out: list[dict[str, str]] = []
    for block in _stanzas(text):
        fields: dict[str, str] = {}
        for line in block:
            if len(line) > 2 and line[1] == ":" and line[0] in "PVAo":
                fields.setdefault(line[0], line[2:].strip())
        if fields.get("P") and fields.get("V"):
            row = {"name": fields["P"][:128], "version": fields["V"][:128], "arch": fields.get("A", "")[:32]}
            if fields.get("o"):
                row["source"] = fields["o"][:128]
            out.append(row)
            if len(out) >= MAX_PACKAGES:
                break
    return out


_RPM_STRING_TYPES = (6, 8, 9)  # STRING, STRING_ARRAY, I18NSTRING (first string)
_RPM_TAGS = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1022: "arch", 1044: "sourcerpm"}


def rpm_header(blob: bytes) -> dict[str, str]:
    """NAME, VERSION, RELEASE, EPOCH, ARCH, SOURCERPM of one RPM header blob (ValueError when malformed)."""
    if len(blob) < 8:
        raise ValueError("short header")
    il, dl = struct.unpack_from(">ii", blob, 0)
    if il <= 0 or dl < 0 or il > 100_000 or 8 + 16 * il + dl > len(blob):
        raise ValueError("bad header counts")
    store = 8 + 16 * il
    out: dict[str, str] = {}
    for i in range(il):
        tag, typ, offset, count = struct.unpack_from(">iiii", blob, 8 + 16 * i)
        name = _RPM_TAGS.get(tag)
        if name is None or offset < 0 or offset >= dl:
            continue
        pos = store + offset
        if typ in _RPM_STRING_TYPES:
            end = blob.find(b"\x00", pos, store + dl)
            if end < 0:
                continue
            out[name] = blob[pos:end].decode("utf-8", "replace")[:128]
        elif typ == 4 and count >= 1 and pos + 4 <= store + dl:  # INT32
            out[name] = str(struct.unpack_from(">i", blob, pos)[0])
    return out


def rpm_sqlite(data: bytes) -> list[dict[str, str]]:
    """Installed packages of an ``rpmdb.sqlite`` held in memory: name, version (``[epoch:]version-release``), arch,
    source (the source RPM). ValueError when the bytes are not that database."""
    if len(data) > MAX_DB_BYTES or not data.startswith(b"SQLite format 3\x00"):
        raise ValueError("not an sqlite database")
    con = sqlite3.connect(":memory:")
    steps = [0]

    def _abort() -> int:  # a crafted schema must not run forever (sqlite.org/security.html)
        steps[0] += 1
        return 1 if steps[0] > 200_000 else 0

    try:
        if hasattr(con, "setconfig") and hasattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE"):
            con.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        con.deserialize(data)
        con.set_progress_handler(_abort, 1000)
        con.execute("PRAGMA trusted_schema=OFF")
        con.execute("PRAGMA query_only=ON")
        kind = con.execute("SELECT type FROM sqlite_master WHERE name = 'Packages'").fetchone()
        if kind != ("table",):  # a view or trigger in an untrusted file is never run
            raise ValueError("no Packages table")
        rows = con.execute("SELECT blob FROM Packages LIMIT ?", (MAX_PACKAGES,)).fetchall()
    except sqlite3.Error as exc:
        raise ValueError(f"unreadable rpm database ({exc.__class__.__name__})") from None
    finally:
        con.close()
    out: list[dict[str, str]] = []
    for (blob,) in rows:
        if not isinstance(blob, bytes):
            continue
        try:
            head = rpm_header(blob)
        except (ValueError, struct.error):
            continue
        if not head.get("name") or not head.get("version") or head["name"] == "gpg-pubkey":
            continue
        version = head["version"] + (f"-{head['release']}" if head.get("release") else "")
        if head.get("epoch") and head["epoch"] != "0":
            version = f"{head['epoch']}:{version}"
        row = {"name": head["name"], "version": version, "arch": head.get("arch", "")}
        if head.get("sourcerpm"):
            row["source"] = head["sourcerpm"]
        out.append(row)
    return out


def purl(ecosystem: str, name: str, version: str, distro: dict[str, str] | None = None, arch: str = "") -> str:
    """A package URL (purl-spec) for an OS package: ``pkg:deb/debian/libssl1.1@1.1.0j-1~deb9u1?arch=amd64``."""
    from urllib.parse import quote

    namespace = (distro or {}).get("id") or {"deb": "debian", "apk": "alpine", "rpm": "redhat"}.get(ecosystem, "")
    qualifiers = []
    if arch:
        qualifiers.append(f"arch={quote(arch, safe='')}")
    if distro and distro.get("id") and distro.get("version_id"):
        qualifiers.append(f"distro={quote(distro['id'] + '-' + distro['version_id'], safe='')}")
    query = ("?" + "&".join(qualifiers)) if qualifiers else ""
    ns = f"{quote(namespace, safe='')}/" if namespace else ""
    return f"pkg:{ecosystem}/{ns}{quote(name, safe='')}@{quote(version, safe=':~+')}{query}"


__all__ = ["APK_INSTALLED", "DPKG_STATUS", "DPKG_STATUS_DIR", "OS_RELEASE", "RPM_SQLITE", "RPM_UNPARSED",
           "apk_installed", "dpkg_status", "os_release", "purl", "rpm_header", "rpm_sqlite"]
