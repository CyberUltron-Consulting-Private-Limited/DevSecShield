"""Agent mode (``ZS_MODE=agent``): collect the node's OWN host, read from read-only mounts, with no credentials.

The host's root file system is mounted read-only at ``ZS_HOST_ROOT`` (default ``/host``; the Helm DaemonSet mounts
``/`` there).  Nothing is executed on the host and no network connection is made: every fact comes from files, read
through :mod:`zs_scan_node.hostfs` (symlinks resolved inside the host root, regular files only, size caps, one
device per walk).  The same asset types and fact shapes as the SSH collector are emitted, so the server classifies
them the same way:

* OS release and kernel, system crypto policy, FIPS mode (``os_crypto_policy``);
* installed crypto packages from the package databases (dpkg status, apk installed, rpm sqlite; the same
  :mod:`zs_scan_node.pkgdb` the code-scan engine uses for container images), with a package URL (``crypto_library``);
* ``sshd_config`` (configured values; ``sshd -T`` is not run) and SSH host public keys;
* certificates, private keys (public half and file mode only), authorized_keys and keystores under the Tier 2
  search roots, the system trust stores as one summary row each;
* with ``ZS_HOST_PROC`` (the DaemonSet's ``hostPID`` option): crypto libraries mapped by running processes, for the
  processes whose memory map (``/proc/<pid>/maps``) the node may read: the kernel allows that for processes of the
  node's own user, and for every process only with ``CAP_SYS_PTRACE`` (chart values ``agent.runAsRoot`` and
  ``agent.sysPtrace``; a host AppArmor or SELinux policy may still refuse it).

Files the node's user cannot read are counted as coverage rows: run the agent as root (chart value
``agent.runAsRoot``) to read root-only files, as Tier 2 does with sudo.  The key and certificate search walks the
Tier 2 roots without listing any directory into memory, within the walk caps of :mod:`zs_scan_node.hostfs`, and stops
at the job's deadline; what it skipped is reported as coverage.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import time
from typing import Any

from cryptography.hazmat.primitives import serialization

from zs_scan_node import commands as C
from zs_scan_node import linux_parsers as P
from zs_scan_node import pkgdb
from zs_scan_node.certparse import cert_facts, key_facts, load_certs
from zs_scan_node.collectors import ConfigError
from zs_scan_node.hostfs import MAX_DEPTH, MAX_DIR_ENTRIES, MAX_WALK_ENTRIES, HostFS, WalkStats
from zs_scan_node.jobctx import JobContext
from zs_scan_node.scrub import printable

MAX_SMALL = 1024 * 1024
MAX_FILES = 2000
MAX_PROCS = 4096
KEY_FILE_RE = re.compile(C.KEY_FILE_RE)
CRYPTO_LIB_RE = re.compile(r"/(?:" + C.CRYPTO_LIBS_RE + r")[\w.\-]*\.so[\w.\-]*$")
TRUST_DIRS = ("/etc/ssl/certs/", "/etc/pki/tls/certs/", "/etc/pki/ca-trust/", "/usr/local/share/ca-certificates/",
              "/usr/share/ca-certificates/", "/etc/ca-certificates/")
TRUST_NAMES = ("ca-certificates.crt", "ca-bundle.crt", "tls-ca-bundle.pem", "ca-bundle.trust.crt")


def host_root() -> str:
    return os.environ.get("ZS_HOST_ROOT", "/host")


def _label() -> str:
    return (os.environ.get("ZS_NODE_NAME") or os.uname().nodename or "host")[:255]


def _fs() -> HostFS:
    root = host_root()
    if not os.path.isdir(root):
        raise ConfigError(f"the host file system is not mounted at {root} (set ZS_HOST_ROOT or mount / read-only there)")
    return HostFS(root)


# ----------------------------------------------------------------------------- packages
def installed_packages(fs: HostFS) -> tuple[str | None, list[dict[str, str]], list[str]]:
    """(ecosystem, packages, notes) from the host's package databases."""
    notes: list[str] = []
    found = fs.read("/" + pkgdb.DPKG_STATUS[0], pkgdb.MAX_DB_BYTES)
    rows: list[dict[str, str]] = []
    if found.ok:
        rows = pkgdb.dpkg_status(found.text())
    for name in fs.listdir("/" + pkgdb.DPKG_STATUS_DIR) or []:  # distroless images keep one file per package
        part = fs.read("/" + pkgdb.DPKG_STATUS_DIR + name, MAX_SMALL)
        if part.ok:
            rows += pkgdb.dpkg_status(part.text())
    if found.ok or rows:
        return "deb", rows, notes
    if found.status in ("denied", "too_large"):
        notes.append(f"dpkg status {found.status}")
    found = fs.read("/" + pkgdb.APK_INSTALLED[0], pkgdb.MAX_DB_BYTES)
    if found.ok:
        return "apk", pkgdb.apk_installed(found.text()), notes
    for path in pkgdb.RPM_SQLITE:
        found = fs.read("/" + path, pkgdb.MAX_DB_BYTES)
        if found.ok:
            try:
                return "rpm", pkgdb.rpm_sqlite(found.data), notes
            except ValueError as exc:
                notes.append(f"rpm database unreadable ({exc})")
                return "rpm", [], notes
        if found.status in ("denied", "too_large"):
            notes.append(f"{path}: {found.status}")
    for path in pkgdb.RPM_UNPARSED:
        if fs.read("/" + path, 0).status in ("ok", "too_large"):  # present (size 0 reads as ok)
            notes.append("the rpm database is in the Berkeley DB / NDB format, which the agent does not parse")
            return "rpm", [], notes
    return None, [], notes


# ----------------------------------------------------------------------------- files
def _is_trust_store(path: str) -> bool:
    return path.startswith(TRUST_DIRS) or path.rsplit("/", 1)[-1] in TRUST_NAMES


def _ssh_public(text: str) -> dict[str, Any] | None:
    """type / bits / SHA256 fingerprint / comment of one OpenSSH public key line (like ``ssh-keygen -l``)."""
    parts = text.strip().split()
    if len(parts) < 2:
        return None
    try:
        key = serialization.load_ssh_public_key(" ".join(parts[:2]).encode())
        blob = base64.b64decode(parts[1])
    except Exception:
        return None
    facts = key_facts(key)
    kind = {"RSA": "RSA", "EC": "ECDSA", "Ed25519": "ED25519", "DSA": "DSA", "Ed448": "ED448"}.get(facts.get("key_alg"),
                                                                                             str(facts.get("key_alg")))
    return {"type": kind, "bits": facts.get("key_size"), "comment": printable(" ".join(parts[2:]), 120),
            "fingerprint": "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")}


def _private_key_facts(data: bytes) -> dict[str, Any]:
    text = data.decode("latin-1")
    if "ENCRYPTED" in text or "Proc-Type: 4,ENCRYPTED" in text:
        return {"encrypted": True, "detail": "passphrase-protected"}
    loader = serialization.load_pem_private_key if b"-----BEGIN" in data else serialization.load_der_private_key
    try:
        key = loader(data, password=None)
    except TypeError:
        return {"encrypted": True, "detail": "passphrase-protected"}
    except Exception:
        return {"parsed": False, "detail": "not a PEM/PKCS#8 key"}
    pub = key.public_key()
    facts = key_facts(pub)
    try:
        der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        facts["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
    except Exception:
        pass
    facts.update({"encrypted": False, "readable": True})
    return facts


def _trust_summary(certs: list[dict]) -> dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {"trust_store": True, "count": len(certs),
            "sha1_signed": sum(1 for c in certs if "sha1" in str(c.get("sig_alg", "")).lower()),
            "md5_signed": sum(1 for c in certs if "md5" in str(c.get("sig_alg", "")).lower()),
            "rsa_under_2048": sum(1 for c in certs if c.get("key_alg") == "RSA" and (c.get("key_size") or 0) < 2048),
            "expired": sum(1 for c in certs if (c.get("not_after") or "9") < now)}


def _inspect(ctx: JobContext, fs: HostFS, loc: str, path: str) -> int:
    kind = P.classify_file(path)
    shown = P.display_path(path)
    got = fs.read(path, MAX_SMALL)
    mode = got.mode
    if not got.ok:
        ctx.coverage(loc, "key and certificate files", "denied" if got.status == "denied" else "error",
                     f"{got.status}: e.g. {shown}", once=True)
        if kind in ("key", "ssh_private_key"):
            ctx.emit("private_key", loc, shown, name=shown.rsplit("/", 1)[-1], facts={"path": shown, "readable": False})
            return 1
        return 0
    mode_facts = {"mode": format(mode, "04o"), "world_readable": bool(mode & 0o004)} if mode is not None else {}
    if kind in ("pem", "cert"):
        certs = [cert_facts(c, "file") for c in load_certs(got.data, 500)]
        if len(certs) > 1 and (_is_trust_store(shown) or P.is_ca_bundle(certs)):
            ctx.emit("certificate", loc, shown, name=f"Trust store ({len(certs)} CA certificates)",
                     facts={"path": shown, **_trust_summary(certs)})
            return 1
        n = 0
        for i, c in enumerate(certs[:200]):
            ctx.emit("certificate", loc, shown if len(certs) == 1 else f"{shown}#{i}", name=c.get("subject", ""),
                     algorithm=c.get("key_alg"), key_size=c.get("key_size"), facts={**c, "path": shown, "index": i})
            n += 1
        if b"PRIVATE KEY-----" in got.data:
            facts = {"path": shown, **_private_key_facts(got.data), **mode_facts}
            ctx.emit("private_key", loc, shown, name=shown.rsplit("/", 1)[-1], algorithm=facts.get("key_alg"),
                     key_size=facts.get("key_size"), facts=facts)
            n += 1
        elif not certs:
            ctx.emit("certificate", loc, shown, name=shown.rsplit("/", 1)[-1],
                     facts={"path": shown, "readable": True, "parsed": False, "detail": "no certificate found"})
            n += 1
        return n
    if kind == "key":
        facts = {"path": shown, **_private_key_facts(got.data), **mode_facts}
        ctx.emit("private_key", loc, shown, name=shown.rsplit("/", 1)[-1], algorithm=facts.get("key_alg"),
                 key_size=facts.get("key_size"), facts=facts)
        return 1
    if kind == "ssh_private_key":
        pub = fs.read(path + ".pub", 64 * 1024)
        k = _ssh_public(pub.text()) if pub.ok else None
        ctx.emit("private_key", loc, shown, name=shown.rsplit("/", 1)[-1], algorithm=(k or {}).get("type"),
                 key_size=(k or {}).get("bits"),
                 facts={"path": shown, "format": "openssh", **(k or {}), "readable": True, "parsed": bool(k),
                        **mode_facts})
        return 1
    if kind == "authorized_keys":
        keys = [k for k in (_ssh_public(line) for line in got.text().splitlines()[:200]
                            if line.strip() and not line.lstrip().startswith("#")) if k]
        if not keys:
            ctx.emit("public_key", loc, shown, name="authorized_keys", facts={"path": shown, "readable": True,
                                                                             "parsed": False})
            return 1
        for i, k in enumerate(keys):
            ctx.emit("public_key", loc, shown if len(keys) == 1 else f"{shown}#{i}", name=k.get("comment") or "authorized key",
                     algorithm=k["type"], key_size=k["bits"], facts={"path": shown, **k, "authorized_key": True})
        return len(keys)
    if kind == "keystore":
        # listing a keystore needs keytool on the host (Tier 2 over SSH does that); the agent records the file only
        ctx.emit("keystore", loc, shown, name=shown.rsplit("/", 1)[-1],
                 facts={"path": shown, "listed": False, "reason": "keystores are listed by the SSH collector (keytool)",
                        **mode_facts})
        return 1
    return 0


# ----------------------------------------------------------------------------- processes
def _process_libraries(ctx: JobContext, loc: str, emit) -> None:
    proc = os.environ.get("ZS_HOST_PROC")
    if not proc:
        ctx.coverage(loc, "process crypto libraries", "not_supported",
                     "process libraries need the DaemonSet's hostPID option (ZS_HOST_PROC)", once=True)
        return
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    denied = seen = 0
    try:
        pids = sorted(int(p) for p in os.listdir(proc) if p.isdigit())[:MAX_PROCS]
    except OSError:
        pids = []
    for pid in pids:
        seen += 1
        try:
            with open(os.path.join(proc, str(pid), "maps"), encoding="utf-8", errors="replace") as f:
                maps = f.read(4 * 1024 * 1024)
            with open(os.path.join(proc, str(pid), "comm"), encoding="utf-8", errors="replace") as f:
                comm = f.read(64).strip()
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        for line in maps.splitlines():
            m = re.search(r"\s(/\S.*?)(\s\(deleted\))?$", line)
            if not m or not CRYPTO_LIB_RE.search(m.group(1)):
                continue
            g = grouped.setdefault((comm, m.group(1)), {"exe": "", "lib": printable(m.group(1), 300), "pids": [],
                                                        "deleted": False, "ports": [], "process": printable(comm, 64)})
            if pid not in g["pids"]:
                g["pids"].append(pid)
            g["deleted"] = g["deleted"] or bool(m.group(2))
    for (_comm, lib), g in list(grouped.items())[:1000]:
        g["pids"] = g["pids"][:20]
        emit("process_library", loc, lib, name=g["process"] or lib.rsplit("/", 1)[-1], facts=g)
    if denied:
        # /proc/<pid>/maps of another user's process needs CAP_SYS_PTRACE, not only uid 0 (ptrace access mode READ)
        ctx.coverage(loc, "process crypto libraries", "denied",
                     f"{denied} of {seen} processes could not be read: the library map of another user's process needs "
                     "CAP_SYS_PTRACE (Helm: agent.runAsRoot=true and agent.sysPtrace=true; a host AppArmor or SELinux "
                     "policy may still refuse it)", once=True)


# ----------------------------------------------------------------------------- entry points
def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    if secrets:
        raise ConfigError("an agent-mode collection never carries credentials; the job was refused")
    fs = _fs()
    loc = _label()
    started = time.monotonic()
    emitted = 0

    def emit(*args, **kwargs):
        nonlocal emitted
        ctx.emit(*args, **kwargs)
        emitted += 1

    facts: dict[str, Any] = {"agent": True, "host_root": fs.root}
    release = fs.read("/etc/os-release", MAX_SMALL)
    if not release.ok:
        release = fs.read("/usr/lib/os-release", MAX_SMALL)
    os_info = pkgdb.os_release(release.text()) if release.ok else {}
    facts["os"] = {k: printable(v, 120) for k, v in os_info.items() if k in ("id", "id_like", "version_id",
                                                                                "pretty_name", "name")}
    facts["kernel"] = os.uname().release[:100]  # a container shares the host's kernel
    policy = fs.read("/etc/crypto-policies/config", 4096)
    facts["crypto_policy"] = policy.text().strip()[:60] if policy.ok else None
    try:
        with open("/proc/sys/crypto/fips_enabled", encoding="ascii") as f:  # kernel-wide, same inside a container
            facts["fips_enabled"] = f.read(8).strip() == "1"
    except OSError:
        facts["fips_enabled"] = None

    ecosystem, packages, notes = installed_packages(fs)
    for note in notes:
        ctx.coverage(loc, "package list", "error", note, once=True)
    if ecosystem is None:
        ctx.coverage(loc, "package list", "not_supported", "no dpkg, apk or rpm package database was found", once=True)
    distro = {"id": os_info.get("id", ""), "version_id": os_info.get("version_id", "")} if os_info.get("id") else None
    for pkg in packages:
        if not P.CRYPTO_PACKAGES.match(pkg["name"]):
            continue
        name, version = printable(pkg["name"], 100), printable(pkg["version"], 100)
        if name.startswith(("openssl", "libssl", "openssl-libs")) and "openssl" not in facts:
            facts["openssl"] = {"implementation": "OpenSSL", "version": version, "source": "package"}
        emit("crypto_library", loc, f"package:{name}", name=name,
             facts={"name": name, "version": version, "arch": pkg.get("arch", ""), "source": "package",
                    "package_manager": ecosystem, "purl": pkgdb.purl(ecosystem or "", name, version, distro,
                                                                     pkg.get("arch", ""))})

    for ktype in C.HOST_KEY_TYPES:
        path = f"/etc/ssh/ssh_host_{ktype}_key.pub"
        got = fs.read(path, 64 * 1024)
        k = _ssh_public(got.text()) if got.ok else None
        if k:
            emit("ssh_host_key", loc, path, name=f"{k['type']} host key", algorithm=k["type"], key_size=k["bits"],
                 facts=k)
    sshd = fs.read("/etc/ssh/sshd_config", MAX_SMALL)
    if sshd.ok and sshd.text().strip():
        emit("ssh_server_config", loc, "/etc/ssh/sshd_config", name="sshd configuration (file)",
             facts=P.sshd_config(sshd.text(), effective=False))
    elif sshd.status == "denied":
        ctx.coverage(loc, "sshd configuration", "denied", "/etc/ssh/sshd_config is not readable by the node's user")

    emit("os_crypto_policy", loc, "os", name=facts["os"].get("pretty_name") or "operating system", facts=facts)
    _process_libraries(ctx, loc, emit)

    stats = WalkStats()
    trust: dict[str, list[str]] = {}
    paths: list[str] = []
    for top in C.KEY_FILE_ROOTS:
        for path in fs.walk(top, KEY_FILE_RE, MAX_FILES, 1024 * 1024, stats, stop=ctx.should_stop):
            paths.append(path)
    for path in paths:
        if _is_trust_store(path) and P.classify_file(path) in ("pem", "cert"):
            trust.setdefault(path.rsplit("/", 1)[0], []).append(path)
    for directory, files in trust.items():
        if len(files) > 1:  # a hashed CA directory: one summary row
            certs: list[dict] = []
            for path in files:
                got = fs.read(path, MAX_SMALL)
                certs += [cert_facts(c, "file") for c in load_certs(got.data, 500)] if got.ok else []
            emit("certificate", loc, directory, name=f"Trust store directory ({len(files)} files)",
                 facts={"path": directory, "files": len(files), "files_read": len(files), **_trust_summary(certs)})
            paths = [p for p in paths if p not in set(files)]
    # one coverage row per check and status: what the search and the reads left out, together
    truncated: list[str] = []
    if stats.stopped:
        truncated.append(f"the search stopped early ({stats.stopped}) after {stats.entries} directory entries")
    if stats.entries_capped:
        truncated.append(f"the search stopped after {MAX_WALK_ENTRIES:,} directory entries")
    if stats.big_dirs:
        truncated.append(f"{stats.big_dirs} directories with more than {MAX_DIR_ENTRIES:,} entries were searched in "
                         f"part (e.g. {', '.join(stats.big_examples[:3])})")
    if stats.too_deep:
        truncated.append(f"{stats.too_deep} directories more than {MAX_DEPTH} levels deep were not searched")
    if stats.truncated:
        truncated.append(f"only the first {MAX_FILES} files were read")
    for path in paths:
        if ctx.should_stop():
            truncated.append("stopped before every file was read")
            break
        emitted += _inspect(ctx, fs, loc, path)
    if truncated:
        ctx.coverage(loc, "key and certificate files", "truncated", "; ".join(truncated))
    if stats.denied_dirs:
        ctx.coverage(loc, "key and certificate files", "denied",
                     f"{stats.denied_dirs} directories were not readable by the node's user (e.g. "
                     f"{', '.join(stats.denied_examples[:3])}); run the agent as root to search them")
    ctx.outcome(loc, "ok", started=started, assets=emitted)
    return f"Host {loc} collected in agent mode: {emitted} assets"


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    if secrets:
        raise ConfigError("an agent-mode collection never carries credentials; the job was refused")
    loc = _label()
    try:
        fs = _fs()
    except ConfigError as exc:
        ctx.samples.append({"target": loc, "status": "error", "reachable": None, "login": False, "privilege": None,
                            "note": str(exc)})
        return str(exc)
    release = fs.read("/etc/os-release", MAX_SMALL)
    ecosystem, _packages, _notes = installed_packages(fs)
    readable = release.ok or ecosystem is not None
    ctx.samples.append({"target": loc, "status": "ready" if readable else "error", "reachable": True, "login": True,
                        "privilege": None,
                        "note": "host file system mounted read-only" if readable else
                        f"nothing readable under {fs.root} (is / mounted there?)"})
    return f"Host file system of {loc} readable" if readable else f"Host file system of {loc} not readable"
