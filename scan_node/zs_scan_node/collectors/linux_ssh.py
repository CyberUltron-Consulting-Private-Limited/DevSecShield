"""Linux servers over SSH: read-only commands, Tier 1 as the login user, Tier 2 through exact sudo lines.

Safety rules:
* Host keys: ``pinned`` checks the customer's known_hosts; ``tofu`` pins per (address, port, key type) in the
  node's state directory, and once a host is pinned only the pinned key types are offered, so a server (or a
  man in the middle) cannot dodge the pin by presenting another key type.  A mismatch stops that target before
  any credential is sent.
* Authentication is tried once.  Keyboard-interactive is answered only for a single password prompt; anything
  else (OTP, Duo, several prompts) is reported as ``mfa_required``.  No agent, no local key files.
* Every command is from ``zs_scan_node.commands``; file paths come only from the Tier 2 find, must be absolute
  without control characters, and are shell-quoted.  Commands run without a PTY, with stdin closed, a timeout and
  an output cap.
* Private key material never leaves the host: only ``openssl pkey -pubout`` (public half) and
  ``ssh-keygen -l`` (fingerprint) are run on key files.
"""
from __future__ import annotations

import concurrent.futures as cf
import io
import json
import os
import shlex
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any

import paramiko

from zs_scan_node import commands as C
from zs_scan_node import linux_parsers as P
from zs_scan_node.certparse import public_key_facts_from_pem
from zs_scan_node.collectors import ConfigError
from zs_scan_node.jobctx import JobContext
from zs_scan_node import netutil
from zs_scan_node.netutil import Target, expand_targets

OUTPUT_CAP = 4 * 1024 * 1024
CMD_TIMEOUT = 60
FILE_CMD_TIMEOUT = 20
MAX_FILES = 2000
RSA_ALGS = ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")
_pin_lock = threading.Lock()


class TargetFail(Exception):
    def __init__(self, status: str, error: str = "") -> None:
        super().__init__(error or status)
        self.status = status
        self.error = error


class _MFA(Exception):
    pass


# ----------------------------------------------------------------------------- host key pins
def _pins_path(state_dir: str) -> str:
    return os.path.join(state_dir, "known_hosts.json")


def load_pins(state_dir: str) -> dict[str, dict[str, str]]:
    try:
        with open(_pins_path(state_dir), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_pin(state_dir: str, host_port: str, key_type: str, fingerprint: str) -> None:
    with _pin_lock:
        pins = load_pins(state_dir)
        pins.setdefault(host_port, {})[key_type] = fingerprint
        tmp = _pins_path(state_dir) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(pins, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, _pins_path(state_dir))


def _fp(key: paramiko.PKey) -> str:
    import base64
    import hashlib

    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def _algs_for(key_types: list[str]) -> list[str]:
    out = []
    for kt in key_types:
        out.extend(RSA_ALGS if kt == "ssh-rsa" else (kt,))
    return out


def _pinned_known_hosts(text: str) -> paramiko.HostKeys:
    hk = paramiko.HostKeys()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            entry = paramiko.hostkeys.HostKeyEntry.from_line(line)
        except Exception:
            continue
        if entry is None:
            continue
        for name in entry.hostnames:
            hk.add(name, entry.key.get_name(), entry.key)
    return hk


# ----------------------------------------------------------------------------- credentials
def _load_private_key(text: str) -> paramiko.PKey:
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except Exception:
            continue
    raise ConfigError("the private key could not be loaded (unsupported type or encrypted)")


def _credentials(ctx: JobContext, config: dict, secrets: dict) -> dict[str, Any]:
    ctype = config.get("credential_type") or "node_key"
    if ctype == "node_key":
        path = ctx.node_private_key_path or os.path.join(ctx.state_dir, "id_ed25519")
        try:
            return {"key": paramiko.Ed25519Key.from_private_key_file(path)}
        except Exception as exc:
            raise ConfigError(f"the scan node's own SSH key is not available ({exc.__class__.__name__})") from None
    if ctype == "ssh_cert":
        if not secrets.get("private_key"):
            raise ConfigError("the SSH certificate credential has no private key")
        key = _load_private_key(secrets["private_key"])
        if secrets.get("ssh_certificate"):
            try:
                key.load_certificate(secrets["ssh_certificate"].strip())
            except Exception as exc:
                raise ConfigError(f"the SSH certificate does not match the key ({exc.__class__.__name__})") from None
        return {"key": key}
    if ctype == "password":
        if not secrets.get("password"):
            raise ConfigError("no password is stored for this source")
        return {"password": secrets["password"]}
    if ctype == "vault":
        from zs_scan_node import vault

        ref = config.get("vault") or {}
        creds = vault.fetch(str(ref.get("provider")), str(ref.get("path") or ""), ctx.vault_prefix)
        for value in creds.values():
            ctx.scrubber.add(value)
        if creds.get("private_key"):
            key = _load_private_key(creds["private_key"])
            if creds.get("ssh_certificate"):
                key.load_certificate(creds["ssh_certificate"].strip())
            return {"key": key}
        if creds.get("password"):
            return {"password": creds["password"]}
        raise ConfigError("the vault secret has neither 'password' nor 'private_key'")
    raise ConfigError(f"credential type {ctype} is not supported")


# ----------------------------------------------------------------------------- session
@dataclass
class Session:
    transport: paramiko.Transport
    host_key: dict[str, Any]

    def run(self, command: str, timeout: float = CMD_TIMEOUT, binary: bool = False) -> tuple[int | None, Any, str, bool]:
        """(exit status, stdout, stderr, timed_out).  stdout is bytes when ``binary`` else str."""
        chan = self.transport.open_session(timeout=10)
        try:
            chan.settimeout(1.0)
            chan.exec_command(command)
            chan.shutdown_write()
            out, err = bytearray(), bytearray()
            deadline = time.monotonic() + timeout
            timed_out = False
            while True:
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                progressed = False
                if chan.recv_ready():
                    data = chan.recv(65536)
                    if len(out) < OUTPUT_CAP:
                        out += data[: OUTPUT_CAP - len(out)]
                    progressed = True
                if chan.recv_stderr_ready():
                    data = chan.recv_stderr(65536)
                    if len(err) < 65536:
                        err += data[: 65536 - len(err)]
                    progressed = True
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                if not progressed:
                    time.sleep(0.02)
            status = chan.recv_exit_status() if not timed_out else None
            stdout: Any = bytes(out) if binary else out.decode("utf-8", "replace")
            return status, stdout, err.decode("utf-8", "replace"), timed_out
        finally:
            chan.close()

    def close(self) -> None:
        try:
            self.transport.close()
        except Exception:
            pass


def open_session(ctx: JobContext, target: Target, config: dict, creds: dict) -> Session:
    port = int(config.get("port") or 22)
    user = str(config.get("login_user") or "zs-cbom")
    policy = config.get("host_key_policy") or "tofu"
    host_port = f"{target.ip}:{port}"
    if ctx.never_scan.blocks_ip(str(target.ip)):  # a never-scan target is skipped before anything else is judged
        raise TargetFail("skipped_never_scan", f"{target.ip} is on the never-scan list")
    if "password" in creds and "key" not in creds and policy != "pinned":
        # a first-seen host key proves nothing, so a password could go to an impostor (whole ranges make that
        # easy): passwords go only to hosts pinned in known_hosts.  Key logins never reveal the key.
        raise TargetFail("identity_unverified", "password logins need a pinned host key (known_hosts); the password "
                         "was not sent")
    try:
        sock = netutil.connect(target.ip, port, ctx.never_scan, 10)  # the network gate: never-scan at connect time
    except netutil.Blocked:
        raise TargetFail("skipped_never_scan", f"{target.ip} is on the never-scan list") from None
    except socket.timeout:
        raise TargetFail("timeout", f"no answer on port {port}") from None
    except ConnectionRefusedError:
        raise TargetFail("refused", f"port {port} refused") from None
    except OSError as exc:
        code = "no_route" if getattr(exc, "errno", None) in (101, 113) else "unreachable"
        raise TargetFail(code, exc.__class__.__name__) from None
    transport = paramiko.Transport(sock)
    transport.banner_timeout = 15
    transport.auth_timeout = 20
    pinned_types: list[str] = []
    if policy == "pinned":
        hk = _pinned_known_hosts(config.get("known_hosts") or "")
        names = [target.label, target.ip] if port == 22 else [f"[{target.label}]:{port}", f"[{target.ip}]:{port}"]
        entry = None
        for name in names:
            entry = hk.lookup(name)
            if entry:
                break
        if not entry:
            transport.close()
            raise TargetFail("host_key_changed", "this host is not in the pinned known_hosts")
        pinned_types = list(entry.keys())
    else:
        pins = load_pins(ctx.state_dir).get(host_port, {})
        pinned_types = list(pins.keys())
    if pinned_types:
        try:
            transport.get_security_options().key_types = tuple(a for a in _algs_for(pinned_types)
                                                               if a in transport._key_info)
        except Exception:
            pass
    try:
        transport.start_client(timeout=20)
    except paramiko.SSHException as exc:
        transport.close()
        if pinned_types and "key" in str(exc).lower():
            raise TargetFail("host_key_changed", "the server no longer offers the pinned host key type") from None
        raise TargetFail("error", f"SSH handshake failed ({exc.__class__.__name__})") from None
    except (EOFError, OSError) as exc:
        transport.close()
        raise TargetFail("error", f"SSH handshake failed ({exc.__class__.__name__})") from None
    key = transport.get_remote_server_key()
    ktype, fp = key.get_name(), _fp(key)
    host_key = {"key_type": ktype, "bits": key.get_bits(), "fingerprint": fp}
    if policy == "pinned":
        expected = entry.get(ktype) if entry else None
        if expected is None or expected.asbytes() != key.asbytes():
            transport.close()
            raise TargetFail("host_key_changed", f"host key {fp} does not match the pinned known_hosts")
    else:
        pins = load_pins(ctx.state_dir).get(host_port, {})
        if ktype in pins and pins[ktype] != fp:
            transport.close()
            raise TargetFail("host_key_changed", f"host key changed (pinned {pins[ktype]}, now {fp})")
        if ktype not in pins:
            save_pin(ctx.state_dir, host_port, ktype, fp)
            host_key["first_use"] = True
    # authenticate once
    try:
        if "key" in creds:
            more = transport.auth_publickey(user, creds["key"])
        else:
            pw = creds["password"]
            try:
                more = transport.auth_password(user, pw, fallback=False)
            except paramiko.BadAuthenticationType as bad:
                if "keyboard-interactive" not in (bad.allowed_types or []):
                    raise
                def handler(_title, _instructions, prompts):
                    if len(prompts) == 0:
                        return []
                    if len(prompts) == 1 and "password" in str(prompts[0][0]).lower():
                        return [pw]
                    raise _MFA()
                more = transport.auth_interactive(user, handler)
        if more:
            transport.close()
            raise TargetFail("mfa_required", "the server asks for a second factor after the credential")
    except _MFA:
        transport.close()
        raise TargetFail("mfa_required", "the server asks for a one-time code or several prompts") from None
    except paramiko.BadAuthenticationType as exc:
        transport.close()
        raise TargetFail("auth_failed", f"the server does not allow this credential type ({', '.join(exc.allowed_types or [])})") from None
    except paramiko.AuthenticationException:
        transport.close()
        raise TargetFail("auth_failed", f"login as {user} was refused") from None
    except (paramiko.SSHException, EOFError, OSError) as exc:
        transport.close()
        raise TargetFail("error", f"authentication failed ({exc.__class__.__name__})") from None
    if not transport.is_authenticated():
        transport.close()
        raise TargetFail("auth_failed", f"login as {user} was refused")
    return Session(transport, host_key)


# ----------------------------------------------------------------------------- tier 2
SUDO_PASSWORD = ("a password is required", "a terminal is required", "no tty present")
SUDO_NOT_ALLOWED = ("is not allowed to execute", "may not run sudo", "is not in the sudoers file",
                    "not allowed to run sudo", "is not allowed to run sudo")


def run_tier2(sess: Session, check: str, binary: bool = False, timeout: float = 120) -> tuple[str, Any, str]:
    """('ok'|'password'|'not_allowed'|'no_sudo'|'timeout'|'error', stdout, detail)"""
    last = ("not_allowed", b"" if binary else "", "")
    for argv in C.TIER2[check]:
        status, out, err, timed_out = sess.run(C.sudo_line(argv), timeout=timeout, binary=binary)
        low = err.lower()
        if timed_out:
            return "timeout", out, "command timed out"
        if any(s in low for s in SUDO_PASSWORD):
            # sudo asks for a password for any line that is not in the NOPASSWD allowlist (old or missing file)
            last = ("password", out, err.strip()[:200])
            continue
        if "sudo: command not found" in low or (status == 127 and "sudo" in low and not out):
            return "no_sudo", out, "sudo is not installed"
        if any(s in low for s in SUDO_NOT_ALLOWED):
            last = ("not_allowed", out, err.strip()[:200])
            continue
        if "command not found" in low and not out:
            last = ("not_allowed", out, err.strip()[:200])
            continue
        return "ok", out, err.strip()[:200]
    return last


# ----------------------------------------------------------------------------- collection per target
def _t1(sess: Session, command: str, timeout: float = CMD_TIMEOUT) -> tuple[int | None, str, str]:
    status, out, err, timed_out = sess.run(C.tier1_line(command), timeout=timeout)
    return (None if timed_out else status), out, err


def _file_cmd(template: str, path: str) -> str:
    return C.tier1_line(template.format(file=shlex.quote(path)))


def collect_target(ctx: JobContext, target: Target, config: dict, creds: dict) -> tuple[str, str | None, int]:
    tier = int(config.get("tier") or 1)
    t_deadline = time.monotonic() + min(float(config.get("timeout_s") or 300), max(ctx.time_left(), 1))
    sess = open_session(ctx, target, config, creds)
    loc = target.label
    emitted = 0

    def emit(*args, **kwargs):
        nonlocal emitted
        ctx.emit(*args, **kwargs)
        emitted += 1

    tier2: dict[str, tuple[str, Any, str]] = {}
    try:
        facts: dict[str, Any] = {"host_key": sess.host_key, "tier": tier}
        _, text, _ = _t1(sess, C.OS_RELEASE)
        facts["os"] = P.os_release(text)
        _, text, _ = _t1(sess, C.KERNEL)
        facts["kernel"] = text.strip()[:100]
        status, text, _ = _t1(sess, C.PACKAGES_DPKG, 120)
        if status != 0 or not text.strip():
            status, text, _ = _t1(sess, C.PACKAGES_RPM, 120)
        pkgs = P.packages(text) if status == 0 else []
        if status != 0:
            ctx.coverage(loc, "package list", "error", "neither dpkg-query nor rpm answered")
        status, text, _ = _t1(sess, C.CRYPTO_POLICY)
        facts["crypto_policy"] = text.strip()[:60] if status == 0 else None
        status, text, _ = _t1(sess, C.FIPS)
        facts["fips_enabled"] = text.strip() == "1" if status == 0 else None
        status, text, _ = _t1(sess, C.OPENSSL_VERSION)
        facts["openssl"] = P.openssl_version(text) if status == 0 else None
        for pkg in pkgs:
            emit("crypto_library", loc, f"package:{pkg['name']}", name=pkg["name"], facts={**pkg, "source": "package"})
        # SSH host keys
        for ktype in C.HOST_KEY_TYPES:
            path = f"/etc/ssh/ssh_host_{ktype}_key.pub"
            status, text, _ = _t1(sess, C.SSH_KEY_FINGERPRINT.format(file=path))
            for k in P.ssh_keygen_l(text) if status == 0 else []:
                emit("ssh_host_key", loc, path, name=f"{k['type']} host key", algorithm=k["type"], key_size=k["bits"],
                     facts=k)
        processes: dict[int, str] = {}
        status, text, _ = _t1(sess, C.PROCESSES)
        if status == 0:
            processes = P.ps_processes(text)
        # tier 2
        if tier >= 2:
            for check in ("listening_sockets", "process_crypto_libraries", "process_executables",
                          "sshd_effective_config", "disk_encryption", "block_devices"):
                if time.monotonic() > t_deadline:
                    break
                tier2[check] = run_tier2(sess, check)
                if tier2[check][0] == "no_sudo":
                    break
            if time.monotonic() < t_deadline and any(v[0] == "ok" for v in tier2.values()):
                tier2["key_and_certificate_files"] = run_tier2(sess, "key_and_certificate_files", binary=True, timeout=300)
            for check, (state, _out, detail) in tier2.items():
                if state != "ok":
                    ctx.coverage(loc, check, "denied" if state in ("password", "not_allowed", "no_sudo") else "error",
                                 detail or state)
        # sshd
        state, out, _ = tier2.get("sshd_effective_config", ("skip", "", ""))
        if state == "ok" and out.strip():
            emit("ssh_server_config", loc, "sshd -T", name="sshd effective configuration",
                 facts=P.sshd_config(out, effective=True))
        else:
            status, text, _ = _t1(sess, C.SSHD_CONFIG)
            if status == 0 and text.strip():
                emit("ssh_server_config", loc, "/etc/ssh/sshd_config", name="sshd configuration (file)",
                     facts=P.sshd_config(text, effective=False))
        # processes -> crypto libraries
        maps = P.proc_maps(tier2.get("process_crypto_libraries", ("", "", ""))[1] or "")
        exes = P.proc_exe(tier2.get("process_executables", ("", "", ""))[1] or "")
        listen = P.ss_listen(tier2.get("listening_sockets", ("", "", ""))[1] or "")
        ports_by_pid: dict[int, list[int]] = {}
        for sock_ in listen:
            for proc in sock_["processes"]:
                ports_by_pid.setdefault(proc["pid"], []).append(sock_["port"])
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for pid, libs in maps.items():
            exe = exes.get(pid) or ""
            for lib, deleted in libs.items():
                g = grouped.setdefault((exe, lib), {"exe": exe, "lib": lib, "pids": [], "deleted": False, "ports": [],
                                                    "process": processes.get(pid) or os.path.basename(exe)})
                g["pids"].append(pid)
                g["deleted"] = g["deleted"] or deleted
                g["ports"] = sorted(set(g["ports"]) | set(ports_by_pid.get(pid, [])))
        for (_exe, lib), g in list(grouped.items())[:1000]:
            g["pids"] = g["pids"][:20]
            emit("process_library", loc, lib, name=g["process"] or lib.rsplit("/", 1)[-1], facts=g)
        if listen:
            facts["listening"] = [{"port": s["port"], "address": s["address"],
                                   "process": (s["processes"][0]["name"] if s["processes"] else None)} for s in listen][:200]
        # disks
        state, out, _ = tier2.get("disk_encryption", ("skip", "", ""))
        crypt_rows = P.dmsetup_crypt(out) if state == "ok" else []
        luks: dict[str, int] = {}
        if crypt_rows:
            st, lout, _e = _t1(sess, C.LUKS_VERSIONS)
            luks = P.luks_versions(lout) if st == 0 else {}
        for row in crypt_rows:
            if row.get("device") in luks:
                row = {**row, "luks_version": luks[row["device"]]}
            emit("disk_encryption", loc, f"/dev/mapper/{row['name']}", name=row["name"], algorithm=row["cipher"],
                 key_size=row["effective_key_bits"], facts=row)
        state, out, _ = tier2.get("block_devices", ("skip", "", ""))
        if state == "ok":
            blocks = P.lsblk(out)
            facts["block_devices"] = blocks
            for b in blocks:
                if b["fstype"] == "crypto_LUKS":
                    emit("disk_encryption", loc, f"/dev/{b['name']}", name=b["name"], algorithm="LUKS",
                         facts={**b, "container": True})
        emit("os_crypto_policy", loc, "os", name=(facts.get("os") or {}).get("pretty_name") or "operating system",
             facts=facts)
        _service_and_config_crypto(sess, loc, emit)
        # files
        state, out, _ = tier2.get("key_and_certificate_files", ("skip", b"", ""))
        if tier < 2:
            ctx.coverage(loc, "key and certificate files", "not_supported",
                         "Tier 1 does not search for key and certificate files; use Tier 2")
        elif state == "ok":
            paths, truncated = P.find_print0(out if isinstance(out, bytes) else out.encode(), MAX_FILES)
            if truncated:
                ctx.coverage(loc, "key and certificate files", "truncated", f"only the first {MAX_FILES} files were read")
            trust: dict[str, list[str]] = {}
            for path in paths:
                if _is_trust_store(path) and P.classify_file(path) in ("pem", "cert"):
                    trust.setdefault(path.rsplit("/", 1)[0], []).append(path)
            for directory, files in trust.items():
                if len(files) > 1:  # e.g. /etc/pki/ca-trust/extracted/pem/directory-hash: one summary row
                    emitted += _trust_dir(ctx, sess, loc, directory, files, t_deadline)
                    paths = [p for p in paths if p not in set(files)]
            for path in paths:
                if time.monotonic() > t_deadline or ctx.should_stop():
                    ctx.coverage(loc, "key and certificate files", "truncated", "time limit reached while reading files")
                    break
                emitted += _inspect_file(ctx, sess, loc, path)
        states = [v[0] for v in tier2.values()]
        if tier >= 2 and states and all(s != "ok" for s in states):
            status = "sudo_denied" if all(s == "password" for s in states) else "sudoers_missing"
            raise TargetFail(status, f"Tier 2 commands were refused by sudo; {emitted} Tier 1 results were kept")
        return "ok", None, emitted
    finally:
        sess.close()


def _inspect_file(ctx: JobContext, sess: Session, loc: str, real_path: str) -> int:
    """Inspect one file.  ``real_path`` is used only shell-quoted; ``path`` (newline/tab made visible) is reported."""
    kind = P.classify_file(real_path)
    path = P.display_path(real_path)
    n = 0
    if kind in ("pem", "cert"):
        status, out, err, timed_out = sess.run(_file_cmd(C.CERTS_IN_FILE, real_path), FILE_CMD_TIMEOUT)
        certs = P.storeutl_certs(out) if status == 0 else []
        if len(certs) > 1 and _is_trust_store(path):
            # a system CA bundle: one summary row instead of 100+ certificate rows
            ctx.emit("certificate", loc, path, name=f"Trust store ({len(certs)} CA certificates)",
                     facts={"path": path, **_trust_summary(certs)})
            return 1
        for i, c in enumerate(certs[:200]):
            ctx.emit("certificate", loc, path if len(certs) == 1 else f"{path}#{i}", name=c.get("subject", ""),
                     algorithm=c.get("key_alg"), key_size=c.get("key_size"), facts={**c, "path": path, "index": i})
            n += 1
        if kind == "pem":
            status2, out2, _e, _t = sess.run(_file_cmd(C.HAS_PRIVATE_KEY, real_path), FILE_CMD_TIMEOUT)
            if status2 == 0 and out2.strip().isdigit() and int(out2.strip()) > 0:
                n += _private_key(ctx, sess, loc, real_path)
            elif not certs:
                readable = "Permission denied" not in err
                ctx.emit("certificate", loc, path, name=path.rsplit("/", 1)[-1],
                         facts={"path": path, "readable": readable, "parsed": False,
                                "detail": "no certificate found" if readable else "not readable at Tier 1"})
                n += 1
        elif not certs:
            ctx.emit("certificate", loc, path, name=path.rsplit("/", 1)[-1],
                     facts={"path": path, "readable": "Permission denied" not in err, "parsed": False,
                            "detail": (err.strip()[:160] or "no certificate found") if not timed_out else "timed out"})
            n += 1
    elif kind == "key":
        n += _private_key(ctx, sess, loc, real_path)
    elif kind == "ssh_private_key":
        status, out, err, _t = sess.run(_file_cmd(C.SSH_KEY_FINGERPRINT, real_path), FILE_CMD_TIMEOUT)
        keys = P.ssh_keygen_l(out) if status == 0 else []
        k = keys[0] if keys else {}
        ctx.emit("private_key", loc, path, name=path.rsplit("/", 1)[-1], algorithm=k.get("type"), key_size=k.get("bits"),
                 facts={"path": path, "format": "openssh", **k, "readable": bool(keys) or "Permission denied" not in err,
                        "parsed": bool(keys)})
        n += 1
    elif kind == "authorized_keys":
        status, out, err, _t = sess.run(_file_cmd(C.SSH_KEY_FINGERPRINT, real_path), FILE_CMD_TIMEOUT)
        keys = P.ssh_keygen_l(out) if status == 0 else []
        if not keys:
            ctx.emit("public_key", loc, path, name="authorized_keys",
                     facts={"path": path, "readable": "Permission denied" not in err, "parsed": False})
            n += 1
        for i, k in enumerate(keys[:200]):
            ctx.emit("public_key", loc, path if len(keys) == 1 else f"{path}#{i}", name=k.get("comment") or "authorized key",
                     algorithm=k["type"], key_size=k["bits"], facts={"path": path, **k, "authorized_key": True})
            n += 1
    elif kind == "keystore":
        status, out, err, timed_out = sess.run(_file_cmd(C.KEYSTORE_LIST, real_path), FILE_CMD_TIMEOUT)
        text = (out or "") + "\n" + (err or "")
        facts: dict[str, Any] = {"path": path}
        if status == 0:
            facts.update(P.keytool_list(out))
            facts["listed"] = True
            if facts.get("store_type") == "PKCS12" and not facts.get("entries"):
                facts.update({"password_protected": True,
                              "detail": "PKCS#12 entries are encrypted with the store password"})
        elif "command not found" in text or status == 127:
            facts.update({"listed": False, "reason": "keytool is not installed on this server"})
        elif "password" in text.lower() or "tampered" in text.lower():
            facts.update({"listed": False, "password_protected": True})
        elif "Permission denied" in text or "AccessDenied" in text:
            facts.update({"listed": False, "readable": False})
        else:
            facts.update({"listed": False, "reason": ("timed out" if timed_out else text.strip()[:160])})
        entries = facts.get("entry_list") or []
        first = entries[0] if entries else {}
        ctx.emit("keystore", loc, path, name=path.rsplit("/", 1)[-1], algorithm=first.get("key_alg"),
                 key_size=first.get("key_size"), facts=facts)
        n += 1
    return n


TRUST_DIRS = ("/etc/ssl/certs/", "/etc/pki/tls/certs/", "/etc/pki/ca-trust/", "/usr/local/share/ca-certificates/",
              "/usr/share/ca-certificates/", "/etc/ca-certificates/")
TRUST_NAMES = ("ca-certificates.crt", "ca-bundle.crt", "tls-ca-bundle.pem", "ca-bundle.trust.crt")


def _is_trust_store(path: str) -> bool:
    return path.startswith(TRUST_DIRS) or path.rsplit("/", 1)[-1] in TRUST_NAMES


def _trust_summary(certs: list[dict]) -> dict:
    return {"trust_store": True, "count": len(certs),
            "sha1_signed": sum(1 for c in certs if "sha1" in str(c.get("sig_alg", "")).lower()),
            "md5_signed": sum(1 for c in certs if "md5" in str(c.get("sig_alg", "")).lower()),
            "rsa_under_2048": sum(1 for c in certs if c.get("key_alg") == "RSA" and (c.get("key_size") or 0) < 2048),
            "expired": sum(1 for c in certs if (c.get("not_after") or "9") < _today())}


def _trust_dir(ctx: JobContext, sess: Session, loc: str, directory: str, files: list[str], deadline: float) -> int:
    certs: list[dict] = []
    read = 0
    for path in files:
        if time.monotonic() > deadline or ctx.should_stop():
            break
        status, out, _err, _t = sess.run(_file_cmd(C.CERTS_IN_FILE, path), FILE_CMD_TIMEOUT)
        if status == 0:
            certs.extend(P.storeutl_certs(out))
            read += 1
    ctx.emit("certificate", loc, P.display_path(directory), name=f"Trust store directory ({len(files)} files)",
             facts={"path": P.display_path(directory), "files": len(files), "files_read": read, **_trust_summary(certs)})
    return 1


def _today() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _private_key(ctx: JobContext, sess: Session, loc: str, real_path: str) -> int:
    status, out, err, timed_out = sess.run(_file_cmd(C.PUBLIC_HALF_OF_KEY, real_path), FILE_CMD_TIMEOUT)
    path = P.display_path(real_path)
    facts: dict[str, Any] = {"path": path}
    pub = public_key_facts_from_pem(out) if status == 0 else None
    low = err.lower()
    if pub:
        facts.update(pub)
        # read by the login user without sudo: anyone with that much access can copy the key
        facts.update({"encrypted": False, "readable": True})
        st, mode_out, _e, _t = sess.run(_file_cmd(C.FILE_MODE, real_path), FILE_CMD_TIMEOUT)
        mode = P.file_mode(mode_out) if st == 0 else None
        if mode is not None:
            facts.update({"mode": format(mode, "04o"), "world_readable": bool(mode & 0o004)})
    elif "permission denied" in low:
        facts.update({"readable": False})
    elif any(s in low for s in ("bad decrypt", "bad password", "maybe wrong password", "pass phrase", "unable to load key",
                                "could not read private key")):
        facts.update({"encrypted": True, "detail": "passphrase-protected or not a PEM/PKCS#8 key"})
    else:
        facts.update({"parsed": False, "detail": "timed out" if timed_out else err.strip()[:160]})
    ctx.emit("private_key", loc, path, name=path.rsplit("/", 1)[-1], algorithm=facts.get("key_alg"),
             key_size=facts.get("key_size"), facts=facts)
    return 1


def _service_and_config_crypto(sess: Session, loc: str, emit) -> None:
    """Tier 1 (no sudo): keys in running services' Environment=, per-service OpenSSL / Java crypto overrides, openssl
    enc command lines in cron jobs and local scripts, and nginx / Apache TLS directives.  Secret values never leave
    the parsers (only name, length and encoding); passphrases on command lines are only noted as present."""
    status, text, _ = _t1(sess, C.SERVICES, 60)
    services = P.systemd_services(text) if status == 0 else []
    modes: dict[str, int | None] = {}

    def mode_of(path: str | None) -> int | None:
        if not path:
            return None
        if path not in modes:
            st, out, _e, _t = sess.run(_file_cmd(C.FILE_MODE, path), FILE_CMD_TIMEOUT)
            modes[path] = P.file_mode(out) if st == 0 else None
        return modes[path]

    overrides: dict[str, dict[str, Any]] = {}
    for svc in services[:500]:
        frag = svc.get("fragment")
        for sec in svc["secrets"]:
            m = mode_of(frag)
            where = f"{frag or svc['unit']}:Environment={sec['name']}"
            emit("host_secret", loc, where, name=sec["name"], key_size=sec.get("key_bits"),
                 facts={**sec, "store": "systemd unit Environment=", "unit": svc["unit"], "file": frag,
                        "file_mode": format(m, "04o") if m is not None else None,
                        "world_readable": bool(m & 0o004) if m is not None else None,
                        "readable_by_any_user_via_systemctl": True})
        for kind, path in (("openssl_conf", svc.get("openssl_conf")), ("java_security", svc.get("java_security"))):
            if path:
                o = overrides.setdefault(path, {"kind": kind, "used_by": []})
                o["used_by"].append(svc["unit"])
                if kind == "java_security":
                    o["replaces_master_file"] = svc.get("java_override_replaces")
    for path, o in list(overrides.items())[:200]:
        st, out, err, _t = sess.run(_file_cmd(C.CRYPTO_DIRECTIVES, path), FILE_CMD_TIMEOUT)
        directives = P.crypto_directives(out) if st in (0, 1) else {}
        readable = st in (0, 1) and "permission denied" not in err.lower() and "no such file" not in err.lower()
        emit("crypto_config", loc, path, name=path.rsplit("/", 1)[-1],
             facts={**o, "path": path, "readable": readable, "directives": directives})
    status, text, _ = _t1(sess, C.OPENSSL_CLI_USES, 60)
    for use in (P.openssl_cli_uses(text) if status in (0, 1, 2) else [])[:200]:
        emit("crypto_config", loc, f"{use['file']}:{use['line']}", name=use["command"], algorithm=use.get("cipher"),
             facts={"kind": "openssl_cli", **use})
    status, text, _ = _t1(sess, C.WEB_TLS, 60)
    for path, cfg in list((P.web_tls(text) if status in (0, 1, 2) else {}).items())[:200]:
        emit("crypto_config", loc, path, name=path.rsplit("/", 1)[-1], facts={"kind": cfg["server"], "path": path, **cfg})


# ----------------------------------------------------------------------------- entry points
def _targets(ctx: JobContext, scope: dict) -> list[Target]:
    targets, skipped = expand_targets(scope.get("targets") or [], ctx.never_scan)
    for label in skipped:
        ctx.outcome(label, "skipped_never_scan")
    return targets


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    creds = _credentials(ctx, config, secrets)
    targets = _targets(ctx, scope)
    parallel = max(1, min(int(config.get("parallel") or 8), 64))

    def one(target: Target):
        started = time.monotonic()
        stop = ctx.should_stop()
        if stop:
            ctx.outcome(target.label, stop, started=started)
            return
        if target.ip is None:
            ctx.outcome(target.label, "unreachable", target.error, started=started)
            return
        try:
            status, err, n = collect_target(ctx, target, config, creds)
            ctx.outcome(target.label, status, err, started=started, assets=n)
            ctx.log("target done", target=target.label, status=status, assets=n)
        except TargetFail as fail:
            ctx.outcome(target.label, fail.status, fail.error, started=started)
            ctx.log("target failed", target=target.label, status=fail.status)
        except Exception as exc:  # never let one host kill the job
            ctx.outcome(target.label, "error", exc.__class__.__name__, started=started)
            ctx.log("target error", target=target.label, error=exc.__class__.__name__)

    with cf.ThreadPoolExecutor(max_workers=parallel) as pool:
        list(pool.map(one, targets))
    return None  # default summary from counts


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    try:
        creds = _credentials(ctx, config, secrets)
    except ConfigError as exc:
        for line in scope.get("targets") or []:
            ctx.samples.append({"target": line, "status": "error", "reachable": None, "login": False,
                                "privilege": None, "note": str(exc)})
        return str(exc)
    tier = int(config.get("tier") or 1)
    for target in _targets(ctx, scope)[:5]:
        sample = {"target": target.label, "status": "ready", "reachable": False, "login": False,
                  "privilege": None if tier < 2 else False, "note": ""}
        if target.ip is None:
            sample.update(status="unreachable", note=target.error or "could not resolve")
            ctx.samples.append(sample)
            continue
        try:
            sess = open_session(ctx, target, config, creds)
        except TargetFail as fail:
            sample["reachable"] = fail.status not in ("unreachable", "refused", "timeout", "no_route")
            sample.update(status=fail.status, note=fail.error)
            ctx.samples.append(sample)
            continue
        sample.update(reachable=True, login=True)
        try:
            if tier >= 2:
                state, _out, detail = run_tier2(sess, "listening_sockets")
                if state == "ok":
                    sample["privilege"] = True
                else:
                    sample["status"] = "sudo_denied" if state == "password" else "sudoers_missing"
                    sample["note"] = ("sudo asks for a password: install the zs-cbom sudoers file with NOPASSWD"
                                      if state == "password" else
                                      "the zs-cbom sudoers file is missing or does not match; this server runs at Tier 1")
            first = " (host key pinned on first use)" if sess.host_key.get("first_use") else ""
            if sample["status"] == "ready":
                sample["note"] = f"{sess.host_key['key_type']} {sess.host_key['fingerprint']}{first}"
        finally:
            sess.close()
        ctx.samples.append(sample)
    ready = sum(1 for s in ctx.samples if s["status"] == "ready")
    return f"{ready} of {len(ctx.samples)} samples ready"
