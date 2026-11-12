"""zs-collect: the read-only Linux collector that a customer's own tools run on each host (AWX/AAP, Salt, AWS SSM).

    zs-collect --nonce <run nonce> [--tier 1|2] [--label <inventory address>] [--run-as zs-cbom]
               [--tmp-dir DIR] [--timeout-s 300] [--output json|chunks] [--chunk-bytes N]

It runs exactly the scan node's Linux collector (``linux_ssh.collect_on_session``) through ``LocalSession``, which
has the same ``run()`` contract as the SSH ``Session``, so the assets are the ones the SSH path produces on the same
host.  It prints one zs-collect/1 document on stdout (the ``python -m zs_scan_node.collect`` document plus an
envelope), or with ``--output chunks`` that document gzipped, base64'd and cut into lines of at most ``--chunk-bytes``
(AWX keeps each job event under 512 KB).

Read-only guarantees (each has a test in tests/test_zs_collect.py):
* Only command lines built from ``zs_scan_node.commands`` run, through ``/bin/sh -c``; ``allowed_line`` checks every
  line before it runs (exact Tier 1 lines, exact Tier 2 sudo lines, per-file lines with one quoted absolute path).
* No listener and no outbound connection: nothing here opens a socket.
* No writes outside the temp dir: the working directory, ``HOME`` and ``TMPDIR`` of every command are the temp dir;
  a temp dir zs-collect makes itself (``mkdtemp``, 0700) is removed at exit.  zs-collect never changes the mode or
  owner of a directory that was not made for it: a given ``--tmp-dir`` must already be private and named
  ``zs-collect.*`` (as the transports' wrapper makes it with ``mktemp -d``), so a mistaken ``--tmp-dir /tmp`` or
  ``/root`` is refused instead of being handed to the run-as user.
* Started as root, it drops to ``--run-as`` (default ``zs-cbom``, with that user's groups, like an SSH login) before
  anything runs, so the zs-cbom sudoers file decides Tier 2 exactly as on the SSH path.  It never collects as root.
* Private keys never leave the host (only ``openssl pkey -pubout`` and fingerprints), and every asset passes the
  same ``Scrubber`` as on the node.

Exit status: 0 success, 1 the collection failed (the document says why), 2 refused (bad arguments, run-as user).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import pwd
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from zs_scan_node import VERSION
from zs_scan_node import commands as C
# the document format, its validation and the chunked output live in transports/zsdoc.py (stdlib only), which the
# backend carries a byte-identical copy of; they are re-exported here for the CLI and older imports
from zs_scan_node.transports.zsdoc import (  # noqa: F401
    CHUNK_PREFIX, DEFAULT_CHUNK_BYTES, FORMAT, MAX_ASSETS, MAX_CHUNK_BYTES, NONCE_RE, STATUSES, ChunkError,
    encode_chunks, reassemble, validate_document)

TMP_DIR_NAME_RE = re.compile(r"zs-collect\.[A-Za-z0-9_.-]+")  # mktemp -d .../zs-collect.XXXXXXXX (the wrapper)
OUTPUT_CAP = 4 * 1024 * 1024  # the same caps as the SSH Session (linux_ssh.OUTPUT_CAP, 64 KB of stderr)
STDERR_CAP = 65536
CMD_TIMEOUT = 60
SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class NotAllowed(Exception):
    """A command line that is not on the allow-list.  It is never executed."""


class Refused(Exception):
    """zs-collect will not run as asked (bad arguments, run-as user missing or root)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


# ----------------------------------------------------------------------------- allow-list
_T1_FIXED = (C.OS_RELEASE, C.KERNEL, C.PACKAGES_DPKG, C.PACKAGES_RPM, C.CRYPTO_POLICY, C.FIPS, C.OPENSSL_VERSION,
             C.SSHD_CONFIG, C.PROCESSES, C.LUKS_VERSIONS, C.SERVICES, C.OPENSSL_CLI_USES, C.WEB_TLS)
_T1_PER_FILE = (C.CERTS_IN_FILE, C.PUBLIC_HALF_OF_KEY, C.HAS_PRIVATE_KEY, C.SSH_KEY_FINGERPRINT, C.KEYSTORE_LIST,
                C.FILE_MODE, C.CRYPTO_DIRECTIVES)
_ALLOWED_EXACT = frozenset([C.tier1_line(c) for c in _T1_FIXED]
                           + [C.sudo_line(argv) for variants in C.TIER2.values() for argv in variants])
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _one_quoted_path(text: str) -> bool:
    """``text`` is exactly ``shlex.quote(p)`` for one absolute path ``p`` without control characters."""
    try:
        parts = shlex.split(text)
    except ValueError:
        return False
    if len(parts) != 1:
        return False
    path = parts[0]
    return path.startswith("/") and not _CONTROL.search(path) and shlex.quote(path) == text


def allowed_line(line: str) -> bool:
    if not isinstance(line, str) or "\n" in line or "\x00" in line:
        return False
    if line in _ALLOWED_EXACT:
        return True
    head, tail = C.T1_ENV + " ", " </dev/null"
    if not (line.startswith(head) and line.endswith(tail)):
        return False
    body = line[len(head):-len(tail)]
    for template in _T1_PER_FILE:
        before, after = template.split("{file}")
        if body.startswith(before) and body.endswith(after) and len(body) > len(before) + len(after):
            if _one_quoted_path(body[len(before):len(body) - len(after)]):
                return True
    return False


# ----------------------------------------------------------------------------- the local session
def _drain(stream, sink: bytearray, cap: int) -> None:
    """Read a pipe to its end, keeping at most ``cap`` bytes (the rest is read and dropped, as over SSH)."""
    try:
        while True:
            data = stream.read(65536)
            if not data:
                break
            if len(sink) < cap:
                sink += data[: cap - len(sink)]
    except (OSError, ValueError):
        pass


class LocalSession:
    """Runs the collector's command lines on this host with the SSH ``Session.run`` contract.

    ``run(command, timeout, binary) -> (exit status | None, stdout, stderr, timed_out)``.  Every line is checked by
    ``allowed_line`` first; commands run through ``/bin/sh -c`` (as sshd runs them through the login shell) with stdin
    closed, a fixed environment, the temp dir as working directory, and their own process group, which is killed on
    timeout."""

    def __init__(self, tmp_dir: str, user: str) -> None:
        self.tmp_dir = tmp_dir
        self.user = user
        self.env = {"PATH": SAFE_PATH, "LC_ALL": "C", "HOME": tmp_dir, "TMPDIR": tmp_dir, "USER": user,
                    "LOGNAME": user, "SHELL": "/bin/sh"}
        # this process, the PyInstaller bootloader that started it and the tool's own processes that launched it map
        # libcrypto: never report them (see transient_ancestors)
        self.exclude_pids = {os.getpid()} | set(transient_ancestors())
        if getattr(sys, "frozen", False):
            self.exclude_pids.add(os.getppid())
        self.lines: list[str] = []
        self.host_key = self._own_host_key()

    def run(self, command: str, timeout: float = CMD_TIMEOUT, binary: bool = False) -> tuple[int | None, Any, str, bool]:
        if not allowed_line(command):
            raise NotAllowed(f"not on the zs-collect allow-list: {command[:120]!r}")
        self.lines.append(command)
        proc = subprocess.Popen(["/bin/sh", "-c", command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=dict(self.env), cwd=self.tmp_dir, close_fds=True,
                                start_new_session=True)
        out, err = bytearray(), bytearray()
        readers = [threading.Thread(target=_drain, args=(proc.stdout, out, OUTPUT_CAP), daemon=True),
                   threading.Thread(target=_drain, args=(proc.stderr, err, STDERR_CAP), daemon=True)]
        for t in readers:
            t.start()
        timed_out = False
        try:
            status: int | None = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out, status = True, None
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        for t in readers:
            t.join(timeout=5)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except Exception:
                pass
        if status is not None and status < 0:
            status = -1  # killed by a signal: paramiko's recv_exit_status() says -1 for the same thing
        stdout: Any = bytes(out) if binary else out.decode("utf-8", "replace")
        return status, stdout, err.decode("utf-8", "replace"), timed_out

    def _own_host_key(self) -> dict[str, Any]:
        """The host key an SSH handshake with this host would show: paramiko prefers ed25519, then ECDSA, then RSA."""
        from zs_scan_node import linux_parsers as P

        names = {"ED25519": "ssh-ed25519", "RSA": "ssh-rsa"}
        for ktype in ("ed25519", "ecdsa", "rsa"):
            path = f"/etc/ssh/ssh_host_{ktype}_key.pub"
            status, text, _err, _t = self.run(C.tier1_line(C.SSH_KEY_FINGERPRINT.format(file=path)))
            keys = P.ssh_keygen_l(text) if status == 0 else []
            if keys:
                k = keys[0]
                name = names.get(k["type"]) or (f"ecdsa-sha2-nistp{k['bits']}" if k["type"] == "ECDSA" else k["type"])
                return {"key_type": name, "bits": k["bits"], "fingerprint": k["fingerprint"]}
        return {"key_type": None, "bits": None, "fingerprint": None, "local": True}

    def close(self) -> None:
        pass


RUN_WINDOW_S = 120  # how long before zs-collect a transport's own process for this run may have started


def _stat(pid: int, proc: str = "/proc") -> tuple[int, int] | None:
    """(parent pid, start time in clock ticks since boot) from ``/proc/<pid>/stat`` (fields 4 and 22)."""
    try:
        with open(f"{proc}/{pid}/stat", encoding="ascii", errors="replace") as f:
            text = f.read()
        fields = text[text.rindex(")") + 2:].split()  # after "pid (comm) ": state is field 3
        return int(fields[1]), int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def transient_ancestors(pid: int | None = None, proc: str = "/proc", limit: int = 64,
                        window_s: float = RUN_WINDOW_S) -> list[int]:
    """The processes that launched zs-collect for this run: its ancestors (from its parent, or from ``pid``) that
    started at most ``window_s`` before zs-collect itself (or before ``pid``).  They are the transport's own short-lived processes (the SSH
    session Ansible or salt-ssh opened, salt-call, a salt-minion job, sudo, the launcher's shell), which the SSH path
    never sees on the host.  A parent never starts after its child, so the walk stops at the first older ancestor: a
    service (sshd, the salt-minion and its long-lived workers, the SSM agent), wherever it sits in the tree, and
    everything above it, is kept.  PID 1 is never excluded, and an ancestor whose start time cannot be read ends the
    walk (it is kept).  The window is a bound, not a proof: a service (re)started less than ``window_s`` before the
    run that is itself an ancestor (a salt-minion restarted just before its job) is treated as part of the run, and a
    transport slower than the window to start zs-collect leaves its oldest process in."""
    out: list[int] = []
    anchor = _stat(os.getpid() if pid is None else pid, proc)
    if anchor is None:
        return out
    since = anchor[1] - window_s * (os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100)
    current = os.getppid() if pid is None else pid
    for _ in range(limit):
        if current is None or current <= 1:
            break
        info = _stat(current, proc)
        if info is None or info[1] < since:
            break
        out.append(current)
        current = info[0]
    return out


# ----------------------------------------------------------------------------- privileges
def _preload() -> None:
    """Import everything the collection needs while the files are still readable (a PyInstaller binary unpacks its
    modules into the temp dir; nothing is imported lazily after the privilege drop)."""
    import base64 as _b  # noqa: F401  (linux_ssh imports these inside functions)
    import concurrent.futures  # noqa: F401
    import encodings.idna  # noqa: F401
    import hashlib as _h  # noqa: F401

    from cryptography import x509  # noqa: F401
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: F401

    from zs_scan_node import certparse, jobctx, linux_parsers, log, netutil, scrub  # noqa: F401
    from zs_scan_node.collectors import linux_ssh  # noqa: F401


def drop_privileges(user: str, tmp_dir: str) -> str | None:
    """Root: become ``user`` with its own groups (as an SSH login would).  Not root: nothing to drop (None)."""
    if os.geteuid() != 0:
        return None
    if not user:
        raise Refused("run_as", "zs-collect does not collect as root: name the run-as user (--run-as)")
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        raise Refused("run_as", f"the run-as user {user} does not exist on this host (create it as for the SSH "
                                "path: useradd --system zs-cbom)") from None
    if pw.pw_uid == 0:
        raise Refused("run_as", f"the run-as user {user} is root; zs-collect does not collect as root")
    _preload()
    for base, dirs, files in os.walk(tmp_dir):  # our temp dir (and the PyInstaller files in it) become the user's
        for path in [base] + [os.path.join(base, name) for name in dirs + files]:
            os.chown(path, pw.pw_uid, pw.pw_gid, follow_symlinks=False)
    os.initgroups(pw.pw_name, pw.pw_gid)
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    if os.geteuid() == 0 or os.getuid() == 0:
        raise Refused("run_as", "the privilege drop did not take effect")
    try:
        os.setuid(0)
    except (PermissionError, OSError):
        pass
    else:
        raise Refused("run_as", "root could be regained after the privilege drop")
    return pw.pw_name


def _current_user() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        return str(os.geteuid())


# ----------------------------------------------------------------------------- the document
def _iso(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_facts(assets: list[dict]) -> dict[str, Any]:
    os_id = None
    for a in assets:
        if a.get("type") == "os_crypto_policy":
            os_id = ((a.get("facts") or {}).get("os") or {}).get("id")
            break
    machine = None
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, encoding="ascii", errors="replace") as f:
                value = f.read().strip()
            if value:
                machine = hashlib.sha256(value.encode()).hexdigest()
                break
        except OSError:
            continue
    return {"hostname": socket.gethostname()[:255], "os_id": os_id, "machine_id_sha256": machine}


def _envelope(nonce: str, label: str, tier: int, started: float) -> dict[str, Any]:
    return {"format": FORMAT, "collector_version": VERSION, "run_nonce": nonce, "target_label": label, "tier": tier,
            "host": {"hostname": socket.gethostname()[:255], "os_id": None, "machine_id_sha256": None},
            "started_at": _iso(started), "finished_at": _iso(started)}


def collect_local(label: str, tier: int, nonce: str, tmp_dir: str, timeout_s: int = 300,
                  user: str | None = None) -> dict[str, Any]:
    """Collect this host and return the zs-collect/1 document (never raises for a collection problem)."""
    from zs_scan_node.collectors import linux_ssh
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    started = time.time()
    t0 = time.monotonic()
    ctx = JobContext(job_id=0, attempt=1, run_id=None, kind="collect", source_kind="linux_servers",
                     scrubber=Scrubber([]), never_scan=NeverScan([]), deadline=time.monotonic() + timeout_s + 60,
                     state_dir=tmp_dir)
    status, error = "success", None
    n_started = time.monotonic()
    try:
        sess = LocalSession(tmp_dir, user or _current_user())
        st, err, n = linux_ssh.collect_on_session(ctx, sess, label, {"tier": tier, "timeout_s": timeout_s},
                                                  time.monotonic() + timeout_s)
        ctx.outcome(label, st, err, started=n_started, assets=n)
    except linux_ssh.TargetFail as fail:
        ctx.outcome(label, fail.status, fail.error, started=n_started)
    except NotAllowed as exc:
        status, error = "failure", f"zs-collect refused a command that is not on its allow-list ({exc})"
        ctx.outcome(label, "error", error, started=n_started)
    except Exception as exc:  # the document still goes out, with the reason
        status, error = "failure", f"zs-collect failed ({exc.__class__.__name__}: {str(exc)[:200]})"
        ctx.outcome(label, "error", error, started=n_started)
    ctx.flush()
    counted = [o for o in ctx.outcomes if o.counted]
    if status == "success" and counted and not any(o.status == "ok" for o in counted):
        first = counted[0]
        status, error = "failure", f"Nothing collected: {first.target}: {first.status}" + (
            f" ({first.error})" if first.error else "")
    assets = ctx.collected[:MAX_ASSETS]
    if len(ctx.collected) > MAX_ASSETS:
        ctx.truncated = True
    doc = _envelope(nonce, label, tier, started)
    doc["host"] = _host_facts(assets)
    doc.update({"status": status, "error": ctx.scrubber.text(error) if error else None, "result": ctx.result(None),
                "assets": assets, "elapsed_s": round(time.monotonic() - t0, 2), "finished_at": _iso(time.time())})
    return doc


def refusal_document(nonce: str, label: str, tier: int, code: str, detail: str) -> dict[str, Any]:
    doc = _envelope(nonce, label, tier, time.time())
    doc.update({"status": "failure", "error": detail[:500], "refusal": code,
                "result": {"summary": detail[:500], "counts": {"total": 1, "ok": 0, "failed": 1, "skipped": 0},
                           "asset_count": 0, "targets": [{"target": label, "status": "refused", "error": detail[:256],
                                                          "duration_ms": 0, "assets": 0, "counted": True}],
                           "truncated": False, "assets_lost": 0, "duration_s": 0},
                "assets": [], "elapsed_s": 0})
    return doc


# ----------------------------------------------------------------------------- CLI
def tmp_dir_problem(path: str) -> str | None:
    """Why ``path`` cannot be zs-collect's working directory, or None when it can.

    Started as root, zs-collect hands its working directory (with the PyInstaller files unpacked in it) to the run-as
    user, and it never changes a directory's mode.  So a given directory must be one made for this run: named
    ``zs-collect.*``, a real directory (not a symbolic link), owned by the user running zs-collect, with no group or
    other access, which is what ``mktemp -d "${TMPDIR:-/tmp}/zs-collect.XXXXXXXX"`` in the wrapper produces."""
    if not TMP_DIR_NAME_RE.fullmatch(os.path.basename(path)):
        return "--tmp-dir must be a directory made for this run, named zs-collect.* (mktemp -d /tmp/zs-collect.XXXXXXXX)"
    try:
        st = os.lstat(path)
    except OSError:
        return "--tmp-dir does not exist"
    if not stat.S_ISDIR(st.st_mode):
        return "--tmp-dir is not a directory (a symbolic link is refused)"
    if st.st_uid != os.geteuid() or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        return "--tmp-dir must be private: owned by the user running zs-collect, mode 0700"
    return None


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="zs-collect", description="ZeroShield read-only CBOM collector for this host")
    p.add_argument("--nonce", required=True, help="the run nonce from ZeroShield; echoed in the output")
    p.add_argument("--tier", type=int, choices=(1, 2), default=1)
    p.add_argument("--label", default=None, help="the inventory address this host is known by (default: hostname)")
    p.add_argument("--run-as", default="zs-cbom", help="when started as root, collect as this user (default zs-cbom)")
    p.add_argument("--tmp-dir", default=None,
                   help="private working directory made for this run: zs-collect.*, mode 0700, owned by the caller "
                        "(default: a new mktemp -d, removed at exit)")
    p.add_argument("--timeout-s", type=int, default=300)
    p.add_argument("--output", choices=("json", "chunks"), default="json")
    p.add_argument("--chunk-bytes", type=int, default=DEFAULT_CHUNK_BYTES)
    p.add_argument("--version", action="version", version=f"zs-collect {VERSION} ({FORMAT})")
    return p


def _write(doc: dict, args: argparse.Namespace) -> None:
    if args.output == "chunks":
        sys.stdout.write("\n".join(encode_chunks(doc, args.nonce, args.chunk_bytes)) + "\n")
    else:
        sys.stdout.write(json.dumps(doc, default=str) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    if not NONCE_RE.match(args.nonce or ""):
        sys.stderr.write("zs-collect: --nonce must be 16-128 characters of A-Z a-z 0-9 _ -\n")
        return 2
    if not 10 <= args.timeout_s <= 3600 or not 1024 <= args.chunk_bytes <= MAX_CHUNK_BYTES:
        sys.stderr.write("zs-collect: --timeout-s must be 10..3600 and --chunk-bytes 1024..524288\n")
        return 2
    label = (args.label or socket.gethostname())[:255]
    own_tmp = args.tmp_dir is None
    if not own_tmp:
        problem = tmp_dir_problem(os.path.abspath(args.tmp_dir))
        if problem:
            sys.stderr.write(f"zs-collect: {problem}\n")
            return 2
    tmp_dir = tempfile.mkdtemp(prefix="zs-collect.") if own_tmp else os.path.abspath(args.tmp_dir)
    try:
        try:
            user = drop_privileges(args.run_as, tmp_dir)
        except Refused as exc:
            sys.stderr.write(f"zs-collect: {exc}\n")
            _write(refusal_document(args.nonce, label, args.tier, exc.code, str(exc)), args)
            return 2
        os.chdir(tmp_dir)
        doc = collect_local(label=label, tier=args.tier, nonce=args.nonce, tmp_dir=tmp_dir, timeout_s=args.timeout_s,
                            user=user)
        _write(doc, args)
        return 0 if doc["status"] == "success" else 1
    finally:
        if own_tmp:
            os.chdir("/")
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
