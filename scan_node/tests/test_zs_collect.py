"""zs-collect: the read-only collector the customer's own tools (AWX, Salt, SSM) run on each host.

Each read-only guarantee of CONTRACT section 4 has a test here:
* only command strings from ``zs_scan_node.commands`` are executed (allow-list, checked on every argv);
* no network: the output is identical inside an empty network namespace, and strace sees no AF_INET/AF_INET6 socket;
* no writes outside the temp dir (strace of every write-like syscall);
* private keys never leave the host (only ``pkey -pubout``; the Scrubber removes any PEM private key);
* the output is the scan node's inventory format, with the zs-collect/1 envelope and the job's nonce echoed;
* the same command outputs give the same assets as the SSH path (``collect_on_session`` is shared).
"""
from __future__ import annotations

import base64
import copy
import io
import json
import os
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from zs_scan_node import VERSION
from zs_scan_node import commands as C
from zs_scan_node import zscollect as Z
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

NODE_DIR = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
NONCE = "run-7f3a9c1e5b2d4a60"
ED_FP = "SHA256:Cq8oZp0aXj2c3m3uVv0N1o3m8dQ0x0fS3rQnqC2b5yI"
RSA_FP = "SHA256:7w1Qn3fA9h2mQe0pV5ZsX8yJ4kL6rT1uB3cD5eF7gHi"


def _pub_pem() -> str:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _private_pem() -> str:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def canned_host() -> dict[str, tuple[int, bytes, bytes]]:
    """Exact command line -> (exit status, stdout, stderr): one Debian host with a server key and certificate."""
    t1 = C.tier1_line
    bundle = (FIXTURES / "storeutl_bundle.txt").read_bytes()
    out: dict[str, tuple[int, bytes, bytes]] = {
        t1(C.OS_RELEASE): (0, b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\n'
                              b'VERSION_ID="12"\nID=debian\n', b""),
        t1(C.KERNEL): (0, b"6.1.0-26-amd64\n", b""),
        t1(C.PACKAGES_DPKG): (0, b"openssl\t3.0.15-1~deb12u1\nlibssl3\t3.0.15-1~deb12u1\nopenssh-server\t1:9.2p1-2\n", b""),
        t1(C.CRYPTO_POLICY): (1, b"", b"cat: /etc/crypto-policies/config: No such file or directory\n"),
        t1(C.FIPS): (0, b"0\n", b""),
        t1(C.OPENSSL_VERSION): (0, b'OpenSSL 3.0.15 3 Sep 2024 (Library: OpenSSL 3.0.15 3 Sep 2024)\n'
                                   b'OPENSSLDIR: "/usr/lib/ssl"\n', b""),
        t1(C.SSH_KEY_FINGERPRINT.format(file="/etc/ssh/ssh_host_ed25519_key.pub")):
            (0, f"256 {ED_FP} root@web-1 (ED25519)\n".encode(), b""),
        t1(C.SSH_KEY_FINGERPRINT.format(file="/etc/ssh/ssh_host_rsa_key.pub")):
            (0, f"3072 {RSA_FP} root@web-1 (RSA)\n".encode(), b""),
        t1(C.PROCESSES): (0, b"    1 sshd\n   77 nginx\n", b""),
        C.sudo_line(C.TIER2["listening_sockets"][0]):
            (0, b'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
                b'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=77,fd=6))\n', b""),
        C.sudo_line(C.TIER2["process_crypto_libraries"][0]):
            (0, b"/proc/1/maps:7f2a1c000000-7f2a1c200000 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libcrypto.so.3\n"
                b"/proc/77/maps:7f2a1d000000-7f2a1d100000 r-xp 00000000 08:01 1240 /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
                b"/proc/4242/maps:7f2a1e000000-7f2a1e100000 r-xp 00000000 08:01 1250 /tmp/zs.x/_MEI1/libcrypto.so.3\n",
                b""),
        C.sudo_line(C.TIER2["process_executables"][0]):
            (0, b"/proc/1\t/usr/sbin/sshd\n/proc/77\t/usr/sbin/nginx\n/proc/4242\t/tmp/zs.x/zs-collect\n", b""),
        C.sudo_line(C.TIER2["sshd_effective_config"][0]):
            (0, b"port 22\nciphers aes128-ctr,chacha20-poly1305@openssh.com\nmacs hmac-sha2-256\n"
                b"kexalgorithms curve25519-sha256\nhostkey /etc/ssh/ssh_host_ed25519_key\n", b""),
        C.sudo_line(C.TIER2["disk_encryption"][0]): (0, b"No devices found\n", b""),
        C.sudo_line(C.TIER2["block_devices"][0]): (0, b"NAME TYPE FSTYPE MOUNTPOINT\nsda disk  \nsda1 part ext4 /\n", b""),
        C.sudo_line(C.TIER2["key_and_certificate_files"][0]):
            (0, b"/etc/ssl/private/server.key\0/srv/app/server.pem\0/home/deploy/.ssh/authorized_keys\0", b""),
        t1(C.CERTS_IN_FILE.format(file="/srv/app/server.pem")): (0, bundle, b""),
        t1(C.HAS_PRIVATE_KEY.format(file="/srv/app/server.pem")): (1, b"0\n", b""),
        t1(C.PUBLIC_HALF_OF_KEY.format(file="/etc/ssl/private/server.key")): (0, _pub_pem().encode(), b""),
        t1(C.FILE_MODE.format(file="/etc/ssl/private/server.key")): (0, b"644\n", b""),
        t1(C.SSH_KEY_FINGERPRINT.format(file="/home/deploy/.ssh/authorized_keys")):
            (0, f"256 {ED_FP} deploy@laptop (ED25519)\n".encode(), b""),
        t1(C.SERVICES): (1, b"", b"System has not been booted with systemd\n"),
        t1(C.OPENSSL_CLI_USES): (1, b"", b""),
        t1(C.WEB_TLS): (0, b"/etc/nginx/sites-enabled/default:12:    ssl_protocols TLSv1 TLSv1.2;\n", b""),
    }
    return out


class FakeProc:
    """A finished child process: what ``subprocess.Popen`` returns, with canned output."""

    def __init__(self, status: int, out: bytes, err: bytes) -> None:
        self.pid = 999_999
        self.stdout, self.stderr = io.BytesIO(out), io.BytesIO(err)
        self.returncode = status

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        pass


class Recorder:
    def __init__(self, host: dict[str, tuple[int, bytes, bytes]]) -> None:
        self.host, self.calls = host, []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        line = argv[-1]
        status, out, err = self.host.get(line, (127, b"", b"sh: 1: not found\n"))
        return FakeProc(status, out, err)


class FakeSsh:
    """The SSH path's session over the same host: ``Session.run`` semantics, the server's ed25519 host key."""

    host_key = {"key_type": "ssh-ed25519", "bits": 256, "fingerprint": ED_FP}

    def __init__(self, host):
        self.host, self.lines = host, []

    def run(self, command, timeout=None, binary=False):
        self.lines.append(command)
        status, out, err = self.host.get(command, (127, b"", b"sh: 1: not found\n"))
        return status, (out if binary else out.decode("utf-8", "replace")), err.decode("utf-8", "replace"), False

    def close(self):
        pass


def _ctx() -> JobContext:
    return JobContext(job_id=0, attempt=1, run_id=None, kind="collect", source_kind="linux_servers",
                      scrubber=Scrubber([]), never_scan=NeverScan([]), deadline=time.monotonic() + 600)


@pytest.fixture()
def fake_popen(monkeypatch):
    rec = Recorder(canned_host())
    monkeypatch.setattr(Z.subprocess, "Popen", rec)
    for name in ("system", "popen", "execv", "execve", "execvp", "spawnv", "posix_spawn"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, lambda *a, **k: pytest.fail(f"os.{name} must never be used"))
    monkeypatch.setattr(os, "killpg", lambda *a: None)
    return rec


def _run_local(tmp_path, tier=2, label="10.0.0.5", **kw):
    return Z.collect_local(label=label, tier=tier, nonce=NONCE, tmp_dir=str(tmp_path), timeout_s=300, **kw)


# ----------------------------------------------------------------------------- allow-list
def test_every_command_is_on_the_allow_list(fake_popen, tmp_path):
    doc = _run_local(tmp_path)
    assert doc["status"] == "success", doc["error"]
    assert fake_popen.calls, "nothing was executed"
    per_file = 0
    for argv, kwargs in fake_popen.calls:
        assert argv[:2] == ["/bin/sh", "-c"] and len(argv) == 3
        assert Z.allowed_line(argv[2]), argv[2]
        assert kwargs.get("stdin") == subprocess.DEVNULL
        assert kwargs.get("start_new_session") is True and kwargs.get("close_fds", True) is True
        assert kwargs["env"]["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin" and kwargs["env"]["LC_ALL"] == "C"
        assert set(kwargs["env"]) <= {"PATH", "LC_ALL", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL"}
        per_file += any(argv[2].startswith(C.T1_ENV + " " + t.split("{file}")[0])
                        for t in (C.CERTS_IN_FILE, C.PUBLIC_HALF_OF_KEY, C.FILE_MODE))
    assert per_file >= 3  # the file commands were exercised too, with their quoted paths


@pytest.mark.parametrize("line", [
    "rm -rf /",
    C.T1_ENV + " cat /etc/shadow </dev/null",
    C.tier1_line(C.OS_RELEASE) + "; id",
    C.tier1_line(C.CERTS_IN_FILE.format(file="relative/path.pem")),
    C.tier1_line(C.CERTS_IN_FILE.format(file="/etc/a.pem; id")),
    C.tier1_line(C.CERTS_IN_FILE.format(file="'/etc/a\nb.pem'")),
    C.tier1_line(C.CERTS_IN_FILE.format(file="/etc/a.pem /etc/b.pem")),
    C.tier1_line(C.CERTS_IN_FILE.format(file="$(id)")),
    C.sudo_line(["/usr/bin/ss", "-H", "-tlnp", "-K"]),
    C.sudo_line(["/bin/sh", "-c", "id"]),
    "/usr/bin/sudo -n /usr/bin/ss -H -tlnp; id",
])
def test_unlisted_command_is_never_executed(fake_popen, tmp_path, line):
    sess = Z.LocalSession(tmp_dir=str(tmp_path), user="zs-cbom")
    fake_popen.calls.clear()  # the session read its own host key through the allowed ssh-keygen line
    with pytest.raises(Z.NotAllowed):
        sess.run(line)
    assert fake_popen.calls == []


def test_allow_list_covers_every_command_the_collector_has():
    """A command added to commands.py without being allowed here would make zs-collect refuse at run time."""
    fixed = {getattr(C, n) for n in dir(C) if n.isupper() and isinstance(getattr(C, n), str)}
    fixed -= {C.T1_ENV, C.SUDO, C.CRYPTO_LIBS_RE, C.KEY_FILE_RE}
    for cmd in fixed:
        line = C.tier1_line(cmd.format(file="/etc/ssl/x.pem") if "{file}" in cmd else cmd)
        assert Z.allowed_line(line), cmd
    for variants in C.TIER2.values():
        for argv in variants:
            assert Z.allowed_line(C.sudo_line(argv))
    for ktype in C.HOST_KEY_TYPES:
        assert Z.allowed_line(C.tier1_line(C.SSH_KEY_FINGERPRINT.format(file=f"/etc/ssh/ssh_host_{ktype}_key.pub")))


def test_paths_with_quotes_and_spaces_are_allowed_only_quoted(fake_popen, tmp_path):
    import shlex

    path = "/srv/my app/it's.pem"
    assert Z.allowed_line(C.tier1_line(C.CERTS_IN_FILE.format(file=shlex.quote(path))))
    assert not Z.allowed_line(C.tier1_line(C.CERTS_IN_FILE.format(file=path)))


# ----------------------------------------------------------------------------- envelope, nonce, schema
def test_envelope_echoes_the_nonce_and_validates(fake_popen, tmp_path):
    doc = _run_local(tmp_path, label="db-7.internal")
    assert doc["format"] == "zs-collect/1" and doc["run_nonce"] == NONCE
    assert doc["collector_version"] == VERSION and doc["tier"] == 2 and doc["target_label"] == "db-7.internal"
    assert set(doc["host"]) == {"hostname", "os_id", "machine_id_sha256"} and doc["host"]["os_id"] == "debian"
    assert doc["started_at"] <= doc["finished_at"]
    assert {a["target"] for a in doc["assets"]} == {"db-7.internal"}
    assert Z.validate_document(doc, nonce=NONCE, version=VERSION) is None
    assert "nonce" in Z.validate_document(doc, nonce="run-0000000000000000", version=VERSION)
    assert "version" in Z.validate_document(doc, nonce=NONCE, version="9.9.9")
    bad = copy.deepcopy(doc)
    bad["assets"][0]["type"] = "x" * 40
    assert "asset" in Z.validate_document(bad, nonce=NONCE, version=VERSION)
    bad = copy.deepcopy(doc)
    del bad["result"]
    assert Z.validate_document(bad, nonce=NONCE, version=VERSION)


def test_schema_file_is_valid_json_and_names_every_envelope_field():
    schema = json.loads((NODE_DIR / "zs_scan_node" / "schemas" / "zs-collect-1.schema.json").read_text())
    assert schema["properties"]["format"]["const"] == "zs-collect/1"
    for name in ("format", "collector_version", "run_nonce", "target_label", "tier", "host", "started_at",
                 "finished_at", "status", "error", "result", "assets", "elapsed_s"):
        assert name in schema["properties"], name
        assert name in schema["required"], name


@pytest.mark.parametrize("nonce", ["short", "has space 1234567890", "x" * 129, "semi;colon-12345678"])
def test_cli_refuses_a_bad_nonce(nonce, capsys):
    assert Z.main(["--nonce", nonce, "--tier", "1"]) == 2
    assert "nonce" in capsys.readouterr().err


# ----------------------------------------------------------------------------- parity with the SSH path
def _key(asset):
    return (asset["type"], asset["target"], asset["location"], asset["name"] or "")


def test_parity_same_session_outputs(fake_popen, tmp_path, monkeypatch):
    """The same host answers give the same assets on the SSH path and through zs-collect."""
    monkeypatch.setattr(Z.os, "getpid", lambda: 4242)  # the canned host shows zs-collect itself as pid 4242
    host = canned_host()
    ctx = _ctx()
    status, err, n = L.collect_on_session(ctx, FakeSsh(host), "10.0.0.5", {"tier": 2, "timeout_s": 300})
    ctx.flush()
    ssh_assets = sorted(ctx.collected, key=_key)
    doc = _run_local(tmp_path)
    local_assets = sorted(doc["assets"], key=_key)
    assert status == "ok" and n == len(ssh_assets)
    # the collector's own process (pid 4242, the _MEI libcrypto) is not reported; the SSH path never sees it
    assert not any("_MEI" in a["location"] for a in local_assets)
    ssh_assets = [a for a in ssh_assets if "_MEI" not in a["location"]]
    assert local_assets == ssh_assets
    assert doc["result"]["counts"] == {"total": 1, "ok": 1, "failed": 0, "skipped": 0}


def test_local_host_key_matches_what_the_ssh_handshake_reports(fake_popen, tmp_path):
    sess = Z.LocalSession(tmp_dir=str(tmp_path), user="zs-cbom")
    assert sess.host_key == FakeSsh.host_key


def test_collect_target_still_opens_a_session_and_delegates(monkeypatch):
    seen = {}

    def fake_open(ctx, target, config, creds):
        seen["opened"] = target.label
        return FakeSsh(canned_host())

    monkeypatch.setattr(L, "open_session", fake_open)
    ctx = _ctx()
    from zs_scan_node.netutil import Target

    status, err, n = L.collect_target(ctx, Target("10.0.0.5", "10.0.0.5"), {"tier": 1}, {"key": object()})
    assert seen["opened"] == "10.0.0.5" and status == "ok" and n > 0


# ----------------------------------------------------------------------------- private keys and scrubbing
def test_private_key_material_never_leaves_the_host(monkeypatch, tmp_path):
    host = canned_host()
    # a broken openssl that printed the private key instead of the public half: the Scrubber still removes it
    host[C.tier1_line(C.PUBLIC_HALF_OF_KEY.format(file="/etc/ssl/private/server.key"))] = (0, _private_pem().encode(), b"")
    rec = Recorder(host)
    monkeypatch.setattr(Z.subprocess, "Popen", rec)
    monkeypatch.setattr(os, "killpg", lambda *a: None)
    doc = _run_local(tmp_path)
    text = json.dumps(doc)
    assert "PRIVATE KEY" not in text and _private_pem().splitlines()[1] not in text
    key_lines = [argv[2] for argv, _k in rec.calls if "server.key" in argv[2]]
    # only the public half and the permission bits of a key file are ever asked for
    assert key_lines and all(" pkey -pubout " in line or " stat -c %a " in line for line in key_lines)


# ----------------------------------------------------------------------------- privileges and the temp dir
def test_drops_to_the_run_as_user_before_running_anything(monkeypatch, tmp_path):
    events = []
    monkeypatch.setattr(Z.os, "geteuid", lambda: 0 if "setuid" not in events else 1234)
    monkeypatch.setattr(Z.os, "getuid", lambda: 0 if "setuid" not in events else 1234)
    monkeypatch.setattr(Z.pwd, "getpwnam", lambda name: pwd.struct_passwd(
        (name, "x", 1234, 1234, "", "/home/" + name, "/usr/sbin/nologin")))
    monkeypatch.setattr(Z.os, "chown", lambda path, uid, gid, **kw: events.append("chown"))
    monkeypatch.setattr(Z.os, "initgroups", lambda name, gid: events.append("initgroups"), raising=False)
    monkeypatch.setattr(Z.os, "setgid", lambda gid: events.append("setgid"))
    monkeypatch.setattr(Z.os, "setuid", lambda uid: events.append("setuid") if uid == 1234 else
                        (_ for _ in ()).throw(PermissionError("not root any more")))
    rec = Recorder(canned_host())

    def popen(argv, **kw):
        assert "setuid" in events, "a command ran before the privilege drop"
        return rec(argv, **kw)

    monkeypatch.setattr(Z.subprocess, "Popen", popen)
    monkeypatch.setattr(os, "killpg", lambda *a: None)
    user = Z.drop_privileges("zs-cbom", str(tmp_path))
    assert user == "zs-cbom"
    assert events.index("initgroups") < events.index("setgid") < events.index("setuid")
    doc = _run_local(tmp_path, user=user)
    assert doc["status"] == "success" and rec.calls


@pytest.mark.parametrize("name,uid,err", [("root", 0, "root"), ("toor", 0, "root"), ("ghost", None, "does not exist")])
def test_refuses_to_collect_as_root_or_a_missing_user(monkeypatch, tmp_path, name, uid, err):
    monkeypatch.setattr(Z.os, "geteuid", lambda: 0)

    def getpwnam(n):
        if uid is None:
            raise KeyError(n)
        return pwd.struct_passwd((n, "x", uid, uid, "", "/root", "/bin/sh"))

    monkeypatch.setattr(Z.pwd, "getpwnam", getpwnam)
    monkeypatch.setattr(Z.os, "setuid", lambda uid: pytest.fail("must not change user"))
    with pytest.raises(Z.Refused) as exc:
        Z.drop_privileges(name, str(tmp_path))
    assert err in str(exc.value)


def test_own_temp_dir_is_private_and_removed(fake_popen, monkeypatch, capsys):
    made = []
    real_mkdtemp = Z.tempfile.mkdtemp

    def mkdtemp(**kw):
        d = real_mkdtemp(**kw)
        made.append(d)
        assert (os.stat(d).st_mode & 0o777) == 0o700
        return d

    monkeypatch.setattr(Z.tempfile, "mkdtemp", mkdtemp)
    monkeypatch.setattr(Z, "drop_privileges", lambda user, tmp: None)
    code = Z.main(["--nonce", NONCE, "--tier", "2", "--label", "10.0.0.5"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0 and doc["run_nonce"] == NONCE
    assert made and not os.path.exists(made[0])


def test_given_temp_dir_is_left_as_found(fake_popen, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(Z, "drop_privileges", lambda user, tmp: None)
    before = sorted(os.listdir(tmp_path))
    assert Z.main(["--nonce", NONCE, "--tier", "1", "--tmp-dir", str(tmp_path)]) == 0
    capsys.readouterr()
    assert sorted(os.listdir(tmp_path)) == before


# ----------------------------------------------------------------------------- chunked output (AWX events)
def test_chunks_roundtrip_and_detect_tampering(fake_popen, tmp_path):
    doc = _run_local(tmp_path)
    lines = Z.encode_chunks(doc, NONCE, chunk_bytes=2048)
    assert len(lines) > 1 and all(len(line.encode()) <= 2048 for line in lines)
    assert Z.reassemble(lines, NONCE) == doc
    assert Z.reassemble(list(reversed(lines)), NONCE) == doc  # events may arrive out of order
    with pytest.raises(Z.ChunkError):
        Z.reassemble(lines[:-1], NONCE)
    broken = list(lines)
    head, data = broken[0].rsplit(" ", 1)
    broken[0] = head + " " + ("A" if data[0] != "A" else "B") + data[1:]
    with pytest.raises(Z.ChunkError):
        Z.reassemble(broken, NONCE)
    with pytest.raises(Z.ChunkError):
        Z.reassemble(lines, "run-ffffffffffffffff")
    assert Z.MAX_CHUNK_BYTES <= 512 * 1024


# ----------------------------------------------------------------------------- real process: network and writes
def _cli(tmp: Path) -> list[str]:
    args = [sys.executable, "-B", "-m", "zs_scan_node.zscollect", "--nonce", NONCE, "--tier", "1", "--label", "self",
            "--tmp-dir", str(tmp)]
    if os.geteuid() == 0:
        args += ["--run-as", "nobody"]
    return args


def _env(tmp: Path) -> dict:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(NODE_DIR), "TMPDIR": str(tmp),
            "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"}


def _normalised(text: str) -> list:
    doc = json.loads(text)
    return sorted((json.dumps({k: v for k, v in a.items()}, sort_keys=True) for a in doc["assets"]))


def _tmp_for_run(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        # root drops to nobody, who cannot enter pytest's 0700 base directory: use a fresh directory under /tmp
        import atexit
        import tempfile

        d = Path(tempfile.mkdtemp(prefix="zs-collect-test."))
        atexit.register(shutil.rmtree, str(d), True)
        return d
    d = tmp_path / "run"
    d.mkdir(mode=0o700)
    return d


def _unshare_prefix() -> list[str] | None:
    if not shutil.which("unshare"):
        return None
    for prefix in (["unshare", "-n"], ["unshare", "-n", "--map-current-user"], ["unshare", "-rn"]):
        probe = subprocess.run(prefix + ["true"], capture_output=True)
        if probe.returncode == 0:
            if prefix[-1] == "-rn" and os.geteuid() != 0:
                return None  # uid 0 inside: zs-collect would try to drop to a user the namespace does not map
            return prefix
    return None


def test_output_identical_without_network(tmp_path):
    prefix = _unshare_prefix()
    if prefix is None:
        pytest.skip("network namespaces are not available here (unshare refused)")
    d1, d2 = _tmp_for_run(tmp_path / "a"), _tmp_for_run(tmp_path / "b")
    a = subprocess.run(_cli(d1), capture_output=True, text=True, env=_env(d1), cwd=str(d1), timeout=300)
    b = subprocess.run(prefix + _cli(d2), capture_output=True, text=True, env=_env(d2), cwd=str(d2), timeout=300)
    assert a.returncode in (0, 1) and b.returncode in (0, 1), (a.stderr[-2000:], b.stderr[-2000:])
    probe = subprocess.run(prefix + ["cat", "/proc/net/dev"], capture_output=True, text=True)
    assert "eth" not in probe.stdout  # really no network in there
    assert _normalised(a.stdout) == _normalised(b.stdout)


def _strace(tmp_path: Path, calls: str) -> tuple[list[str], Path]:
    if not shutil.which("strace"):
        pytest.skip("strace is not installed")
    run = _tmp_for_run(tmp_path)
    log = tmp_path / "strace.log"
    p = subprocess.run(["strace", "-f", "-qq", "-e", f"trace={calls}", "-o", str(log)] + _cli(run),
                       capture_output=True, text=True, env=_env(run), cwd=str(run), timeout=600)
    if p.returncode not in (0, 1) and "ptrace" in p.stderr:
        pytest.skip("ptrace is not permitted here")
    assert p.returncode in (0, 1), p.stderr[-2000:]
    assert json.loads(p.stdout)["run_nonce"] == NONCE
    return log.read_text().splitlines(), run


def test_no_inet_socket_syscalls(tmp_path):
    lines, _run = _strace(tmp_path, "socket,connect,bind,listen,accept,accept4")
    inet = [line for line in lines if "AF_INET" in line]
    listening = [line for line in lines if " listen(" in line or " accept" in line]
    assert inet == [] and listening == [], (inet + listening)[:10]


def test_writes_only_inside_tmp_dir(tmp_path):
    calls = "open,openat,openat2,creat,mkdir,mkdirat,rename,renameat,renameat2,unlink,unlinkat,rmdir,link,linkat," \
            "symlink,symlinkat,truncate,chmod,fchmodat,chown,fchownat,mknod,mknodat"
    lines, run = _strace(tmp_path, calls)
    import re

    bad = []
    for line in lines:
        m = re.search(r'\b(\w+)\((?:AT_FDCWD|\d+)?,?\s*"([^"]*)"(.*)', line)
        if not m or "= -1" in line:
            continue
        call, path, rest = m.group(1), m.group(2), m.group(3)
        if call in ("open", "openat", "openat2") and not re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND", rest):
            continue
        if path in ("/dev/null", "/dev/tty") or path.startswith("/proc/self/") or path.startswith("/dev/pts/"):
            continue
        absolute = path if path.startswith("/") else os.path.join(str(run), path)
        if not os.path.realpath(absolute).startswith(os.path.realpath(str(run))):
            bad.append(line)
    assert bad == [], bad[:10]
