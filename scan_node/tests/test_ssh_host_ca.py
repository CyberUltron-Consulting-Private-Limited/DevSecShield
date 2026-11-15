"""#59: ``host_key_policy: host_ca``: a Linux source trusts OpenSSH host certificates signed by its listed host CAs.

paramiko 3.5.1 negotiates a host certificate but checks only the key-exchange signature, never the certificate.  The
node checks it itself (cryptography 44): signed by a listed CA, type HOST, a principal equal to the target's name or
address, inside its validity window, and certifying the very key that signed the key exchange.  Anything else is
``host_key_mismatch`` before any credential is sent.
"""
from __future__ import annotations

import base64
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import SSHCertificateBuilder, SSHCertificateType

from zs_scan_node import hostcert as HC
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber

NOW = 1_800_000_000


def _openssh(public_key) -> str:
    return public_key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def _cert(ca, host_key, *, principals=("db01.bank.local", "10.0.0.5"), kind=SSHCertificateType.HOST,
          after=NOW - 60, before=NOW + 3600, critical=None):
    builder = (SSHCertificateBuilder().public_key(host_key.public_key()).serial(7).type(kind).key_id(b"db01")
               .valid_after(after).valid_before(before))
    builder = builder.valid_principals([p.encode() for p in principals]) if principals else \
        builder.valid_for_all_principals()
    for name, value in (critical or {}).items():
        builder = builder.add_critical_option(name, value)
    cert = builder.sign(ca)
    line = cert.public_bytes()
    cert_type, blob = line.split()[:2]
    return cert_type.decode(), base64.b64decode(blob)


def _plain_blob(key) -> bytes:
    return base64.b64decode(_openssh(key.public_key()).split()[1])


CA = ed25519.Ed25519PrivateKey.generate()
OTHER_CA = ed25519.Ed25519PrivateKey.generate()
HOST = ed25519.Ed25519PrivateKey.generate()


def _check(cert, kex_key=HOST, cas=(CA,), names=("db01.bank.local", "10.0.0.5"), now=NOW):
    cert_type, blob = cert
    return HC.check_host_certificate(cert_type, blob, _plain_blob(kex_key), [_openssh(c.public_key()) for c in cas],
                                     list(names), now)


def test_a_host_certificate_from_a_listed_ca_for_this_host_is_accepted():
    facts = _check(_cert(CA, HOST))
    assert facts["key_id"] == "db01" and facts["serial"] == 7 and facts["principals"] == ["db01.bank.local", "10.0.0.5"]
    assert facts["ca_fingerprint"].startswith("SHA256:")
    _check(_cert(CA, HOST), names=("10.0.0.5",))  # the address alone is enough
    _check(_cert(CA, HOST, principals=("DB01.bank.local",)), names=("db01.bank.local",))  # names: case-insensitive


@pytest.mark.parametrize("key_type", ["rsa", "ecdsa"])
def test_rsa_and_ecdsa_host_keys_and_cas_work_too(key_type):
    host = rsa.generate_private_key(public_exponent=65537, key_size=2048) if key_type == "rsa" else \
        ec.generate_private_key(ec.SECP256R1())
    ca = ec.generate_private_key(ec.SECP384R1()) if key_type == "rsa" else rsa.generate_private_key(65537, 3072)
    _check(_cert(ca, host), kex_key=host, cas=(ca,))


@pytest.mark.parametrize("case,expected", [
    ("other_ca", "is not signed by a host CA listed for this source"),
    ("expired", "expired"),
    ("not_yet", "is not valid before"),
    ("user_cert", "a user certificate, not a host certificate"),
    ("wrong_principal", "is not for db01.bank.local or 10.0.0.5"),
    ("all_principals", "names no host"),
    ("swapped_key", "certifies another key than the one that signed the key exchange"),
    ("critical", "has critical options"),
    ("bad_signature", "signature does not verify"),
])
def test_every_other_certificate_is_refused(case, expected):
    other_host = ed25519.Ed25519PrivateKey.generate()
    certs = {
        "other_ca": lambda: _check(_cert(OTHER_CA, HOST)),
        "expired": lambda: _check(_cert(CA, HOST, after=NOW - 7200, before=NOW - 3600)),
        "not_yet": lambda: _check(_cert(CA, HOST, after=NOW + 600, before=NOW + 3600)),
        "user_cert": lambda: _check(_cert(CA, HOST, kind=SSHCertificateType.USER)),
        "wrong_principal": lambda: _check(_cert(CA, HOST, principals=("web01.bank.local",))),
        "all_principals": lambda: _check(_cert(CA, HOST, principals=())),
        "swapped_key": lambda: _check(_cert(CA, other_host)),  # a valid certificate, but for another key
        "critical": lambda: _check(_cert(CA, HOST, critical={b"force-command": b"/bin/true"})),
        "bad_signature": lambda: _tampered(),
    }

    def _tampered():
        cert_type, blob = _cert(CA, HOST)
        return _check((cert_type, blob[:-1] + bytes([blob[-1] ^ 1])))

    with pytest.raises(HC.HostCertRefused, match=expected):
        certs[case]()


def test_a_plain_host_key_is_not_a_certificate():
    with pytest.raises(HC.HostCertRefused, match="presented a plain host key"):
        HC.check_host_certificate("ssh-ed25519", _plain_blob(HOST), _plain_blob(HOST), [_openssh(CA.public_key())],
                                  ["10.0.0.5"], NOW)


def test_only_certificate_host_key_types_are_offered():
    assert HC.offered_key_types(L.paramiko.Transport._key_info) == (
        "ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com")


def test_host_ca_passes_the_password_rule():
    """A certificate from a listed CA proves the server, like a pinned known_hosts line: a password may go to it."""
    assert L.verified_host_policy("host_ca") and L.verified_host_policy("pinned") and not L.verified_host_policy("tofu")


# ----------------------------------------------------------------------------- a real sshd (acceptance, #59)
SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
KEYGEN = shutil.which("ssh-keygen")
live = pytest.mark.skipif(not (SSHD and KEYGEN and os.geteuid() == 0 and os.path.isdir("/run/sshd")),
                          reason="needs openssh-server, ssh-keygen and root (the sandbox's acceptance run)")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def sshd(tmp_path: Path):
    """sshd on 127.0.0.1 whose host certificate is made per test: (start(cert args), ca public line, node key)."""
    procs: list[subprocess.Popen] = []
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731
    for name in ("ca", "other-ca", "host", "node"):
        run(KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / name), "-C", name)
    (tmp_path / "authorized_keys").write_text((tmp_path / "node.pub").read_text())

    def start(ca="ca", principals="127.0.0.1", validity="-5m:+1h", user_cert=False) -> int:
        cert = tmp_path / "host-cert.pub"
        cert.unlink(missing_ok=True)
        args = [KEYGEN, "-q", "-s", str(tmp_path / ca), "-I", "lab-host", "-n", principals, "-V", validity]
        run(*args, *([] if user_cert else ["-h"]), str(tmp_path / "host.pub"))
        port = _free_port()
        conf = tmp_path / f"sshd-{port}.conf"
        conf.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {tmp_path / 'host'}\nHostCertificate {cert}\n"
                        f"PidFile {tmp_path / f'sshd-{port}.pid'}\nAuthorizedKeysFile {tmp_path / 'authorized_keys'}\n"
                        "PermitRootLogin prohibit-password\nPasswordAuthentication no\nUsePAM no\nStrictModes no\n")
        procs.append(subprocess.Popen([SSHD, "-D", "-e", "-f", str(conf)], stderr=subprocess.DEVNULL))
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return port
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("sshd did not start")

    yield start, (tmp_path / "ca.pub").read_text().strip(), str(tmp_path / "node")
    for p in procs:
        p.kill()
        p.wait()


def _session(port: int, ca_line: str, node_key: str, state: Path):
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="test_connection", source_kind="linux_servers",
                     scrubber=Scrubber(), never_scan=NeverScan(), deadline=time.monotonic() + 60,
                     state_dir=str(state))
    creds = {"key": L.paramiko.Ed25519Key.from_private_key_file(node_key)}
    config = {"port": port, "login_user": "root", "host_key_policy": "host_ca", "host_ca_keys": [ca_line]}
    return L.open_session(ctx, Target("127.0.0.1", "127.0.0.1"), config, creds)


@live
def test_a_real_sshd_with_a_host_certificate_from_the_listed_ca_is_accepted(sshd, tmp_path):
    start, ca_line, node_key = sshd
    sess = _session(start(), ca_line, node_key, tmp_path)
    try:
        assert sess.host_key["key_type"] == "ssh-ed25519-cert-v01@openssh.com"
        assert sess.host_key["certificate"]["principals"] == ["127.0.0.1"]
        assert sess.run("true")[0] == 0
    finally:
        sess.close()
    assert not (tmp_path / "known_hosts.json").exists()  # nothing pinned on first use under host_ca


@live
@pytest.mark.parametrize("variant,expected", [
    ({"ca": "other-ca"}, "is not signed by a host CA listed for this source"),
    ({"validity": "-2h:-1h"}, "expired"),
    ({"user_cert": True}, "user certificate"),
    ({"principals": "db99.bank.local"}, "is not for 127.0.0.1"),
])
def test_a_real_sshd_with_any_other_certificate_is_refused(sshd, tmp_path, variant, expected):
    start, ca_line, node_key = sshd
    with pytest.raises(L.TargetFail) as err:
        _session(start(**variant), ca_line, node_key, tmp_path)
    assert err.value.status == "host_key_mismatch" and expected in err.value.error
