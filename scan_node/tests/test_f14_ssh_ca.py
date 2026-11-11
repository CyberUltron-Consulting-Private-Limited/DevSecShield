"""F1.4 on the node: SSH CA certificates for the node's own key (``zs_scan_node.sshca``, ``linux_ssh._credentials``).

The certificate is checked to be a user certificate for this node's key, renewed through ``ctx.cert_refresher`` before
it runs out, and a failed renewal falls back to the current certificate only while it still has time left.  The real
sshd proofs (valid, expired, principal / source-address mismatch, KRL, rotation) are in bench/f1_sshca/.
"""
from __future__ import annotations

import time
from pathlib import Path

import httpx
import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    SSHCertificateBuilder,
    SSHCertificateType,
)

from zs_scan_node import api as node_api
from zs_scan_node import sshca
from zs_scan_node.collectors import CAPABILITIES, ConfigError
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

CA = ed25519.Ed25519PrivateKey.generate()


def _node_key(tmp_path: Path, name: str = "id_ed25519") -> tuple[Path, ed25519.Ed25519PrivateKey]:
    key = ed25519.Ed25519PrivateKey.generate()
    path = tmp_path / name
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    path.chmod(0o600)
    return path, key


def _cert(key: ed25519.Ed25519PrivateKey, *, serial: int = 1, ttl: int = 300,
          cert_type: SSHCertificateType = SSHCertificateType.USER) -> str:
    now = int(time.time())
    b = (SSHCertificateBuilder().public_key(key.public_key()).serial(serial).type(cert_type).key_id(b"zs:1:2:3:1")
         .valid_principals([b"zs-1-prod"]).valid_after(now - 60).valid_before(now + ttl))
    return b.sign(CA).public_bytes().decode()


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_the_node_advertises_the_ssh_ca_capability():
    assert "ssh_ca" in CAPABILITIES


def test_only_a_user_certificate_for_the_nodes_own_key_is_used(tmp_path):
    path, key = _node_key(tmp_path)
    mine = paramiko.Ed25519Key.from_private_key_file(str(path))
    sshca.check_cert_for_key(_cert(key), mine)
    with pytest.raises(sshca.CertUnavailable, match="another key"):
        sshca.check_cert_for_key(_cert(ed25519.Ed25519PrivateKey.generate()), mine)
    with pytest.raises(sshca.CertUnavailable, match="not a user certificate"):
        sshca.check_cert_for_key(_cert(key, cert_type=SSHCertificateType.HOST), mine)
    with pytest.raises(sshca.CertUnavailable):
        sshca.check_cert_for_key("ssh-ed25519 AAAA", mine)
    with pytest.raises(sshca.CertUnavailable):
        sshca.check_cert_for_key(key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode(), mine)


def test_cert_source_renews_before_expiry_and_falls_back_while_the_old_one_lasts(tmp_path):
    path, key = _node_key(tmp_path)
    clock = Clock()
    calls: list[int] = []
    answers: list = []

    def refresher():
        calls.append(1)
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    src = sshca.CertSource(str(path), _cert(key, serial=1), 300, 120, refresher, clock=clock)
    first = src.key()
    assert first.public_blob is not None and first.public_blob.key_type == "ssh-ed25519-cert-v01@openssh.com"
    assert calls == []  # 300 s left: no renewal
    clock.t += 200  # 100 s left: inside the 120 s window
    answers.append({"certificate": _cert(key, serial=2), "expires_in_s": 300, "serial": 2})
    second = src.key()
    assert calls == [1] and second is not first and src.serial == 2 and src.renewals == 1
    clock.t += 250  # 50 s left; ZeroShield cannot be reached: keep using the current certificate
    answers.append(node_api.ApiError(0, "ConnectError"))
    assert src.key() is second
    clock.t += 45  # 5 s left and renewal refused: no certificate for a new login
    answers.append(node_api.ApiError(400, "The source's SSH CA has no active key (missing, revoked or not promoted)"))
    with pytest.raises(sshca.CertUnavailable, match="no active key"):
        src.key()
    # a renewal answer for another key is refused, never offered to a server
    clock.t += 1000
    answers.append({"certificate": _cert(ed25519.Ed25519PrivateKey.generate()), "expires_in_s": 300})
    with pytest.raises(sshca.CertUnavailable, match="another key"):
        src.key()


def _ctx(tmp_path, path, refresher=None) -> JobContext:
    ctx = JobContext(job_id=7, attempt=1, run_id=None, kind="collect", source_kind="linux_servers",
                     scrubber=Scrubber([]), never_scan=NeverScan(), deadline=time.monotonic() + 60,
                     state_dir=str(tmp_path), node_private_key_path=str(path))
    ctx.cert_refresher = refresher
    return ctx


def test_credentials_for_ssh_ca(tmp_path):
    path, key = _node_key(tmp_path)
    ctx = _ctx(tmp_path, path)
    creds = L._credentials(ctx, {"credential_type": "ssh_ca",
                                 "ssh_ca": {"serial": 1, "expires_in_s": 300, "refresh_before_s": 120}},
                           {"ssh_certificate": _cert(key)})
    assert isinstance(creds["cert_source"], sshca.CertSource) and "password" not in creds
    with pytest.raises(ConfigError, match="SSH CA: The source's SSH CA has no active key"):
        L._credentials(ctx, {"credential_type": "ssh_ca", "ssh_ca": {"error": "The source's SSH CA has no active key"}},
                       {})
    # no certificate in the claim (a Vault CA): the node asks for one before it connects
    asked = []
    ctx2 = _ctx(tmp_path, path, lambda: asked.append(1) or {"certificate": _cert(key), "expires_in_s": 300})
    creds = L._credentials(ctx2, {"credential_type": "ssh_ca", "ssh_ca": {"fetch": True}}, {})
    assert asked == [1] and creds["cert_source"].renewals == 1
    ctx3 = _ctx(tmp_path, path, None)
    with pytest.raises(ConfigError, match="no SSH certificate was issued"):
        L._credentials(ctx3, {"credential_type": "ssh_ca", "ssh_ca": {"fetch": True}}, {})


def test_api_asks_for_a_certificate_with_the_lease(tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"certificate": "c", "expires_in_s": 300})

    client = node_api.Api("https://zs.example", "zsn_" + "a" * 40)
    client.client = httpx.Client(base_url="https://zs.example", transport=httpx.MockTransport(handler))
    assert client.ssh_cert(42, 2, "lease-abc")["expires_in_s"] == 300
    assert seen[0].url.path == "/cbom/node/jobs/42/ssh-cert" and seen[0].content == b'{"lease_id":"lease-abc"}'

    def gone(request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"detail": "This job is no longer leased to this node"})

    client.client = httpx.Client(base_url="https://zs.example", transport=httpx.MockTransport(gone))
    with pytest.raises(node_api.LeaseLost):
        client.ssh_cert(42, 2, "lease-abc")
