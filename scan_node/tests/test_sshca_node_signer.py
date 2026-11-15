"""#61: a customer-held SSH CA key on the scan node (``provider: node``).

ZeroShield stores only the CA's public key.  For each job the claim carries a grant (``config.ssh_ca.node_sign``): the
CA's public key, the serial, key id, principals, source addresses and validity ZeroShield recorded for the job.  The
node signs its own key with the CA key file in its state directory (mode 0400, path ``ZS_SSH_CA_KEY``), only for
what the grant says, reports the certificate (ZeroShield checks it against the grant), and the CA private key never
leaves the node.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_ssh_public_identity

from zs_scan_node import sshca_node as SN
from zs_scan_node.collectors import ConfigError
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber


def _line(public_key) -> str:
    return public_key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


@pytest.fixture()
def state(tmp_path: Path):
    """A node state directory: the node's own key and the customer's CA key file (0400)."""
    node = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "id_ed25519").write_bytes(node.private_bytes(serialization.Encoding.PEM,
                                                             serialization.PrivateFormat.OpenSSH,
                                                             serialization.NoEncryption()))
    os.chmod(tmp_path / "id_ed25519", 0o600)
    ca = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "ssh-ca").mkdir(mode=0o700)
    key_file = tmp_path / "ssh-ca" / "ca_key"
    key_file.write_bytes(ca.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                          serialization.NoEncryption()))
    os.chmod(key_file, 0o400)
    return {"dir": tmp_path, "node": node, "ca": ca, "ca_line": _line(ca.public_key()), "key_file": key_file}


def _grant(st, now=None, **over):
    now = int(now or time.time())
    grant = {"ca_public_key": st["ca_line"], "serial": 41, "key_id": "zs:1:7:9:41", "principals": ["zs-1-prod"],
             "source_addresses": ["127.0.0.1"], "valid_after": now - 60, "valid_before": now + 240, "ttl_s": 300}
    grant.update(over)
    return grant


def _signer(st):
    return SN.NodeSigner.from_state(str(st["dir"]), env={})


def test_the_node_signs_exactly_what_the_grant_says(state):
    grant = _grant(state)
    line = _signer(state).sign(grant, _line(state["node"].public_key()))
    cert = load_ssh_public_identity(line.encode())
    cert.verify_cert_signature()
    assert _line(cert.signature_key()) == state["ca_line"]
    assert _line(cert.public_key()) == _line(state["node"].public_key())  # the node's own key
    assert (cert.serial, cert.key_id, cert.valid_principals) == (41, b"zs:1:7:9:41", [b"zs-1-prod"])
    assert (cert.valid_after, cert.valid_before) == (grant["valid_after"], grant["valid_before"])
    assert cert.critical_options == {b"source-address": b"127.0.0.1"} and cert.extensions == {}
    assert cert.type.name == "USER"


@pytest.mark.parametrize("request_,message", [
    ({"principals": ["zs-1-prod", "zs-1-admin"]}, "principals it was not sent for this job"),
    ({"principals": ["root"]}, "principals it was not sent for this job"),
    ({"ttl_s": 301}, "longer than the 300 s it was sent for this job"),
])
def test_the_node_refuses_principals_or_ttls_it_was_not_sent(state, request_, message):
    with pytest.raises(SN.SignRefused, match=message):
        _signer(state).sign(_grant(state), _line(state["node"].public_key()), **request_)


@pytest.mark.parametrize("over,message", [
    ({"principals": []}, "no principals"),
    ({"principals": ["root"]}, "only zs-<team>-<group> principals"),
    ({"source_addresses": []}, "no source address"),
    ({"ttl_s": 7200, "valid_before": int(time.time()) + 7140}, "at most 3600 s"),
    ({"ttl_s": 120}, "does not match its TTL"),
    ({"serial": 0}, "serial"),
    ({"ca_public_key": _line(ed25519.Ed25519PrivateKey.generate().public_key())}, "is not this node's CA key"),
])
def test_a_grant_outside_the_rules_is_refused(state, over, message):
    with pytest.raises(SN.SignRefused, match=message):
        _signer(state).sign(_grant(state, **over), _line(state["node"].public_key()))


@pytest.mark.parametrize("mode", [0o440, 0o600, 0o644, 0o404])
def test_the_ca_key_file_must_be_mode_0400(state, mode):
    os.chmod(state["key_file"], mode)
    with pytest.raises(ConfigError, match="mode 0400"):
        _signer(state)


def test_a_missing_ca_key_file_names_the_path_and_the_setting(state):
    os.chmod(state["key_file"], 0o600)
    state["key_file"].unlink()
    with pytest.raises(ConfigError, match=r"no SSH CA key at .*ssh-ca/ca_key.*ZS_SSH_CA_KEY"):
        _signer(state)


def test_the_key_path_is_configurable(state, tmp_path):
    other = tmp_path / "elsewhere.key"
    shutil.copy(state["key_file"], other)
    os.chmod(other, 0o400)
    signer = SN.NodeSigner.from_state(str(state["dir"]), env={"ZS_SSH_CA_KEY": str(other)})
    assert signer.public_line == state["ca_line"]


def test_the_collector_signs_reports_and_logs_in_with_the_grant(state):
    """linux_ssh's ssh_ca credential: the claim's grant is signed, reported, and the certificate is used."""
    reported: list[str] = []
    ctx = JobContext(job_id=9, attempt=1, run_id=None, kind="collect", source_kind="linux_servers",
                     scrubber=Scrubber(), never_scan=NeverScan(), deadline=time.monotonic() + 60,
                     state_dir=str(state["dir"]), node_private_key_path=str(state["dir"] / "id_ed25519"))
    ctx.cert_reporter = lambda line: reported.append(line) or {"recorded": True}
    grant = _grant(state)
    creds = L._credentials(ctx, {"credential_type": "ssh_ca", "ssh_ca": {
        "node_sign": grant, "serial": 41, "expires_in_s": 240, "refresh_before_s": 120, "backdated_s": 60}}, {})
    key = creds["cert_source"].key()
    assert reported and key.public_blob is not None and creds["cert_source"].serial == 41
    assert load_ssh_public_identity(reported[0].encode()).serial == 41


def test_a_certificate_zeroshield_did_not_record_is_never_used(state):
    ctx = JobContext(job_id=9, attempt=1, run_id=None, kind="collect", source_kind="linux_servers",
                     scrubber=Scrubber(), never_scan=NeverScan(), deadline=time.monotonic() + 60,
                     state_dir=str(state["dir"]), node_private_key_path=str(state["dir"] / "id_ed25519"))

    def refuse(line):
        raise RuntimeError("ZeroShield refused the report")

    ctx.cert_reporter = refuse
    with pytest.raises(ConfigError, match="could not be reported to ZeroShield"):
        L._credentials(ctx, {"credential_type": "ssh_ca", "ssh_ca": {"node_sign": _grant(state), "expires_in_s": 240}},
                       {})


# ----------------------------------------------------------------------------- a real sshd with TrustedUserCAKeys
SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
KEYGEN = shutil.which("ssh-keygen")
live = pytest.mark.skipif(not (SSHD and KEYGEN and os.geteuid() == 0 and os.path.isdir("/run/sshd")),
                          reason="needs openssh-server, ssh-keygen and root (the sandbox's acceptance run)")


@live
@pytest.mark.parametrize("principal,accepted", [("zs-1-prod", True), ("zs-1-other", False)])
def test_a_real_sshd_trusting_the_customer_ca_accepts_the_node_signed_certificate(state, tmp_path, principal,
                                                                                  accepted):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    run_dir = tmp_path / "sshd"
    run_dir.mkdir()
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(run_dir / "host")], check=True)
    (run_dir / "ca.pub").write_text(state["ca_line"] + "\n")
    (run_dir / "principals").write_text(principal + "\n")  # what this server lets in (AuthorizedPrincipalsFile)
    conf = run_dir / "sshd.conf"
    conf.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {run_dir / 'host'}\n"
                    f"TrustedUserCAKeys {run_dir / 'ca.pub'}\nAuthorizedPrincipalsFile {run_dir / 'principals'}\n"
                    "AuthorizedKeysFile none\nPermitRootLogin prohibit-password\nPasswordAuthentication no\n"
                    "UsePAM no\nStrictModes no\n")
    proc = subprocess.Popen([SSHD, "-D", "-e", "-f", str(conf)], stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        ctx = JobContext(job_id=9, attempt=1, run_id=None, kind="test_connection", source_kind="linux_servers",
                         scrubber=Scrubber(), never_scan=NeverScan(), deadline=time.monotonic() + 60,
                         state_dir=str(state["dir"]), node_private_key_path=str(state["dir"] / "id_ed25519"))
        ctx.cert_reporter = lambda line: {"recorded": True}
        config = {"port": port, "login_user": "root", "credential_type": "ssh_ca", "host_key_policy": "tofu",
                  "ssh_ca": {"node_sign": _grant(state), "expires_in_s": 240, "backdated_s": 60}}
        creds = L._credentials(ctx, config, {})
        if accepted:
            sess = L.open_session(ctx, Target("127.0.0.1", "127.0.0.1"), config, creds)
            try:
                assert sess.run("true")[0] == 0
            finally:
                sess.close()
        else:
            with pytest.raises(L.TargetFail) as err:
                L.open_session(ctx, Target("127.0.0.1", "127.0.0.1"), config, creds)
            assert err.value.status == "auth_failed"
    finally:
        proc.kill()
        proc.wait()


def test_paramiko_is_still_the_client():  # the signer adds no SSH client of its own
    assert paramiko.__version__ == "3.5.1"
