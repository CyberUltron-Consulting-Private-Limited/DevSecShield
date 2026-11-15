"""CB-13: SSH endpoints are judged on every host key the server holds and on every algorithm it offers.

Facts are in the shape the scan node's sshprobe reports (``host_keys``: one entry per host-key family, certificates
with their CA and validity).  Expected codes come from the rule table in the DA (KF-17: RSA-1024 beside Ed25519 must
raise RSA_LT_2048) and from the IANA / OpenSSH algorithm names, never from the classifier's own output.
"""
from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest
from backend.utilities.cbom_sources.classify import classify
from backend.utilities.cbom_sources.drift import job_gaps

NOW = dt.datetime(2026, 11, 12, 12, 0, 0, tzinfo=dt.timezone.utc).replace(tzinfo=None)  # classify works in naive UTC


def _ssh(**facts):
    return classify("ssh_endpoint", facts.pop("algorithm", None), facts.pop("key_size", None), "ssh", facts, now=NOW)


def test_every_host_key_is_judged_not_only_the_negotiated_one():
    """KF-17: the network view listed only Ed25519; the RSA-1024 key beside it must raise RSA_LT_2048 (High)."""
    out = _ssh(algorithm="ssh-ed25519", key_size=256, kex=["curve25519-sha256"],
               host_key={"key_type": "ssh-ed25519", "bits": 256},
               host_keys=[{"type": "ssh-ed25519", "bits": 256}, {"type": "ssh-rsa", "bits": 1024},
                          {"type": "ecdsa-sha2-nistp256", "bits": 256, "curve": "nistp256"}])
    assert "RSA_LT_2048" in out["finding_codes"] and out["impacts"]["RSA_LT_2048"] == "High"
    assert "ssh-rsa" in out["texts"]["RSA_LT_2048"] and "1024" in out["texts"]["RSA_LT_2048"]
    assert out["impact"] == "High"


@pytest.mark.parametrize("key, code", [({"type": "ssh-rsa", "bits": 768}, "RSA_LT_1024"),
                                       ({"type": "ssh-dss", "bits": 1024}, "DSA"),
                                       ({"type": "ssh-rsa-cert-v01@openssh.com", "key_type": "ssh-rsa", "bits": 1024,
                                         "certificate": {"valid_before": "forever"}}, "RSA_LT_2048")])
def test_host_key_size_rules(key, code):
    assert code in _ssh(kex=["curve25519-sha256"], host_keys=[key])["finding_codes"]


def test_strong_host_keys_raise_no_key_finding():
    out = _ssh(kex=["mlkem768x25519-sha256"], host_keys=[{"type": "ssh-ed25519", "bits": 256},
                                                         {"type": "ssh-rsa", "bits": 3072},
                                                         {"type": "ecdsa-sha2-nistp384", "bits": 384}])
    assert out["finding_codes"] == [] and out["quantum_vulnerable"] is False


def test_host_certificates_expiry_ca_key_and_sha1_signature():
    expired = {"type": "ssh-rsa-cert-v01@openssh.com", "key_type": "ssh-rsa", "bits": 3072,
               "certificate": {"cert_type": "host", "valid_after": "2020-01-01T00:00:00+00:00",
                               "valid_before": "2021-01-01T00:00:00+00:00", "signature_algorithm": "ssh-rsa",
                               "ca": {"type": "ssh-rsa", "bits": 1024}}}
    soon = {"type": "ssh-ed25519-cert-v01@openssh.com", "key_type": "ssh-ed25519", "bits": 256,
            "certificate": {"valid_before": "2026-11-30T00:00:00+00:00", "signature_algorithm": "ssh-ed25519",
                            "ca": {"type": "ssh-ed25519", "bits": 256}}}
    out = _ssh(kex=["curve25519-sha256"], host_keys=[expired])
    assert {"CERT_EXPIRED", "RSA_LT_2048", "SIG_SHA1"} <= set(out["finding_codes"])
    assert "2021-01-01" in out["texts"]["CERT_EXPIRED"] and "SSH host certificate" in out["texts"]["CERT_EXPIRED"]
    assert "CA key" in out["texts"]["RSA_LT_2048"]
    out = _ssh(kex=["curve25519-sha256"], host_keys=[soon])
    assert "CERT_EXPIRES_30D" in out["finding_codes"] and "CERT_EXPIRED" not in out["finding_codes"]
    forever = {**soon, "certificate": {**soon["certificate"], "valid_before": "forever"}}
    assert "CERT_EXPIRES_30D" not in _ssh(kex=["curve25519-sha256"], host_keys=[forever])["finding_codes"]


@pytest.mark.parametrize("facts, code", [
    ({"kex": ["diffie-hellman-group1-sha1"]}, "SSH_DH_GROUP1"),
    ({"kex": ["gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g=="]}, "SSH_DH_GROUP1"),
    ({"kex": ["rsa1024-sha1"]}, "SSH_DH_SHA1"),
    ({"ciphers_c2s": ["3des-cbc"]}, "SSH_WEAK_CIPHER"),
    ({"ciphers_c2s": ["des-cbc"]}, "SSH_WEAK_CIPHER"),
    ({"ciphers_s2c": ["none"]}, "SSH_WEAK_CIPHER"),
    ({"ciphers_c2s": ["idea-cbc"]}, "SSH_WEAK_CIPHER"),
    ({"macs_c2s": ["hmac-md5"]}, "SSH_WEAK_MAC"),
    ({"macs_c2s": ["hmac-md5-etm@openssh.com"]}, "SSH_WEAK_MAC"),
    ({"macs_s2c": ["none"]}, "SSH_WEAK_MAC"),
    ({"host_key_algs": ["ssh-rsa-cert-v01@openssh.com"]}, "SSH_RSA_SHA1"),
    ({"host_key_algs": ["x509v3-sign-rsa"]}, "SSH_RSA_SHA1"),
    ({"host_key_algs": ["x509v3-ssh-dss"]}, "SSH_DSS"),
])
def test_legacy_algorithms_are_flagged(facts, code):
    assert code in _ssh(**facts)["finding_codes"]


def test_none_mac_is_not_reported_as_a_cipher():
    out = _ssh(ciphers_c2s=["aes256-gcm@openssh.com"], macs_c2s=["none"])
    assert "SSH_WEAK_MAC" in out["finding_codes"] and "SSH_WEAK_CIPHER" not in out["finding_codes"]


@pytest.mark.parametrize("kex", ["mlkem768x25519-sha256", "sntrup761x25519-sha512",
                                 "sntrup761x25519-sha512@openssh.com", "mlkem768nistp256-sha256",
                                 "mlkem1024nistp384-sha384", "mlkem512-sha256", "mlkem768-sha256",
                                 "mlkem1024-sha384"])
def test_pq_key_exchanges_count_as_post_quantum(kex):
    """IANA SSH KEX registry (RFC 10042, RFC 9941, draft-harrison) and OpenSSH's alias: each is a PQ KEM."""
    out = _ssh(kex=[kex, "ext-info-s", "kex-strict-s-v00@openssh.com"])
    assert out["quantum_vulnerable"] is False and "SSH_NO_PQ_KEX" not in out["finding_codes"]


@pytest.mark.parametrize("kex", ["curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group16-sha512",
                                 "diffie-hellman-group-exchange-sha256"])
def test_classical_only_key_exchange_is_quantum_vulnerable(kex):
    out = _ssh(kex=[kex, "ext-info-s", "kex-strict-s-v00@openssh.com"])
    assert out["quantum_vulnerable"] is True and "SSH_NO_PQ_KEX" in out["finding_codes"]


def test_old_nodes_single_host_key_is_still_judged():
    out = _ssh(kex=["curve25519-sha256"], host_key={"key_type": "ssh-rsa", "bits": 1024})
    assert "RSA_LT_2048" in out["finding_codes"]


def test_unread_host_keys_coverage_row_keeps_earlier_findings_not_read():
    """The node's coverage row for unread families is scoped to the endpoint and marked incomplete: drift treats the
    listed endpoint's vanished findings as "not read", never resolved."""
    row = SimpleNamespace(asset_type="coverage", target="10.0.0.5", facts={
        "check": "ssh host keys 10.0.0.5:22", "status": "truncated", "scope": ["10.0.0.5:22"], "incomplete": True,
        "detail": "SSH 10.0.0.5:22: host keys not read (rsa-sha2-512): budget"})
    [gap] = job_gaps([row])
    assert gap.target == "10.0.0.5" and gap.prefixes == ("10.0.0.5:22",) and gap.incomplete is True
    assert gap.reason.startswith("SSH 10.0.0.5:22: host keys not read")
