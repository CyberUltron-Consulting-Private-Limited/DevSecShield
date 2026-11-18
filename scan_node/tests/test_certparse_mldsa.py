"""KF-3 / #407: an ML-DSA-65 certificate is named and graded, not stored as 'Unknown OID'.

cryptography's ObjectIdentifier._name is the placeholder 'Unknown OID' for 2.16.840.1.101.3.4.3.18.
That placeholder has no quantum verdict. The certificate is the CB-02 lab z05b leaf.
"""
from __future__ import annotations

import datetime as dt
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from zs_scan_node import algid, certparse

_LAB = Path(__file__).resolve().parents[2] / "e2e/cbom/lab/tests/fixtures/cert-z05b-mldsa.crt.txt"
_ML_DSA_65 = "2.16.840.1.101.3.4.3.18"


def _load(pem: str) -> x509.Certificate:
    return x509.load_der_x509_certificate(ssl.PEM_cert_to_DER_cert(pem))


def test_mldsa65_certificate_is_named_and_quantum_safe():
    facts = certparse.cert_facts(_load(_LAB.read_text()), "tls")
    assert facts["sig_alg"] == "ML-DSA-65"
    assert facts["key_alg"] == "ML-DSA-65"
    assert facts["key_alg_oid"] == _ML_DSA_65
    assert "Unknown OID" not in (facts["sig_alg"], facts["key_alg"])
    assert facts.get("key_size") is None
    assert facts["subject"] == "CN=z05b.lab"
    # the verdict the backend classifier reads: the OID and the name are both quantum-safe
    assert algid.quantum_vulnerable(facts["key_alg"]) is False
    assert algid.quantum_vulnerable(facts["key_alg_oid"]) is False
    assert algid.quantum_vulnerable("Unknown OID") is None


def _signed(key, digest) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "classical.example")])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now.replace(year=2027))
            .sign(key, digest))


def test_classical_certificate_names_stay():
    rsa_facts = certparse.cert_facts(_signed(rsa.generate_private_key(65537, 2048), hashes.SHA256()), "tls")
    assert rsa_facts["key_alg"] == "RSA"
    assert rsa_facts["key_size"] == 2048
    assert rsa_facts["sig_alg"] == "sha256WithRSAEncryption"
    assert "key_alg_oid" not in rsa_facts
    assert algid.quantum_vulnerable(rsa_facts["key_alg"]) is True

    ec_key = ec.generate_private_key(ec.SECP384R1())
    ec_facts = certparse.cert_facts(_signed(ec_key, hashes.SHA384()), "tls")
    assert (ec_facts["key_alg"], ec_facts["key_size"], ec_facts["curve"], ec_facts["sig_alg"]) == (
        "EC", 384, "secp384r1", "ecdsa-with-SHA384")
    assert "key_alg_oid" not in ec_facts
