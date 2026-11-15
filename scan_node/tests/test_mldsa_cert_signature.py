"""#407 / KF-3: an ML-DSA-65 certificate's signature is ML-DSA-65, not cryptography's "Unknown OID".

The lab certificate is the CB-02 z05b cert (the same PEM the backend IdP reader already names).
The key algorithm stays the dotted OID: that field is the #93 lab pin, not this row.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from zs_scan_node import certparse

_LAB = (Path(__file__).resolve().parents[2] / "e2e/cbom/lab/tests/fixtures/cert-z05b-mldsa.crt.txt")
_MLDSA = "2.16.840.1.101.3.4.3.18"


def test_mldsa65_signature_is_named():
    cert = x509.load_pem_x509_certificate(_LAB.read_bytes())
    assert cert.signature_algorithm_oid.dotted_string == _MLDSA
    assert cert.signature_algorithm_oid._name == "Unknown OID"
    facts = certparse.cert_facts(cert, "tls")
    assert facts["sig_alg"] == "ML-DSA-65"
    assert facts["key_alg"] == _MLDSA  # public key stays the OID
    assert facts["subject"] == "CN=z05b.lab"


def test_an_oid_algid_does_not_know_stays_the_dotted_oid():
    class _Oid:
        _name = "Unknown OID"
        dotted_string = "1.2.3.4.5.6"

    assert certparse._signature_algorithm(_Oid()) == "1.2.3.4.5.6"


def test_a_known_signature_keeps_cryptography_spelling():
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "known.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    oid = cert.signature_algorithm_oid
    assert certparse.cert_facts(cert, "tls")["sig_alg"] == oid._name
    assert "unknown oid" not in oid._name.lower()
    # the builder is only here to sign; its PEM must still parse
    assert x509.load_pem_x509_certificate(cert.public_bytes(serialization.Encoding.PEM)).serial_number == 1
