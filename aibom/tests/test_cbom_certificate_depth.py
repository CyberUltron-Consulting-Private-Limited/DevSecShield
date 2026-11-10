"""C4 — certificate DEPTH: EC curve / CA capture, chain edges, weak-cert flags.

Extends the C2 certificate lane (fields + expiry, tested in
``test_cbom_certificate_scan.py``) with the certificate-depth capabilities C4
requires:

* the offline :mod:`aibom.cbom.x509` reader now captures the EC named curve and
  the BasicConstraints ``cA`` flag (in addition to the RSA modulus size);
* the scanner emits ``crypto:curve`` / ``crypto:isCertificateAuthority`` and
  links a CA-signed leaf to its co-located issuer certificate via a ``signed_by``
  edge (the trust chain);
* the weak-crypto lane flags a certificate signed with a broken digest
  (MD5/SHA-1), a certificate with an undersized public key, and a self-signed
  *leaf* certificate — findings that STACK with the expiry finding.

Driven over real, committed X.509 fixtures under ``synthetic-crypto-certs`` (all
generated offline; no OSS tool ships in the product). Lane discipline: the
scanner EMITS facts + edges; the predicates in :mod:`aibom.cbom.weakness` FLAG;
the C8 scorer WEIGHTS.
"""

from __future__ import annotations

import base64
import os
import re
from datetime import date

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.weakness import (
    EXPIRED_CERTIFICATE,
    SELF_SIGNED_LEAF,
    WEAK_CERTIFICATE_KEY,
    WEAK_CERTIFICATE_SIGNATURE,
    cert_expiry_finding,
    certificate_findings,
)
from aibom.cbom.x509 import parse_certificate
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-certs")
_PEM = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", re.DOTALL
)


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _cert_by_source(result: ScanResult, source: str) -> CryptoAssetComponent:
    for c in result.components:
        props = c.properties or {}
        if (
            props.get("crypto:assetType") == "certificate"
            and props.get("discovery:source") == source
        ):
            return c
    raise AssertionError(f"no certificate for source {source!r}")


def _codes_for(result: ScanResult, ref: str) -> set[str]:
    return {f.code for f in result.flags if f.target == ref}


def _parse(name: str):
    with open(os.path.join(_FX, name)) as fh:
        body = _PEM.search(fh.read()).group(1)
    return parse_certificate(base64.b64decode("".join(body.split())))


# --- x509 reader depth (unit) ----------------------------------------------- #


def test_x509_captures_ec_curve_and_size() -> None:
    cert = _parse("ec-p256.crt")
    assert cert is not None
    assert cert.public_key_algorithm == "ecPublicKey"
    assert cert.curve == "P-256"
    assert cert.key_size == 256  # curve field size == comparable key size


def test_x509_captures_basic_constraints_ca() -> None:
    assert _parse("chain-root.crt").is_ca is True
    assert _parse("selfsigned-leaf.crt").is_ca is False
    assert _parse("chain-leaf.crt").is_ca is False


# --- scanner emits new certificate facts ------------------------------------ #


def test_scanner_emits_curve_and_ca_props() -> None:
    ec = _cert_by_source(_scan(), "ec-p256.crt")
    props = ec.properties or {}
    assert props.get("crypto:curve") == "P-256"
    assert props.get("crypto:keySize") == "256"
    assert props.get("crypto:isCertificateAuthority") == "true"


def test_chain_edge_links_leaf_to_issuer() -> None:
    result = _scan()
    leaf = _cert_by_source(result, "chain-leaf.crt")
    root = _cert_by_source(result, "chain-root.crt")
    signed_by = [
        e for e in result.edges if e.src == leaf.bom_ref and e.rel == "signed_by"
    ]
    assert len(signed_by) == 1, f"expected one signed_by edge, got {result.edges}"
    assert signed_by[0].dst == root.bom_ref
    # A self-signed root is its own issuer -> no self-loop edge.
    assert not [e for e in result.edges if e.src == root.bom_ref]


# --- weak-certificate flags (real fixtures, via the pipeline) --------------- #


def test_sha1_signed_cert_flagged() -> None:
    result = _scan()
    cert = _cert_by_source(result, "weak-sha1.crt")
    assert WEAK_CERTIFICATE_SIGNATURE in _codes_for(result, cert.bom_ref)


def test_undersized_key_cert_flagged() -> None:
    result = _scan()
    cert = _cert_by_source(result, "weak-rsa1024.crt")
    assert WEAK_CERTIFICATE_KEY in _codes_for(result, cert.bom_ref)


def test_self_signed_leaf_flagged() -> None:
    result = _scan()
    cert = _cert_by_source(result, "selfsigned-leaf.crt")
    codes = _codes_for(result, cert.bom_ref)
    assert SELF_SIGNED_LEAF in codes
    # A self-signed leaf with a strong SHA-256 signature is not a sig weakness.
    assert WEAK_CERTIFICATE_SIGNATURE not in codes


def test_strong_ca_certs_unflagged() -> None:
    result = _scan()
    for source in ("ec-p256.crt", "chain-root.crt", "chain-leaf.crt"):
        cert = _cert_by_source(result, source)
        assert not _codes_for(result, cert.bom_ref), f"{source} unexpectedly flagged"


# --- predicate purity + stacking (unit) ------------------------------------- #


def _cert_comp(**crypto: str) -> CryptoAssetComponent:
    props = {"crypto:assetType": "certificate", **crypto}
    return CryptoAssetComponent(bom_ref="c", name="x.pem", properties=props)


def test_certificate_findings_stack_all_weaknesses() -> None:
    comp = _cert_comp(
        **{
            "crypto:signatureAlgorithm": "sha1WithRSAEncryption",
            "crypto:publicKeyAlgorithm": "rsaEncryption",
            "crypto:keySize": "1024",
            "crypto:selfSigned": "true",
            "crypto:isCertificateAuthority": "false",
        }
    )
    codes = {c for c, _s, _m in certificate_findings(comp)}
    assert codes == {
        WEAK_CERTIFICATE_SIGNATURE,
        WEAK_CERTIFICATE_KEY,
        SELF_SIGNED_LEAF,
    }
    # ...and stacks on top of expiry (a truly broken, expired, self-signed cert).
    expired = _cert_comp(
        **{
            "crypto:signatureAlgorithm": "md5WithRSAEncryption",
            "crypto:notValidAfter": "2000-01-01T00:00:00Z",
        }
    )
    exp = cert_expiry_finding(expired, date(2026, 6, 29))
    sig = certificate_findings(expired)
    assert exp is not None and exp[0] == EXPIRED_CERTIFICATE
    assert {c for c, _s, _m in sig} == {WEAK_CERTIFICATE_SIGNATURE}


def test_self_signed_weak_signature_text_does_not_claim_forgery() -> None:
    """A self-signed certificate's own signature is never verified (trust anchor), so the text must not say it can be
    forged (the scan-node path does not raise SIG_SHA1 for it at all: owner decision).  A CA-issued one still can."""
    from aibom.cbom.weakness import WEAK_CERT_SIGNATURE, cert_weakness_findings

    sha1 = {"crypto:signatureAlgorithm": "sha1WithRSAEncryption", "crypto:publicKeyAlgorithm": "rsaEncryption",
            "crypto:keySize": "2048"}
    own = _cert_comp(**{**sha1, "crypto:selfSigned": "true"})
    issued = _cert_comp(**{**sha1, "crypto:selfSigned": "false"})
    for findings, code in ((certificate_findings, WEAK_CERTIFICATE_SIGNATURE),
                           (lambda c: cert_weakness_findings(c, date(2026, 6, 29)), WEAK_CERT_SIGNATURE)):
        text = next(m for c, _s, m in findings(own) if c == code)
        assert "can be forged" not in text and "collision-broken hash" not in text
        assert "is self-signed with sha1WithRSAEncryption" in text
        assert "never verify a self-signed certificate's own signature" in text and "SHA-256" in text
        other = next(m for c, _s, m in findings(issued) if c == code)
        assert "self-signed" not in other and ("can be forged" in other or "collision-broken" in other)


def test_certificate_findings_empty_for_strong_ca() -> None:
    strong = _cert_comp(
        **{
            "crypto:signatureAlgorithm": "sha256WithRSAEncryption",
            "crypto:publicKeyAlgorithm": "rsaEncryption",
            "crypto:keySize": "2048",
            "crypto:selfSigned": "true",
            "crypto:isCertificateAuthority": "true",
        }
    )
    assert certificate_findings(strong) == []


def test_certificate_findings_ignores_non_certificate() -> None:
    algo = CryptoAssetComponent(
        bom_ref="a",
        name="MD5",
        properties={"crypto:assetType": "algorithm"},
    )
    assert certificate_findings(algo) == []


def test_ec_undersized_curve_flagged_but_p256_not() -> None:
    weak_ec = _cert_comp(
        **{"crypto:publicKeyAlgorithm": "ecPublicKey", "crypto:curve": "P-192",
           "crypto:keySize": "192"}
    )
    assert {c for c, _s, _m in certificate_findings(weak_ec)} == {WEAK_CERTIFICATE_KEY}
    ok_ec = _cert_comp(
        **{"crypto:publicKeyAlgorithm": "ecPublicKey", "crypto:curve": "P-256",
           "crypto:keySize": "256"}
    )
    assert certificate_findings(ok_ec) == []
