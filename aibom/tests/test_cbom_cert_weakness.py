"""C4 — CBOM certificate weakness catalog.

Extends the C5 weak-crypto FLAGGING lane with the certificate-depth verdicts the
inventory could already *describe* but never *graded* (R3 ledger row 14):

* ``WEAK_CERT_SIGNATURE`` — a certificate signed with a collision-broken hash
  (MD2/MD4/MD5/SHA-1);
* ``WEAK_CERT_KEY_SIZE`` — an RSA/DSA certificate key below the 2048-bit floor
  (the algorithm-lane ``WEAK_KEY_SIZE`` skips certs, gating on
  ``assetType == "algorithm"``);
* ``CERT_NEAR_EXPIRY`` — a still-valid certificate inside the rotate-soon warn
  window (a Medium band ahead of the hard High ``EXPIRED_CERTIFICATE``).

The predicate is unit-tested with fixed reference dates (deterministic), and the
real CBOM pipeline is driven over offline-generated weak-certificate fixtures
(``synthetic-crypto-certs/``) parsed by the dependency-free x509 reader — no
mocks, real graph. Certificate weaknesses STACK per cert (a SHA-1 + RSA-1024
cert earns both flags), which the C8 scorer sums into one severity.
"""

from __future__ import annotations

import os
from datetime import date

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.weakness import (
    CERT_NEAR_EXPIRY,
    EXPIRED_CERTIFICATE,
    WEAK_CERT_KEY_SIZE,
    WEAK_CERT_SIGNATURE,
    WEAK_CRYPTO_CODES,
    cert_weakness_findings,
)
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-certs")
_TODAY = date(2026, 7, 1)


def _cert(ref: str, name: str, **props: str) -> CryptoAssetComponent:
    base = {"crypto:assetType": "certificate"}
    base.update(props)
    return CryptoAssetComponent(bom_ref=ref, name=name, properties=base)


def _codes(findings: list[tuple[str, str, str]]) -> set[str]:
    return {code for code, _sev, _msg in findings}


# --- weak signature hash ---------------------------------------------------- #


def test_sha1_signed_cert_is_weak_signature() -> None:
    comp = _cert(
        "c1", "sha1.pem",
        **{"crypto:signatureAlgorithm": "sha1WithRSAEncryption",
           "crypto:publicKeyAlgorithm": "rsaEncryption", "crypto:keySize": "2048"},
    )
    findings = cert_weakness_findings(comp, _TODAY)
    assert _codes(findings) == {WEAK_CERT_SIGNATURE}
    assert all(sev == "error" for _c, sev, _m in findings)


def test_md5_signed_cert_is_weak_signature() -> None:
    comp = _cert("c2", "md5.pem",
                 **{"crypto:signatureAlgorithm": "md5WithRSAEncryption",
                    "crypto:publicKeyAlgorithm": "rsaEncryption",
                    "crypto:keySize": "2048"})
    assert _codes(cert_weakness_findings(comp, _TODAY)) == {WEAK_CERT_SIGNATURE}


def test_md2_raw_oid_signature_is_weak() -> None:
    # md2WithRSAEncryption is left as a raw OID by the x509 reader.
    comp = _cert("c3", "md2.pem",
                 **{"crypto:signatureAlgorithm": "1.2.840.113549.1.1.2",
                    "crypto:publicKeyAlgorithm": "rsaEncryption",
                    "crypto:keySize": "2048"})
    assert _codes(cert_weakness_findings(comp, _TODAY)) == {WEAK_CERT_SIGNATURE}


def test_sha256_signed_cert_is_not_weak_signature() -> None:
    comp = _cert("c4", "ok.pem",
                 **{"crypto:signatureAlgorithm": "sha256WithRSAEncryption",
                    "crypto:publicKeyAlgorithm": "rsaEncryption",
                    "crypto:keySize": "2048"})
    assert cert_weakness_findings(comp, _TODAY) == []


def test_sha512_is_not_confused_for_sha1() -> None:
    comp = _cert("c5", "big.pem",
                 **{"crypto:signatureAlgorithm": "sha512WithRSAEncryption",
                    "crypto:publicKeyAlgorithm": "rsaEncryption",
                    "crypto:keySize": "4096"})
    assert cert_weakness_findings(comp, _TODAY) == []


# --- weak key size (certs are skipped by the algorithm-lane WEAK_KEY_SIZE) --- #


def test_rsa1024_cert_is_weak_key_size() -> None:
    comp = _cert("c6", "rsa1024.pem",
                 **{"crypto:signatureAlgorithm": "sha256WithRSAEncryption",
                    "crypto:publicKeyAlgorithm": "rsaEncryption",
                    "crypto:keySize": "1024"})
    assert _codes(cert_weakness_findings(comp, _TODAY)) == {WEAK_CERT_KEY_SIZE}


def test_rsa2048_cert_is_not_weak_key_size() -> None:
    comp = _cert("c7", "rsa2048.pem",
                 **{"crypto:signatureAlgorithm": "sha256WithRSAEncryption",
                    "crypto:publicKeyAlgorithm": "rsaEncryption",
                    "crypto:keySize": "2048"})
    assert cert_weakness_findings(comp, _TODAY) == []


def test_ec_cert_without_modulus_is_not_weak_key_size() -> None:
    # EC keys are sized by curve, not modulus; the x509 reader sets no keySize.
    comp = _cert("c8", "ec.pem",
                 **{"crypto:signatureAlgorithm": "ecdsaWithSHA256",
                    "crypto:publicKeyAlgorithm": "ecPublicKey"})
    assert cert_weakness_findings(comp, _TODAY) == []


# --- weaknesses STACK on one certificate ------------------------------------ #


def test_sha1_rsa1024_cert_stacks_both_flags() -> None:
    comp = _cert("c9", "legacy.pem",
                 **{"crypto:signatureAlgorithm": "sha1WithRSAEncryption",
                    "crypto:publicKeyAlgorithm": "rsaEncryption",
                    "crypto:keySize": "1024"})
    assert _codes(cert_weakness_findings(comp, _TODAY)) == {
        WEAK_CERT_SIGNATURE, WEAK_CERT_KEY_SIZE,
    }


# --- near-expiry warn band vs hard-expired ---------------------------------- #


def test_cert_within_warn_window_is_near_expiry() -> None:
    comp = _cert("c10", "soon.pem",
                 **{"crypto:notValidAfter": "2026-07-20T00:00:00Z"})
    findings = cert_weakness_findings(comp, _TODAY)
    assert _codes(findings) == {CERT_NEAR_EXPIRY}
    assert all(sev == "warning" for _c, sev, _m in findings)  # Medium


def test_cert_well_before_expiry_is_clean() -> None:
    comp = _cert("c11", "later.pem",
                 **{"crypto:notValidAfter": "2030-01-01T00:00:00Z"})
    assert cert_weakness_findings(comp, _TODAY) == []


def test_expired_cert_is_high_not_near_expiry() -> None:
    comp = _cert("c12", "old.pem",
                 **{"crypto:notValidAfter": "2020-01-01T00:00:00Z"})
    findings = cert_weakness_findings(comp, _TODAY)
    assert _codes(findings) == {EXPIRED_CERTIFICATE}
    assert all(sev == "error" for _c, sev, _m in findings)  # High, not the warn band


def test_near_expiry_stacks_with_weak_signature() -> None:
    comp = _cert("c13", "soon-weak.pem",
                 **{"crypto:notValidAfter": "2026-07-20T00:00:00Z",
                    "crypto:signatureAlgorithm": "sha1WithRSAEncryption",
                    "crypto:publicKeyAlgorithm": "rsaEncryption",
                    "crypto:keySize": "2048"})
    assert _codes(cert_weakness_findings(comp, _TODAY)) == {
        CERT_NEAR_EXPIRY, WEAK_CERT_SIGNATURE,
    }


def test_non_certificate_asset_yields_no_cert_findings() -> None:
    algo = CryptoAssetComponent(
        bom_ref="a1", name="MD5", properties={"crypto:assetType": "algorithm"},
    )
    assert cert_weakness_findings(algo, _TODAY) == []


# --- REAL pipeline over offline weak-cert fixtures (no mocks) ---------------- #


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _flags_on(result: ScanResult, source_substr: str) -> set[str]:
    refs = {
        c.bom_ref
        for c in result.components
        if c.kind == "crypto_asset"
        # the file name itself: "sha1.pem" must not also pick up "rsa1024_sha1.pem"
        and os.path.basename((c.properties or {}).get("discovery:source") or "") == source_substr
    }
    return {f.code for f in result.flags if f.target in refs}


def test_pipeline_flags_rsa1024_cert_weak_key_size() -> None:
    codes = _flags_on(_scan(), "rsa1024.pem")
    assert WEAK_CERT_KEY_SIZE in codes
    assert WEAK_CERT_SIGNATURE not in codes  # it is SHA-256-signed


def test_pipeline_flags_sha1_cert_weak_signature() -> None:
    codes = _flags_on(_scan(), "sha1.pem")
    # sha1.pem is SELF-signed: not a weak signature, CERT_SELF_SIGNED at Low (aligned with the scan node)
    assert WEAK_CERT_SIGNATURE not in codes and "CERT_SELF_SIGNED" in codes
    assert WEAK_CERT_KEY_SIZE not in codes  # it is RSA-2048


def test_pipeline_leaves_strong_cert_unflagged() -> None:
    codes = _flags_on(_scan(), "strong.pem")
    assert not (codes & WEAK_CRYPTO_CODES)
    assert EXPIRED_CERTIFICATE not in codes


def test_pipeline_weak_certs_band_high_in_scores() -> None:
    result = _scan()
    sev = (result.scores or {}).get("component_severity", {})
    for c in result.components:
        src = (c.properties or {}).get("discovery:source") or ""
        if src == "rsa1024.pem":
            assert sev.get(c.bom_ref) == "high", f"{src} should band high (weight 8)"
        if src == "sha1.pem":  # self-signed SHA-1: CERT_SELF_SIGNED only -> low
            assert sev.get(c.bom_ref) == "low", f"{src} self-signed SHA-1 bands low"
