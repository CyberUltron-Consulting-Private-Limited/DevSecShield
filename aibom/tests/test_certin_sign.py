"""Hermetic tests for CERT-In HMAC signing (stdlib)."""

from __future__ import annotations

from aibom.compliance.cert_in.sign import (
    canonical_bom_bytes,
    sign_bom,
    verify_signature,
)

_SECRET = b"test-certin-hmac-secret"
_BOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "a"}]}


def test_canonical_bytes_stable() -> None:
    a = canonical_bom_bytes({"z": 1, "a": {"b": 2}})
    b = canonical_bom_bytes({"a": {"b": 2}, "z": 1})
    assert a == b
    assert a.startswith(b"{")


def test_sign_verify_roundtrip() -> None:
    sig = sign_bom(_BOM, secret=_SECRET)
    assert sig["alg"] == "HMAC-SHA256"
    assert sig["key_id"] == "certin-hmac-1"
    assert sig["signature_b64"]
    assert sig["digest"]
    assert sig["signed_at"]
    assert verify_signature(_BOM, sig, secret=_SECRET) is True


def test_tamper_fails_verify() -> None:
    sig = sign_bom(_BOM, secret=_SECRET)
    tampered = {**_BOM, "components": [{"name": "b"}]}
    assert verify_signature(tampered, sig, secret=_SECRET) is False


def test_wrong_secret_fails() -> None:
    sig = sign_bom(_BOM, secret=_SECRET)
    assert verify_signature(_BOM, sig, secret=b"other-secret") is False


def test_empty_secret_raises() -> None:
    try:
        sign_bom(_BOM, secret=b"")
        assert False, "expected ValueError"
    except ValueError:
        pass
