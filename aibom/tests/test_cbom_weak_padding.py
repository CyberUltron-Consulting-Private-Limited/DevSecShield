"""C16 — clean-room weak-asymmetric-ENCRYPTION-padding weakness (CWE-780).

RSA encryption under PKCS#1 v1.5 (or textbook/raw) is a chosen-ciphertext /
padding-oracle break (Bleichenbacher, ROBOT). RSA *signatures* under PKCS#1 v1.5
are FIPS 186-5-approved and must NEVER be flagged. The discriminator is the
crypto OPERATION, captured by the C1 detection lane as a new arg-role
(``ROLE_OPERATION``) and read back by the pure ``weak_padding_finding`` predicate.

Coverage:

* **Unit (detect)** — ``ROLE_OPERATION`` resolves ``encrypt`` vs ``sign`` from the
  call line; an ambiguous / operation-less line resolves to ``None``.
* **Unit (predicate)** — ``weak_padding_finding`` fires only on encrypt+pkcs1v15,
  and never on a signature, on OAEP, or on an unknown operation.
* **Integration** — the real pipeline over an isolated ``synthetic-crypto-padding``
  fixture raises exactly one WEAK_PADDING flag (the encrypt case), and NONE on the
  OAEP / signature negative controls.
* **Frozen regression** — ``synthetic-crypto-dataflow`` (its rsa_pkcs1v15_sign) and
  the benchmark oracle ``synthetic-crypto-app`` gain ZERO WEAK_PADDING flags.
"""

from __future__ import annotations

import os

from aibom.cbom.detect import ROLE_OPERATION, detect_crypto
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.weakness import (
    WEAK_CRYPTO_CODES,
    WEAK_PADDING,
    weak_padding_finding,
)
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-padding")
_DATAFLOW_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-dataflow")
_APP_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


# --------------------------------------------------------------------------- #
# Unit — the ROLE_OPERATION resolution in the detection lane.
# --------------------------------------------------------------------------- #


def test_role_operation_constant_is_wired() -> None:
    assert ROLE_OPERATION == "OPERATION"


def test_operation_resolves_encrypt_on_rsa_encryption() -> None:
    dets = detect_crypto("ct = pub.encrypt(m, padding.PKCS1v15())", "python")
    rsa = [d for d in dets if d.key == "rsa"]
    assert rsa and rsa[0].padding == "pkcs1v15" and rsa[0].operation == "encrypt"


def test_operation_resolves_sign_on_rsa_signature() -> None:
    dets = detect_crypto("sig = priv.sign(m, padding.PKCS1v15(), h)", "python")
    rsa = [d for d in dets if d.key == "rsa"]
    assert rsa and rsa[0].padding == "pkcs1v15" and rsa[0].operation == "sign"


def test_operation_is_none_when_ambiguous_or_absent() -> None:
    # padding on its own line, no encrypt/sign token -> operation unknown.
    dets = detect_crypto("pad = padding.PKCS1v15()", "python")
    rsa = [d for d in dets if d.key == "rsa"]
    assert rsa and rsa[0].operation is None


# --------------------------------------------------------------------------- #
# Unit — the pure weak_padding_finding predicate.
# --------------------------------------------------------------------------- #


def _rsa(padding: str | None, operation: str | None) -> CryptoAssetComponent:
    props = {"crypto:assetType": "algorithm", "crypto:primitive": "pke"}
    if padding is not None:
        props["crypto:padding"] = padding
    if operation is not None:
        props["crypto:operation"] = operation
    return CryptoAssetComponent(bom_ref="rsa-x", name="RSA", properties=props)


def test_predicate_flags_pkcs1v15_encryption() -> None:
    finding = weak_padding_finding(_rsa("pkcs1v15", "encrypt"))
    assert finding is not None and finding[0] == WEAK_PADDING
    assert finding[1] == "error"  # High impact


def test_predicate_never_flags_pkcs1v15_signature() -> None:
    assert weak_padding_finding(_rsa("pkcs1v15", "sign")) is None


def test_predicate_never_flags_oaep_encryption() -> None:
    assert weak_padding_finding(_rsa("oaep", "encrypt")) is None


def test_predicate_never_flags_unknown_operation() -> None:
    # Conservative: without proven encryption, no flag (avoids signature FPs).
    assert weak_padding_finding(_rsa("pkcs1v15", None)) is None


def test_predicate_ignores_non_pke_and_non_algorithm() -> None:
    aes = CryptoAssetComponent(
        bom_ref="aes-x",
        name="AES-256",
        properties={
            "crypto:assetType": "algorithm",
            "crypto:primitive": "block-cipher",
            "crypto:padding": "pkcs1v15",
            "crypto:operation": "encrypt",
        },
    )
    assert weak_padding_finding(aes) is None


def test_weak_padding_in_weak_crypto_codes() -> None:
    assert WEAK_PADDING in WEAK_CRYPTO_CODES


# --------------------------------------------------------------------------- #
# Integration — the real pipeline over the isolated fixture.
# --------------------------------------------------------------------------- #


def _padding_flag_refs(result: ScanResult) -> set[str]:
    return {f.target for f in result.flags if f.code == WEAK_PADDING}


def _asset_ref_by_source(result: ScanResult, source: str) -> str:
    for c in result.components:
        props = c.properties or {}
        if (
            c.kind == "crypto_asset"
            and props.get("crypto:assetType") == "algorithm"
            and props.get("discovery:source") == source
        ):
            return c.bom_ref
    raise AssertionError(f"no algorithm asset from source {source!r}")


def test_fixture_flags_only_the_encrypt_case() -> None:
    result = scan_crypto(_FX)
    refs = _padding_flag_refs(result)
    assert len(refs) == 1, f"expected exactly one WEAK_PADDING flag, got {refs}"
    encrypt_ref = _asset_ref_by_source(result, "rsa_pkcs1v15_encrypt.py")
    assert refs == {encrypt_ref}


def test_fixture_does_not_flag_oaep_or_signature() -> None:
    result = scan_crypto(_FX)
    refs = _padding_flag_refs(result)
    assert _asset_ref_by_source(result, "rsa_oaep_encrypt.py") not in refs
    assert _asset_ref_by_source(result, "rsa_pkcs1v15_sign.py") not in refs


def test_encrypt_asset_carries_operation_property() -> None:
    result = scan_crypto(_FX)
    ref = _asset_ref_by_source(result, "rsa_pkcs1v15_encrypt.py")
    comp = result.by_ref(ref)
    assert comp is not None
    props = comp.properties or {}
    assert props.get("crypto:padding") == "pkcs1v15"
    assert props.get("crypto:operation") == "encrypt"


# --------------------------------------------------------------------------- #
# Frozen regression — the deferred-from-C6 constraint.
# --------------------------------------------------------------------------- #


def test_frozen_dataflow_pkcs1v15_signature_not_flagged() -> None:
    """The reason C16 was split out of C6: the frozen synthetic-crypto-dataflow
    rsa_pkcs1v15_sign is a signature, and must NEVER earn a WEAK_PADDING flag."""
    assert _padding_flag_refs(scan_crypto(_DATAFLOW_FX)) == set()


def test_frozen_benchmark_oracle_unchanged() -> None:
    assert _padding_flag_refs(scan_crypto(_APP_FX)) == set()
