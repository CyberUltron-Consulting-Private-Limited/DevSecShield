"""C5 — CBOM weak-algorithm detection.

The first CBOM story that EMITS flags. Lane discipline: the C1/C2/C3 scanners
INVENTORY crypto assets (``crypto:strength`` / ``crypto:mode`` / ``crypto:keySize``
/ protocol version); this scanner READS that inventory and raises a weak-crypto
``Flag`` (SARIF ``error`` == High impact) per weak asset. The C8 scorer (later)
WEIGHTS the flags; C5 never scores or serializes.

Drives the real CBOM pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over the
hand-labeled ``synthetic-crypto-app`` fixture and asserts the oracle's weak
assets are all flagged and the strong assets are not, plus exercises the
detection predicate directly on synthetic components (SHA-1, RSA<2048, TLS 1.1)
the fixture does not contain.
"""

from __future__ import annotations

import json
import os

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.weakness import WEAK_CRYPTO_CODES, weak_finding
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _manifest() -> dict:
    with open(os.path.join(_FX, "expected_crypto.json")) as fh:
        return json.load(fh)


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _ref_by_name(result: ScanResult, predicate) -> dict[str, str]:
    """Map crypto_asset display-name -> bom_ref for components matching predicate."""
    return {
        c.name: c.bom_ref
        for c in result.components
        if c.kind == "crypto_asset" and predicate(c)
    }


def _flagged_refs(result: ScanResult) -> set[str]:
    return {f.target for f in result.flags if f.code in WEAK_CRYPTO_CODES}


# --------------------------------------------------------------------------- #
# Fixture-level: weak assets all flagged, strong assets never flagged.
# --------------------------------------------------------------------------- #


def test_every_weak_algorithm_in_the_fixture_is_flagged() -> None:
    result = _scan()
    flagged = _flagged_refs(result)
    # The oracle's 5 weak algorithms map onto these detected components
    # (DES is detected via cryptography's TripleDES primitive == 3DES;
    # AES-128-ECB is detected as AES-ECB).
    weak_names = {"3DES-CBC", "AES-ECB", "MD5", "RC4", "RSA-1024"}
    weak_refs = _ref_by_name(result, lambda c: c.name in weak_names)
    assert set(weak_refs) == weak_names, f"missing weak assets: {weak_refs}"
    for name, ref in weak_refs.items():
        assert ref in flagged, f"{name} ({ref}) was not flagged weak"


def test_strong_algorithms_in_the_fixture_are_not_flagged() -> None:
    result = _scan()
    flagged = _flagged_refs(result)
    strong_names = {"RSA-2048", "AES-GCM", "AES", "SHA-256"}
    strong_refs = _ref_by_name(result, lambda c: c.name in strong_names)
    assert strong_names <= set(strong_refs), f"missing strong assets: {strong_refs}"
    for name, ref in strong_refs.items():
        assert ref not in flagged, f"strong {name} ({ref}) was wrongly flagged"


def test_weak_protocol_tls_10_is_flagged() -> None:
    result = _scan()
    flagged = _flagged_refs(result)
    proto = _ref_by_name(
        result,
        lambda c: c.properties.get("crypto:assetType") == "protocol",
    )
    assert "TLS 1.0" in proto
    assert proto["TLS 1.0"] in flagged


_COMMITTED_KEY = "crypto-material-private-key-crypto-app-py"


def test_certificate_and_material_are_not_weak_flagged() -> None:
    # C5 is weak-ALGORITHM detection; certificates / private-key material are
    # not algorithm-weakness findings and must not get weak-crypto flags.
    result = _scan()
    flagged = _flagged_refs(result)
    others = _ref_by_name(
        result,
        lambda c: c.properties.get("crypto:assetType")
        in ("certificate", "related-crypto-material"),
    )
    for name, ref in others.items():
        if ref == _COMMITTED_KEY:  # a PEM private key pasted into source: HARDCODED_KEY (integrator decision)
            assert {f.code for f in result.flags if f.target == ref} == {"HARDCODED_KEY"}
            continue
        assert ref not in flagged, f"{name} ({ref}) wrongly weak-flagged"


def test_flag_count_matches_oracle_weak_total() -> None:
    # 5 weak algorithms + 1 weak protocol = 6 weak-crypto findings; the committed private key's HARDCODED_KEY
    # (integrator decision) is key material, not an algorithm, and is counted on its own.
    result = _scan()
    weak_flags = [f for f in result.flags if f.code in WEAK_CRYPTO_CODES and f.code != "HARDCODED_KEY"]
    assert len(weak_flags) == 6, [f"{f.code}:{f.target}" for f in weak_flags]
    assert [f.target for f in result.flags if f.code == "HARDCODED_KEY"] == [_COMMITTED_KEY]


def test_weak_flags_are_high_severity_error() -> None:
    result = _scan()
    for f in result.flags:
        if f.code in WEAK_CRYPTO_CODES:
            assert f.severity == "error", f"{f.code} should be SARIF error (High)"
            assert f.message, f"{f.code} flag carries no message"


def test_weak_count_matches_manifest_counts() -> None:
    manifest = _manifest()
    result = _scan()
    # the manifest counts algorithms and protocols; the committed private key's HARDCODED_KEY is not one
    weak_flags = [f for f in result.flags if f.code in WEAK_CRYPTO_CODES and f.code != "HARDCODED_KEY"]
    expected = (
        manifest["counts"]["weak_algorithms"]
        + manifest["counts"]["weak_protocols"]
    )
    assert len(weak_flags) == expected


# --------------------------------------------------------------------------- #
# Predicate-level: synthetic components the fixture does not contain.
# --------------------------------------------------------------------------- #


def _algo(name: str, **props) -> CryptoAssetComponent:
    base = {"crypto:assetType": "algorithm"}
    base.update({f"crypto:{k}": str(v) for k, v in props.items()})
    return CryptoAssetComponent(bom_ref=f"x-{name.lower()}", name=name, properties=base)


def test_sha1_is_weak() -> None:
    finding = weak_finding(_algo("SHA-1", strength="weak", primitive="hash"))
    assert finding is not None and finding[0] == "WEAK_ALGORITHM"


def test_3des_moderate_strength_is_still_weak() -> None:
    # 3DES is strength=moderate but in the deprecated corpus — must flag.
    finding = weak_finding(
        _algo("3DES", strength="moderate", primitive="block-cipher")
    )
    assert finding is not None and finding[0] == "WEAK_ALGORITHM"


def test_rsa_below_2048_is_weak_key_size() -> None:
    # A strong-strength RSA with an explicit sub-2048 key size still flags.
    finding = weak_finding(
        _algo("RSA-1536", strength="strong", primitive="pke", keySize=1536)
    )
    assert finding is not None and finding[0] == "WEAK_KEY_SIZE"


def test_rsa_2048_is_not_weak() -> None:
    assert weak_finding(
        _algo("RSA-2048", strength="strong", primitive="pke", keySize=2048)
    ) is None


def test_ecb_mode_on_strong_cipher_is_weak() -> None:
    finding = weak_finding(
        _algo("AES-256-ECB", strength="strong", primitive="block-cipher",
              mode="ECB", keySize=256)
    )
    assert finding is not None and finding[0] == "WEAK_CIPHER_MODE"


def test_gcm_mode_strong_cipher_is_not_weak() -> None:
    assert weak_finding(
        _algo("AES-256-GCM", strength="strong", primitive="ae",
              mode="GCM", keySize=256)
    ) is None


def test_tls_11_protocol_is_weak() -> None:
    comp = CryptoAssetComponent(
        bom_ref="x-tls11",
        name="TLS 1.1",
        properties={
            "crypto:assetType": "protocol",
            "crypto:protocolType": "tls",
            "crypto:protocolVersion": "1.1",
            "crypto:strength": "weak",
        },
    )
    finding = weak_finding(comp)
    assert finding is not None and finding[0] == "WEAK_PROTOCOL"


def test_strong_protocol_tls_13_is_not_weak() -> None:
    comp = CryptoAssetComponent(
        bom_ref="x-tls13",
        name="TLS 1.3",
        properties={
            "crypto:assetType": "protocol",
            "crypto:protocolType": "tls",
            "crypto:protocolVersion": "1.3",
            "crypto:strength": "strong",
        },
    )
    assert weak_finding(comp) is None


def test_weak_flags_target_existing_components() -> None:
    # Every weak-crypto flag must target a real crypto_asset bom_ref (no orphans).
    result = _scan()
    refs = {c.bom_ref for c in result.components}
    for f in result.flags:
        if f.code in WEAK_CRYPTO_CODES:
            assert f.target in refs, f"orphan flag target {f.target}"
