"""C1 — Python-AST crypto-API scanner (argument binding + detection-rule model).

These tests pin the capabilities a flat line-regex CANNOT have: cross-statement
value following, nested-call argument binding (mode / padding), keyword-argument
work-factor capture, and related-crypto-material from literal IV / salt. They
drive the REAL pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over a fixture
whose every asset is resolvable only by following the AST — never a mocked graph.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-ast")
_SHARED = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _scan(path: str = _FX) -> ScanResult:
    return scan_crypto(path)


def _algorithms(result: ScanResult) -> dict[str, dict]:
    """name -> properties, for every AST-detected algorithm asset."""
    return {
        c.name: (c.properties or {})
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
        and (c.properties or {}).get("crypto:detectionMethod") == "ast"
    }


def _materials(result: ScanResult) -> dict[str, dict]:
    return {
        (c.properties or {}).get("crypto:materialKind"): (c.properties or {})
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "related-crypto-material"
        and (c.properties or {}).get("crypto:detectionMethod") == "ast"
    }


# --------------------------------------------------------------------------- #
# Cross-statement value following — the headline capability.
# --------------------------------------------------------------------------- #


def test_rsa_key_size_resolved_across_statements() -> None:
    """``RSA_BITS = 3072`` then ``key_size=RSA_BITS`` -> RSA-3072 (the call line
    carries no digit; only argument binding + const-following resolves it)."""
    algos = _algorithms(_scan())
    assert "RSA-3072" in algos, f"AST algorithms: {sorted(algos)}"
    assert algos["RSA-3072"]["crypto:keySize"] == "3072"
    assert algos["RSA-3072"]["crypto:primitive"] == "pke"


def test_aes_mode_bound_from_nested_call() -> None:
    """``Cipher(algorithms.AES(k), modes.CBC(iv))`` binds AES + CBC from the
    nested constructor calls."""
    algos = _algorithms(_scan())
    assert "AES-CBC" in algos
    assert algos["AES-CBC"]["crypto:mode"] == "CBC"


def test_kdf_work_factor_captured_from_kwarg() -> None:
    """PBKDF2's ``iterations=`` keyword (a cross-statement constant) is captured
    as ``crypto:iterations`` — the parameter C17 later weights."""
    algos = _algorithms(_scan())
    assert "PBKDF2" in algos
    assert algos["PBKDF2"]["crypto:iterations"] == "100000"


def test_asymmetric_padding_bound_within_scope() -> None:
    """The ``padding.OAEP(...)`` argument of ``.encrypt`` binds to the RSA asset
    generated in the same function scope."""
    algos = _algorithms(_scan())
    assert algos["RSA-3072"].get("crypto:padding") == "OAEP"


# --------------------------------------------------------------------------- #
# Related-crypto-material from literals.
# --------------------------------------------------------------------------- #


def test_static_iv_emitted_as_related_material() -> None:
    """A literal IV bound to ``modes.CBC`` is inventoried as an
    initialization-vector related-crypto-material asset."""
    mats = _materials(_scan())
    assert "initialization-vector" in mats


def test_kdf_salt_emitted_as_related_material() -> None:
    mats = _materials(_scan())
    assert "salt" in mats


# --------------------------------------------------------------------------- #
# Detection-rule provenance: every AST asset names the library + context.
# --------------------------------------------------------------------------- #


def test_every_ast_asset_carries_detection_provenance() -> None:
    algos = _algorithms(_scan())
    assert algos, "no AST algorithms detected"
    for name, props in algos.items():
        assert props.get("crypto:detectedBy"), f"{name} missing crypto:detectedBy"
        assert props.get("crypto:detectionContext"), f"{name} missing context"
        assert props.get("crypto:confidence") == "high", name


# --------------------------------------------------------------------------- #
# Shared-fixture parity + determinism (no regression on the C1 oracle).
# --------------------------------------------------------------------------- #


def test_shared_fixture_algorithms_are_ast_detected() -> None:
    """On the hand-labeled oracle, the AST scanner is the authority for every
    Python algorithm usage (the pipeline keeps the richer AST component)."""
    algos = _algorithms(_scan(_SHARED))
    names = set(algos)
    assert {"RSA-2048", "RSA-1024", "AES-GCM", "AES-ECB", "MD5", "SHA-256"} <= names


def test_shared_fixture_static_iv_now_inventoried() -> None:
    """The AST scanner adds the static CBC IV the regex scanner never emitted."""
    mats = _materials(_scan(_SHARED))
    assert "initialization-vector" in mats


def test_scan_is_deterministic() -> None:
    a = _scan()
    b = _scan()
    refs_a = [(c.kind, c.bom_ref) for c in a.components]
    refs_b = [(c.kind, c.bom_ref) for c in b.components]
    assert refs_a == refs_b


def test_ast_scanner_does_not_leak_into_aibom_pipeline() -> None:
    from aibom.scan.registry import SCANNERS

    assert not any(s.name == "crypto_ast" for s in SCANNERS)
