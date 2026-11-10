"""C6 — CBOM crypto-material MISUSE detection.

Extends the weakness lane beyond the algorithm/certificate/protocol inventory to
*how* crypto material is produced and used: weak RNG (CWE-338), static IV
(CWE-329), reused nonce (CWE-323) and hardcoded key (CWE-321). Lane discipline:
the C6 scanner (:mod:`aibom.cbom.scanners.crypto_misuse_scan`) EMITS enriched
``related-crypto-material`` components carrying the misuse as ``crypto:`` props;
the pure predicate :func:`aibom.cbom.weakness.material_misuse_findings` reads them
into flags (raised by the C5 flag scanner); the C8 scorer weights them.

Drives the real pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over the
hand-labeled ``synthetic-crypto-misuse`` fixture, asserts a negative control
(``good_crypto.py``) raises nothing, proves zero regression on the frozen
``synthetic-crypto-app`` oracle, and exercises the predicate + detector directly.
"""

from __future__ import annotations

import os

from aibom.cbom.misuse import detect_material_misuse
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.weakness import (
    HARDCODED_KEY,
    REUSED_NONCE,
    STATIC_IV,
    WEAK_RNG,
    material_misuse_findings,
)
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-misuse")
_MISUSE_CODES = {WEAK_RNG, STATIC_IV, REUSED_NONCE, HARDCODED_KEY}


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _flag_codes_by_source(result: ScanResult) -> dict[str, set[str]]:
    """misuse flag code -> set of discovery:source files it was raised on."""
    ref_src = {
        c.bom_ref: (c.properties or {}).get("discovery:source")
        for c in result.components
        if c.kind == "crypto_asset"
    }
    out: dict[str, set[str]] = {}
    for f in result.flags:
        if f.code in _MISUSE_CODES:
            out.setdefault(f.code, set()).add(ref_src.get(f.target, ""))
    return out


# --------------------------------------------------------------------------- #
# Fixture-level: every planted misuse is flagged on the right file.
# --------------------------------------------------------------------------- #
def test_static_iv_is_flagged() -> None:
    by_src = _flag_codes_by_source(_scan())
    assert "static_iv.py" in by_src.get(STATIC_IV, set())


def test_reused_nonce_is_flagged() -> None:
    by_src = _flag_codes_by_source(_scan())
    assert "static_iv.py" in by_src.get(REUSED_NONCE, set())


def test_hardcoded_key_is_flagged() -> None:
    by_src = _flag_codes_by_source(_scan())
    assert "hardcoded_key.py" in by_src.get(HARDCODED_KEY, set())


def test_weak_rng_is_flagged_python_and_js() -> None:
    by_src = _flag_codes_by_source(_scan())
    weak_sources = by_src.get(WEAK_RNG, set())
    assert "weak_rng.py" in weak_sources  # random.getrandbits / random.randbytes
    assert "weak_crypto.js" in weak_sources  # Math.random -> IV (cross-language)


def test_reused_supersedes_static_on_same_asset() -> None:
    """The reused nonce is NOT also double-flagged as a plain STATIC_IV."""
    result = _scan()
    reused_targets = {f.target for f in result.flags if f.code == REUSED_NONCE}
    static_targets = {f.target for f in result.flags if f.code == STATIC_IV}
    assert reused_targets
    assert reused_targets.isdisjoint(static_targets)


# --------------------------------------------------------------------------- #
# Negative control: good crypto raises nothing.
# --------------------------------------------------------------------------- #
def test_good_crypto_raises_no_misuse() -> None:
    by_src = _flag_codes_by_source(_scan())
    for sources in by_src.values():
        assert "good_crypto.py" not in sources


def test_non_crypto_random_is_not_flagged() -> None:
    """A game die-roll in a crypto file (weak_rng.py::game_score) is ignored —
    the material-name gate keeps ``roll = random.random()`` out of the lane."""
    result = _scan()
    # exactly three WEAK_RNG (two in weak_rng.py: key + iv; one in the js file);
    # game_score's random.random() must NOT add a fourth.
    weak = [f for f in result.flags if f.code == WEAK_RNG]
    assert len(weak) == 3


# --------------------------------------------------------------------------- #
# Emission: enriched material components + used_by edges.
# --------------------------------------------------------------------------- #
def test_misuse_material_components_carry_props() -> None:
    result = _scan()
    misuse = [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and "misuse" in c.bom_ref
        and (c.properties or {}).get("crypto:assetType") == "related-crypto-material"
    ]
    assert misuse
    generated = {
        (c.properties or {}).get("crypto:generatedBy")
        for c in misuse
        if (c.properties or {}).get("crypto:weakRng") == "true"
    }
    assert "Math.random" in generated
    assert any(g and g.startswith("random.") for g in generated)


def test_misused_material_links_to_cipher() -> None:
    """A static/weak IV records a used_by edge to the cipher it secures."""
    result = _scan()
    misuse_edges = [e for e in result.edges if "misuse" in e.src]
    assert misuse_edges
    for e in misuse_edges:
        assert e.rel == "used_by"
        assert any(c.bom_ref == e.dst for c in result.components)


# --------------------------------------------------------------------------- #
# Predicate + detector units (no fixture, no I/O).
# --------------------------------------------------------------------------- #
def test_predicate_ignores_non_material_component() -> None:
    algo = CryptoAssetComponent(
        bom_ref="a", name="AES-256-GCM",
        properties={"crypto:assetType": "algorithm"},
    )
    assert material_misuse_findings(algo) == []


def test_predicate_reads_props_into_codes() -> None:
    comp = CryptoAssetComponent(
        bom_ref="m", name="nonce (n, x.py)",
        properties={
            "crypto:assetType": "related-crypto-material",
            "crypto:materialKind": "nonce",
            "crypto:staticIv": "true",
            "crypto:reused": "true",
        },
    )
    codes = {c for c, _s, _m in material_misuse_findings(comp)}
    assert codes == {REUSED_NONCE}  # reused supersedes static


def test_detector_requires_crypto_context() -> None:
    """A non-crypto file (no cipher/import context) yields no facts even with a
    weak PRNG assigned to a key-named variable."""
    text = "def f():\n    key = random.randbytes(16)\n    return key\n"
    assert detect_material_misuse(text, "python") == []


def test_detector_excludes_secure_rng() -> None:
    text = (
        "from cryptography.hazmat.primitives.ciphers import Cipher\n"
        "iv = os.urandom(16)\n"
        "key = secrets.token_bytes(32)\n"
    )
    assert detect_material_misuse(text, "python") == []


# --------------------------------------------------------------------------- #
# Regression: the frozen synthetic-crypto-app oracle gains no phantom misuse.
# --------------------------------------------------------------------------- #
def test_no_phantom_misuse_on_frozen_app() -> None:
    app = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
    result = scan_crypto(app)
    # the one misuse is real: the PEM private key pasted into crypto_app.py is a committed key (HARDCODED_KEY,
    # integrator decision); nothing else may be invented on the frozen app
    misuse = [(f.code, f.target) for f in result.flags if f.code in _MISUSE_CODES]
    assert misuse == [("HARDCODED_KEY", "crypto-material-private-key-crypto-app-py")]
