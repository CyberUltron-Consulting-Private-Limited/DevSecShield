"""C8 — CBOM scorer + severity (per-asset flag stacking).

The CBOM scorer is a thin peer of the AIBOM scorer: it weights the crypto flags
(C5 weak-crypto -> high, C6 quantum-vulnerable -> medium, the C8
expired-certificate -> high) into ``ScanResult.scores`` using a SEPARATE
weights file, sharing the stacking + per-component severity machinery. Lane
discipline: scanners EMIT flags, the scorer WEIGHTS them — this never re-detects.

Drives the real CBOM pipeline over the hand-labeled fixture (so ``scan_crypto``
now fills ``scores``), and exercises the severity calibration directly on
synthetic flag sets, including the stacking case (RSA-1024 = weak + q-v).
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.pqc import QUANTUM_VULNERABLE
from aibom.cbom.scorer import score_crypto
from aibom.cbom.weakness import EXPIRED_CERTIFICATE, WEAK_ALGORITHM
from aibom.model.component import CryptoAssetComponent, MetadataComponent
from aibom.model.result import Flag, ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _scored(*flags: Flag, components=()) -> ScanResult:
    r = ScanResult(
        subject=MetadataComponent(name="crypto-app"),
        components=list(components),
        edges=[],
        flags=list(flags),
    )
    score_crypto(r)
    return r


def _algo(ref: str, name: str, **crypto: str) -> CryptoAssetComponent:
    props = {"crypto:assetType": "algorithm"}
    props.update({f"crypto:{k}": v for k, v in crypto.items()})
    return CryptoAssetComponent(bom_ref=ref, name=name, properties=props)


# --------------------------------------------------------------------------- #
# Pipeline: scan_crypto now fills `scores`.
# --------------------------------------------------------------------------- #


def test_scan_crypto_fills_the_scores_seam() -> None:
    result = scan_crypto(_FX)
    assert result.scores, "C8: scan_crypto must populate result.scores"
    for key in (
        "risk_total",
        "risk_normalized",
        "risk_band",
        "by_flag",
        "by_component",
        "component_severity",
        "flag_count",
    ):
        assert key in result.scores, f"missing score key {key}"
    assert result.scores["flag_count"] == len(result.flags)


def test_fixture_component_severity_bands() -> None:
    """On the fixture: weak assets -> high, RSA-2048 (q-v only) -> medium."""
    result = scan_crypto(_FX)
    sev = result.scores["component_severity"]
    by_name = {c.name: c.bom_ref for c in result.components if c.kind == "crypto_asset"}

    # weak crypto -> high
    for name in ("MD5", "RC4", "3DES-CBC", "AES-ECB", "TLS 1.0"):
        assert sev[by_name[name]] == "high", f"{name} should band high"

    # RSA-1024 stacks WEAK_ALGORITHM (8) + QUANTUM_VULNERABLE (4) = 12 -> high
    assert sev[by_name["RSA-1024"]] == "high"
    # RSA-2048 is strong-by-size but quantum-vulnerable (4) -> medium
    assert sev[by_name["RSA-2048"]] == "medium"


# --------------------------------------------------------------------------- #
# Severity calibration (criterion: weak->high, q-v->medium, expired-cert->high).
# --------------------------------------------------------------------------- #


def test_weak_crypto_bands_high() -> None:
    r = _scored(Flag(code=WEAK_ALGORITHM, target="a", severity="error"))
    assert r.scores["component_severity"]["a"] == "high"


def test_quantum_vulnerable_bands_medium() -> None:
    r = _scored(Flag(code=QUANTUM_VULNERABLE, target="a", severity="warning"))
    assert r.scores["component_severity"]["a"] == "medium"


def test_expired_certificate_bands_high() -> None:
    r = _scored(Flag(code=EXPIRED_CERTIFICATE, target="c", severity="error"))
    assert r.scores["component_severity"]["c"] == "high"


def test_per_asset_flags_stack() -> None:
    """Weak (8) + quantum-vulnerable (4) on ONE asset = 12 -> still high (>= 8)."""
    r = _scored(
        Flag(code=WEAK_ALGORITHM, target="rsa", severity="error"),
        Flag(code=QUANTUM_VULNERABLE, target="rsa", severity="warning"),
    )
    assert r.scores["by_component"]["rsa"] == 12.0
    assert r.scores["component_severity"]["rsa"] == "high"


def test_heavy_stacking_reaches_critical() -> None:
    """Expired (8) + weak-key (8) on one cert = 16 -> critical (>= 13)."""
    r = _scored(
        Flag(code=EXPIRED_CERTIFICATE, target="c", severity="error"),
        Flag(code="WEAK_KEY_SIZE", target="c", severity="error"),
    )
    assert r.scores["component_severity"]["c"] == "critical"


def test_clean_asset_has_no_severity_entry() -> None:
    """A flagless strong asset is not in component_severity (inventory floor)."""
    r = _scored(components=[_algo("aes", "AES-GCM", primitive="block-cipher")])
    assert "aes" not in r.scores["component_severity"]
    assert r.scores["flag_count"] == 0


def test_by_flag_aggregates_codes() -> None:
    r = _scored(
        Flag(code=WEAK_ALGORITHM, target="a", severity="error"),
        Flag(code=WEAK_ALGORITHM, target="b", severity="error"),
        Flag(code=QUANTUM_VULNERABLE, target="a", severity="warning"),
    )
    assert r.scores["by_flag"][WEAK_ALGORITHM] == 16.0
    assert r.scores["by_flag"][QUANTUM_VULNERABLE] == 4.0
