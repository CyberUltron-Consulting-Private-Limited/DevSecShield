"""CB-18 HF-1: an unidentified algorithm is never quantum-safe in the code lane.

Write time (this package): the DevSecShield row carries ``quantum_safe`` None and
the PQC readiness distribution skips it. Read time (scans stored before CB-18):
backend ``cbom_metrics.code_row_quantum_vulnerable``.
"""

from __future__ import annotations

from aibom.cbom.normalize import _pqc_readiness
from aibom.integrations.cbom_devsecshield import _legacy_quantum_safe
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult


def _algo_row(primitive: str | None, vulnerable: bool) -> dict:
    return {
        "asset_type": "algorithm",
        "primitive": primitive,
        "quantum_vulnerable": vulnerable,
    }


def test_engine_writes_none_for_an_unidentified_algorithm() -> None:
    assert _legacy_quantum_safe(_algo_row("unknown", False)) is None
    assert _legacy_quantum_safe(_algo_row(None, False)) is None
    assert _legacy_quantum_safe(_algo_row("ae", False)) is True
    assert _legacy_quantum_safe(_algo_row("pke", True)) is False


def _algo(name: str, props: dict[str, str]) -> CryptoAssetComponent:
    return CryptoAssetComponent(
        bom_ref=f"r-{name}",
        name=name,
        properties={"crypto:assetType": "algorithm", **props},
    )


def test_readiness_skips_an_unidentified_algorithm() -> None:
    result = ScanResult(subject={"name": "cb18"})
    rsa = _algo(
        "RSA-2048", {"crypto:primitive": "pke", "crypto:quantumVulnerable": "true"}
    )
    odd = _algo(
        "1.3.9999.6.4.13",
        {"crypto:primitive": "unknown", "crypto:strength": "unknown"},
    )
    out = _pqc_readiness([rsa, odd], result)
    assert (out["quantum_vulnerable"], out["quantum_safe"]) == (1, 0)
    assert out["readiness_pct"] == 0.0
    aes = _algo(
        "AES-256-GCM",
        {"crypto:primitive": "ae", "crypto:quantumVulnerable": "false"},
    )
    out = _pqc_readiness([aes], result)
    assert (out["quantum_safe"], out["readiness_pct"]) == (1, 100.0)
