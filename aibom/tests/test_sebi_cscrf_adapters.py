"""Adapter carry-through: SEBI CSCRF blocks on CBOM / AIBOM / SBOM run-objects."""

from __future__ import annotations

import os

from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield
from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.integrations.sbom_devsecshield import enrich_sbom_scan

_HERE = os.path.dirname(os.path.abspath(__file__))
_CRYPTO = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
_AI = os.path.join(_HERE, "..", "examples", "no-phi-model")


def test_cbom_adapter_carries_sebi_cscrf_cbom() -> None:
    run = scan_crypto_to_devsecshield(_CRYPTO)
    fw = run["cbom_compliance"]["sebi_cscrf_cbom"]
    assert fw["requirements"]
    assert "cert_in_cbom" in run["cbom_compliance"]
    assert "nist_800_57" in run["cbom_compliance"]


def test_sbom_adapter_carries_sebi_cscrf_sbom() -> None:
    out = enrich_sbom_scan(
        [
            {
                "dependency": "requests==2.31.0",
                "impact": "Low",
                "reachability": "not_reachable",
                "license_type": "permissive",
                "cves": {},
                "title": "t",
                "description": "d",
                "purl": "pkg:pypi/requests@2.31.0",
            }
        ],
        1.0,
        bom_properties={
            "sbom:author": "DevSecShield",
            "sbom:timestamp": "2026-08-09T12:00:00Z",
            "sbom:vuln_scanner": "grype",
        },
    )
    fw = out["sbom_compliance"]["sebi_cscrf_sbom"]
    assert fw["requirements"]
    assert "ntia_minimum_elements" in out["sbom_compliance"]
    assert "cert_in_sbom" in out["sbom_compliance"]


def test_aibom_adapter_carries_sebi_cscrf_aibom() -> None:
    if not os.path.isdir(_AI):
        return
    run = scan_to_devsecshield(_AI, level=4)
    fw = run["ai_bom_compliance"]["sebi_cscrf_aibom"]
    assert fw["requirements"]
    assert "cert_in_aibom" in run["ai_bom_compliance"]
