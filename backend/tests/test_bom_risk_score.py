"""Hermetic: BOM risk scores are differentiated (not flat impact-only)."""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.bom_risk_score import (  # noqa: E402
    aibom_finding_risk_score,
    cbom_finding_risk_score,
    sbom_finding_risk_score,
)


def test_cbom_scores_differ_by_finding_codes() -> None:
    weak_proto = cbom_finding_risk_score(
        {
            "impact": "High",
            "finding_codes": ["WEAK_CIPHER_SUITE"],
            "crypto_strength": "weak",
        }
    )
    weak_plus_qv = cbom_finding_risk_score(
        {
            "impact": "High",
            "finding_codes": ["WEAK_KEY_SIZE", "QUANTUM_VULNERABLE"],
            "quantum_vulnerable": True,
            "security_strength_bits": 80,
        }
    )
    clean = cbom_finding_risk_score(
        {"impact": "Low", "finding_codes": [], "crypto_strength": "quantum_safe"}
    )
    assert weak_plus_qv > weak_proto > clean
    assert clean < 3.0
    assert weak_plus_qv <= 10.0


def test_aibom_scores_differ_by_category() -> None:
    theft = aibom_finding_risk_score(
        {
            "impact": "Critical",
            "risk_category": "model_theft_exposure",
            "component_type": "external_provider",
            "license": "unknown",
        }
    )
    license_gap = aibom_finding_risk_score(
        {
            "impact": "Medium",
            "risk_category": "license_compliance_gap",
            "component_type": "ml_framework",
            "license": "MIT",
        }
    )
    inventory = aibom_finding_risk_score(
        {"impact": "Low", "risk_category": "inventory", "component_type": "ml_framework", "license": "Apache-2.0"}
    )
    assert theft > license_gap > inventory


def test_sbom_scores_differ_by_cve_and_reachability() -> None:
    reachable_cve = sbom_finding_risk_score(
        {
            "impact": "High",
            "cves": {"CVE-2024-1": "x", "CVE-2024-2": "y"},
            "reachability": "reachable",
        }
    )
    inventory = sbom_finding_risk_score(
        {
            "impact": "Low",
            "cves": {},
            "reachability": "not_reachable",
            "inventory_only": True,
        }
    )
    assert reachable_cve > inventory
    assert inventory <= 2.0
