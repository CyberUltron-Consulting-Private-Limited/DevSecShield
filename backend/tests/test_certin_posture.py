"""Backend contract tests for CERT-In posture rollup aggregation."""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.certin_posture import (  # noqa: E402
    build_certin_posture,
    build_team_certin_posture_from_scans,
)


def _fw_report(framework: str, req_id: str, verdict: str) -> dict:
    return {
        framework: {
            "pass": 1 if verdict == "pass" else 0,
            "pass_with_evidence": 1 if verdict == "pass_with_evidence" else 0,
            "fail": 1 if verdict == "fail" else 0,
            "out_of_scope": 0,
            "not_bom_evidenceable": 1 if verdict == "not_bom_evidenceable" else 0,
            "na": 0,
            "coverage": 1.0 if verdict in ("pass", "pass_with_evidence") else 0.0,
            "requirements": [
                {
                    "id": req_id,
                    "title": "test",
                    "source": "test",
                    "verdict": verdict,
                    "evidence": "",
                    "refs": [],
                    "attestable": verdict == "not_bom_evidenceable",
                }
            ],
        },
        "disclaimer": "advisory",
    }


def test_maps_t5_into_sbom_minimum_elements() -> None:
    out = build_certin_posture(
        sbom_compliance=_fw_report("cert_in_sbom", "T5-Component-Name", "fail")
    )
    assert out is not None
    dim = out["certin_posture"]["sbom_minimum_elements"]
    assert dim["fail"] == 1
    assert dim["coverage"] == 0.0


def test_maps_manual_into_cbom_recommendations() -> None:
    out = build_certin_posture(
        cbom_compliance=_fw_report(
            "cert_in_cbom", "8.4.1.1", "not_bom_evidenceable"
        )
    )
    assert out is not None
    dim = out["certin_posture"]["cbom_recommendations"]
    assert dim["not_bom_evidenceable"] == 1
    assert dim["coverage"] is None  # NBE not in pass/fail coverage
    req = dim["requirements"][0]
    assert req["id"] == "8.4.1.1"
    assert req["attestable"] is True
    assert req["resolve_hint"]
    assert "attestation" in req["resolve_hint"].lower()
    assert req["source"] == "test"
    # Read-time ledger overlay replaces placeholder scan titles.
    assert req["title"] == "Require CBOM in procurements"
    assert "Attest that CBOM" in (req.get("evidence") or "")


def test_posture_requirement_carries_evidence_and_refs() -> None:
    blob = {
        "cert_in_cbom": {
            "pass": 0,
            "pass_with_evidence": 0,
            "fail": 0,
            "out_of_scope": 0,
            "not_bom_evidenceable": 1,
            "na": 0,
            "coverage": None,
            "requirements": [
                {
                    "id": "T9-Algorithms-Mode",
                    "title": "Algorithm Mode",
                    "source": "Table 9 / Algorithms / Mode",
                    "verdict": "not_bom_evidenceable",
                    "evidence": "crypto:mode not present on algorithm assets",
                    "refs": ["crypto-algo-rsa-1", "crypto-algo-aes-2"],
                    "attestable": False,
                }
            ],
        },
        "disclaimer": "advisory",
    }
    out = build_certin_posture(cbom_compliance=blob)
    assert out is not None
    req = out["certin_posture"]["cbom_crypto_assets"]["requirements"][0]
    assert req["evidence"].startswith("crypto:mode")
    assert req["refs"] == ["crypto-algo-rsa-1", "crypto-algo-aes-2"]
    assert "findings" in req["resolve_hint"].lower()
    assert req["source"] == "Table 9 / Algorithms / Mode"

def test_ignores_non_cert_in_frameworks() -> None:
    blob = _fw_report("nist_800_57", "KM-1", "fail")
    assert build_certin_posture(cbom_compliance=blob) is None


def test_merges_multiple_bom_sources() -> None:
    sb = _fw_report("cert_in_sbom", "T5-Component-Version", "pass")
    cb = _fw_report("cert_in_cbom", "T9-Algorithms-Name", "fail")
    ai = _fw_report("cert_in_aibom", "T10-Model-Name", "pass")
    out = build_certin_posture(
        sbom_compliance=sb, cbom_compliance=cb, ai_bom_compliance=ai
    )
    assert out is not None
    assert out["certin_posture"]["sbom_minimum_elements"]["pass"] == 1
    assert out["certin_posture"]["cbom_crypto_assets"]["fail"] == 1
    assert out["certin_posture"]["aibom_ai_assets"]["pass"] == 1
    assert "CERT-In" in out["disclaimer"]
    assert "HBOM" in out["hbom_note"]


def test_pass_with_evidence_counts_toward_coverage() -> None:
    out = build_certin_posture(
        cbom_compliance=_fw_report(
            "cert_in_cbom", "8.4.1.1", "pass_with_evidence"
        )
    )
    dim = out["certin_posture"]["cbom_recommendations"]
    assert dim["pass_with_evidence"] == 1
    assert dim["coverage"] == 1.0


def test_empty_compliance_returns_none() -> None:
    assert build_certin_posture() is None
    assert build_certin_posture(cbom_compliance={"disclaimer": "x"}) is None


def test_team_posture_picks_latest_success_scan_per_type() -> None:
    older = SimpleNamespace(
        scan_type="cbom",
        scan_status="success",
        created_at="2020-01-01",
        scan_data={
            "cbom_compliance": _fw_report(
                "cert_in_cbom", "T9-Algorithms-Name", "fail"
            )
        },
    )
    newer = SimpleNamespace(
        scan_type="cbom",
        scan_status="SUCCESS",
        created_at="2026-01-01",
        scan_data={
            "cbom_compliance": _fw_report(
                "cert_in_cbom", "T9-Algorithms-Name", "pass"
            )
        },
    )
    out = build_team_certin_posture_from_scans([older, newer])
    assert out is not None
    assert out["certin_posture"]["cbom_crypto_assets"]["pass"] == 1
    assert out["certin_posture"]["cbom_crypto_assets"]["fail"] == 0


def test_team_posture_skips_non_success() -> None:
    pending = SimpleNamespace(
        scan_type="cbom",
        scan_status="not_started",
        created_at="2026-01-01",
        scan_data={
            "cbom_compliance": _fw_report(
                "cert_in_cbom", "T9-Algorithms-Name", "pass"
            )
        },
    )
    assert build_team_certin_posture_from_scans([pending]) is None
