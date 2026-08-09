"""Backend contract tests for RBI CSF rollup aggregation."""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.rbi_posture import build_rbi_csf_rollup  # noqa: E402


def _fw_report(req_id: str, verdict: str) -> dict:
    return {
        "rbi_free_ai": {
            "pass": 1 if verdict == "pass" else 0,
            "fail": 1 if verdict == "fail" else 0,
            "out_of_scope": 0,
            "not_bom_evidenceable": 0,
            "na": 0,
            "coverage": 1.0 if verdict == "pass" else 0.0,
            "requirements": [
                {
                    "id": req_id,
                    "title": "test",
                    "source": "test",
                    "verdict": verdict,
                    "evidence": "",
                    "refs": [],
                    "attestable": False,
                }
            ],
        },
        "disclaimer": "advisory",
    }


def test_rollup_maps_governance_requirement() -> None:
    out = build_rbi_csf_rollup(ai_bom_compliance=_fw_report("FREEAI-14", "fail"))
    gov = out["rbi_csf_rollup"]["governance"]
    assert gov["fail"] == 1
    assert gov["coverage"] == 0.0


def test_rollup_merges_multiple_bom_sources() -> None:
    ai = _fw_report("FREEAI-23-1", "pass")
    cb = {
        "rbi_free_ai_protection": {
            "pass": 0,
            "fail": 1,
            "out_of_scope": 0,
            "not_bom_evidenceable": 0,
            "na": 0,
            "coverage": 0.0,
            "requirements": [
                {
                    "id": "FREEAI-PROT-2",
                    "title": "tls",
                    "source": "test",
                    "verdict": "fail",
                    "evidence": "",
                    "refs": [],
                    "attestable": False,
                }
            ],
        },
        "disclaimer": "advisory",
    }
    out = build_rbi_csf_rollup(ai_bom_compliance=ai, cbom_compliance=cb)
    assert out["rbi_csf_rollup"]["identification"]["pass"] == 1
    assert out["rbi_csf_rollup"]["protection"]["fail"] == 1


def test_team_posture_picks_latest_success_scan_per_type() -> None:
    from types import SimpleNamespace

    from backend.utilities.dashboard.rbi_posture import build_team_rbi_posture_from_scans

    older = SimpleNamespace(
        scan_type="ai_bom",
        scan_status="SUCCESS",
        created_at=__import__("datetime").datetime(2025, 1, 1),
        scan_data={"ai_bom_compliance": _fw_report("FREEAI-14", "fail")},
    )
    newer = SimpleNamespace(
        scan_type="ai_bom",
        scan_status="SUCCESS",
        created_at=__import__("datetime").datetime(2026, 1, 1),
        scan_data={"ai_bom_compliance": _fw_report("FREEAI-23-1", "pass")},
    )
    out = build_team_rbi_posture_from_scans([older, newer])
    assert out is not None
    assert out["rbi_csf_rollup"]["identification"]["pass"] == 1


def test_rollup_requirement_carries_evidence_refs_and_hint() -> None:
    blob = {
        "rbi_free_ai_protection": {
            "pass": 0,
            "fail": 1,
            "out_of_scope": 0,
            "not_bom_evidenceable": 0,
            "na": 0,
            "coverage": 0.0,
            "requirements": [
                {
                    "id": "FREEAI-PROT-3",
                    "title": "No hardcoded keys",
                    "source": "FREE-AI §protection",
                    "verdict": "fail",
                    "evidence": "59 hardcoded key(s) detected",
                    "refs": ["crypto-material-misuse-1", "crypto-material-misuse-2"],
                    "attestable": False,
                }
            ],
        },
        "disclaimer": "advisory",
    }
    out = build_rbi_csf_rollup(cbom_compliance=blob)
    req = out["rbi_csf_rollup"]["protection"]["requirements"][0]
    assert req["evidence"] == "59 hardcoded key(s) detected"
    assert req["refs"] == ["crypto-material-misuse-1", "crypto-material-misuse-2"]
    assert req["source"] == "FREE-AI §protection"
    assert req["attestable"] is False
    assert "findings" in req["resolve_hint"].lower()
    assert req["_scanner"] == "cbom"


def test_rollup_nbe_is_attestable_with_resolve_hint() -> None:
    blob = {
        "rbi_free_ai_protection": {
            "pass": 0,
            "fail": 0,
            "out_of_scope": 0,
            "not_bom_evidenceable": 1,
            "na": 0,
            "coverage": None,
            "requirements": [
                {
                    "id": "FREEAI-PROT-7",
                    "title": "Key lifecycle process",
                    "source": "FREE-AI §protection",
                    "verdict": "not_bom_evidenceable",
                    "evidence": "Process control — attach attestation",
                    "refs": [],
                    "attestable": True,
                }
            ],
        },
        "disclaimer": "advisory",
    }
    out = build_rbi_csf_rollup(cbom_compliance=blob)
    # FREEAI-PROT-7 maps to detection in rbi-csf-rollup.yaml
    req = out["rbi_csf_rollup"]["detection"]["requirements"][0]
    assert req["attestable"] is True
    assert req["evidence"].startswith("Process control")
    assert req["refs"] == []
    assert "attestation" in req["resolve_hint"].lower()
    assert req["_scanner"] == "cbom"


def test_rollup_refs_capped_at_50() -> None:
    refs = [f"ref-{i}" for i in range(60)]
    blob = {
        "rbi_free_ai_supply": {
            "pass": 0,
            "fail": 1,
            "out_of_scope": 0,
            "not_bom_evidenceable": 0,
            "na": 0,
            "coverage": 0.0,
            "requirements": [
                {
                    "id": "FREEAI-SUPPLY-1",
                    "title": "Dependency inventory",
                    "source": "test",
                    "verdict": "fail",
                    "evidence": "many deps",
                    "refs": refs,
                    "attestable": False,
                }
            ],
        },
        "disclaimer": "advisory",
    }
    out = build_rbi_csf_rollup(sbom_compliance=blob)
    req = out["rbi_csf_rollup"]["identification"]["requirements"][0]
    assert len(req["refs"]) == 50
    assert req["_scanner"] == "sbom"
