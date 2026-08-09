"""Hermetic: scan_metadata surfaces live-computed certin_posture for BOM types.

Lane scoping: a single-scan posture emits only that BOM's dimensions (no
cross-BOM AIBOM rows on an SBOM page, etc.).
"""

from __future__ import annotations

import os
import sys
import types

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.certin_posture import (  # noqa: E402
    build_certin_posture,
    build_team_certin_posture_from_scans,
)
from backend.utilities.dashboard.scan_metadata import get_scan_metadata  # noqa: E402

_CBOM_DIMS = frozenset({"cbom_crypto_assets", "cbom_recommendations"})
_SBOM_DIMS = frozenset({"sbom_minimum_elements", "sbom_recommendations"})
_AIBOM_DIMS = frozenset({"aibom_ai_assets", "aibom_recommendations"})


def _scan(scan_metadata=None, scan_data=None):
    return types.SimpleNamespace(
        scan_metadata=scan_metadata or {}, scan_data=scan_data or {}
    )


def _cert_fw(fw_key: str, req_id: str, verdict: str = "fail") -> dict:
    return {
        fw_key: {
            "pass": 0 if verdict != "pass" else 1,
            "fail": 1 if verdict == "fail" else 0,
            "not_bom_evidenceable": 0,
            "pass_with_evidence": 0,
            "na": 0,
            "out_of_scope": 0,
            "coverage": 0.0,
            "requirements": [
                {"id": req_id, "title": req_id, "verdict": verdict},
            ],
        }
    }


def test_cbom_metadata_surfaces_certin_posture() -> None:
    data = {"cbom_compliance": _cert_fw("cert_in_cbom", "T9-Algorithms-Name")}
    out = get_scan_metadata("cbom", _scan({}, data))
    assert out.get("certin_posture")
    posture = out["certin_posture"]["certin_posture"]
    assert posture["cbom_crypto_assets"]["fail"] == 1
    assert set(posture) <= _CBOM_DIMS
    assert not (set(posture) & (_SBOM_DIMS | _AIBOM_DIMS))


def test_sbom_metadata_posture_keys_are_sbom_only() -> None:
    data = {"sbom_compliance": _cert_fw("cert_in_sbom", "T5-Component-Name")}
    out = get_scan_metadata("sbom_sca", _scan({}, data))
    assert out.get("certin_posture")
    keys = set(out["certin_posture"]["certin_posture"])
    assert keys <= _SBOM_DIMS
    assert not (keys & (_CBOM_DIMS | _AIBOM_DIMS))


def test_aibom_metadata_posture_keys_are_aibom_only() -> None:
    data = {"ai_bom_compliance": _cert_fw("cert_in_aibom", "T10-Model-Name")}
    out = get_scan_metadata("ai_bom", _scan({}, data))
    assert out.get("certin_posture")
    keys = set(out["certin_posture"]["certin_posture"])
    assert keys <= _AIBOM_DIMS
    assert not (keys & (_CBOM_DIMS | _SBOM_DIMS))


def test_build_certin_posture_single_lane_omits_other_dims() -> None:
    posture = build_certin_posture(
        cbom_compliance=_cert_fw("cert_in_cbom", "T9-Algorithms-Name")
    )
    assert posture is not None
    keys = set(posture["certin_posture"])
    assert keys == _CBOM_DIMS or keys <= _CBOM_DIMS
    assert "aibom_ai_assets" not in keys
    assert "sbom_minimum_elements" not in keys


def test_team_builder_merges_two_lanes() -> None:
    scans = [
        types.SimpleNamespace(
            scan_type="cbom",
            scan_status="SUCCESS",
            created_at="2026-01-02",
            scan_data={"cbom_compliance": _cert_fw("cert_in_cbom", "T9-Algorithms-Name")},
        ),
        types.SimpleNamespace(
            scan_type="sbom_sca",
            scan_status="SUCCESS",
            created_at="2026-01-02",
            scan_data={"sbom_compliance": _cert_fw("cert_in_sbom", "T5-Component-Name")},
        ),
    ]
    posture = build_team_certin_posture_from_scans(scans)
    assert posture is not None
    keys = set(posture["certin_posture"])
    assert keys & _CBOM_DIMS
    assert keys & _SBOM_DIMS
    assert not (keys & _AIBOM_DIMS)


def test_legacy_cbom_without_cert_in_has_null_posture() -> None:
    out = get_scan_metadata(
        "cbom",
        _scan({}, {"cbom_compliance": {"nist_800_57": {"pass": 1, "requirements": []}}}),
    )
    assert out.get("certin_posture") is None
