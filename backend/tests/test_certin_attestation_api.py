"""Hermetic CERT-In Phase 4 attestation helpers + metadata contract.

No live DB/server. Tests ``apply_evidence_to_compliance`` NBE→PWE flip,
unknown-req gating via ``requirement_ids_in_compliance``, and that
``get_scan_metadata`` surfaces attestations / bom_signature / vex_json.
"""

from __future__ import annotations

import os
import sys
import types

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.compliance.certin_attest import (  # noqa: E402
    apply_evidence_to_compliance,
    evidence_map_from_attestations,
    recompute_compliance_for_scan,
    requirement_ids_in_compliance,
    upsert_attestation,
)
from backend.utilities.dashboard.scan_metadata import get_scan_metadata  # noqa: E402


def _nbe_compliance():
    return {
        "cert_in_cbom": {
            "pass": 0,
            "pass_with_evidence": 0,
            "fail": 1,
            "out_of_scope": 0,
            "not_bom_evidenceable": 2,
            "na": 0,
            "coverage": 0.0,
            "requirements": [
                {
                    "id": "8.4.1.1",
                    "title": "manual",
                    "verdict": "not_bom_evidenceable",
                    "attestable": True,
                },
                {
                    "id": "T9-Algorithms-OID",
                    "title": "oid",
                    "verdict": "not_bom_evidenceable",
                    "attestable": True,
                },
                {"id": "T9-Algorithms-Name", "title": "name", "verdict": "fail"},
            ],
        },
        "disclaimer": "advisory",
    }


def test_apply_evidence_flips_nbe_to_pass_with_evidence() -> None:
    updated = apply_evidence_to_compliance(
        _nbe_compliance(),
        {"cert_in_cbom": {"8.4.1.1": "policy.pdf"}},
    )
    fw = updated["cert_in_cbom"]
    req = next(r for r in fw["requirements"] if r["id"] == "8.4.1.1")
    assert req["verdict"] == "pass_with_evidence"
    assert "policy.pdf" in (req.get("evidence") or "")
    assert fw["not_bom_evidenceable"] == 1
    assert fw["pass_with_evidence"] == 1
    # fail still applicable → coverage = 1/(1+1)
    assert fw["coverage"] == 0.5


def test_apply_evidence_ignores_unknown_requirement() -> None:
    updated = apply_evidence_to_compliance(
        _nbe_compliance(),
        {"cert_in_cbom": {"NOPE": "x.pdf"}},
    )
    assert updated["cert_in_cbom"]["not_bom_evidenceable"] == 2
    assert updated["cert_in_cbom"]["pass_with_evidence"] == 0


def test_requirement_ids_for_unknown_framework_empty() -> None:
    assert requirement_ids_in_compliance(_nbe_compliance(), "missing") == set()
    assert "8.4.1.1" in requirement_ids_in_compliance(
        _nbe_compliance(), "cert_in_cbom"
    )


def test_recompute_compliance_persists_attestations() -> None:
    data = {
        "results": [],
        "cbom_compliance": _nbe_compliance(),
        "cbom_json": {"bomFormat": "CycloneDX", "components": []},
    }
    atts = upsert_attestation(
        None,
        framework="cert_in_cbom",
        requirement_id="8.4.1.1",
        filename="att.pdf",
        note="signed policy",
    )
    out = recompute_compliance_for_scan("cbom", data, atts)
    assert out["attestations"]["cert_in_cbom"]["8.4.1.1"]["filename"] == "att.pdf"
    req = next(
        r
        for r in out["cbom_compliance"]["cert_in_cbom"]["requirements"]
        if r["id"] == "8.4.1.1"
    )
    assert req["verdict"] == "pass_with_evidence"


def test_evidence_map_from_attestations() -> None:
    atts = {
        "cert_in_cbom": {
            "8.4.1.1": {"filename": "a.pdf", "note": "note-text", "uploaded_at": "t"}
        }
    }
    assert evidence_map_from_attestations(atts) == {
        "cert_in_cbom": {"8.4.1.1": "note-text"}
    }


def test_scan_metadata_surfaces_phase4_keys_cbom() -> None:
    from backend.utilities.cbom_sources.vex_semantics import VEX_RULES

    scan = types.SimpleNamespace(
        scan_metadata={"repo_url": "https://ex/r", "branch": "main"},
        scan_data={
            "cbom_json": {"bomFormat": "CycloneDX"},
            "cbom_compliance": {"cert_in_cbom": {"pass": 0}},
            "attestations": {"cert_in_cbom": {"8.4.1.1": {"filename": "a.pdf"}}},
            "bom_signature": {"alg": "HMAC-SHA256", "digest": "abc"},
            "vex_json": {"bomFormat": "CycloneDX", "vulnerabilities": [],
                         "metadata": {"properties": [{"name": "zs:vex_rules", "value": VEX_RULES}]}},
        },
    )
    out = get_scan_metadata("cbom", scan)
    assert out["attestations"]["cert_in_cbom"]["8.4.1.1"]["filename"] == "a.pdf"
    assert out["bom_signature"]["alg"] == "HMAC-SHA256"
    assert out["vex_json"]["bomFormat"] == "CycloneDX"
    # a CBOM VEX stored by older rules is not served from metadata (CB-22): the page fetches /vex, which rebuilds it
    scan.scan_data["vex_json"] = {"bomFormat": "CycloneDX", "vulnerabilities": []}
    assert get_scan_metadata("cbom", scan)["vex_json"] is None


def test_scan_metadata_surfaces_phase4_keys_ai_bom_and_sbom() -> None:
    ai = types.SimpleNamespace(
        scan_metadata={},
        scan_data={
            "ai_bom_compliance": {"cert_in_aibom": {}},
            "attestations": {"cert_in_aibom": {"x": {"filename": "f"}}},
            "bom_signature": {"digest": "d"},
            "vex_json": {"vulnerabilities": []},
        },
    )
    out_ai = get_scan_metadata("ai_bom", ai)
    assert out_ai["attestations"]["cert_in_aibom"]["x"]["filename"] == "f"
    assert out_ai["bom_signature"]["digest"] == "d"
    assert "vulnerabilities" in out_ai["vex_json"]

    sb = types.SimpleNamespace(
        scan_metadata={},
        scan_data={
            "sbom_compliance": {"cert_in_sbom": {}},
            "attestations": {},
            "bom_signature": None,
            "vex_json": {"vulnerabilities": [{"id": "CVE-1"}]},
        },
    )
    out_sb = get_scan_metadata("sbom_sca", sb)
    assert out_sb["vex_json"]["vulnerabilities"][0]["id"] == "CVE-1"
    assert out_sb["attestations"] == {}
