"""Review 6037909737 of #498 (D5 AI BOM), backend majors M3, M4, M5 and M7, through the routes a customer calls:
GET /scan (the results page), GET /export (the PDF) and GET /evidence-pack.

* M3  the results page (scan metadata ``ai_bom_applicability`` and the Compliance Controls chart) shows only the
      frameworks that bind the team, as the PDF and the pack do;
* M4  a team that never declared its regulated entity gets no filter (in-scope healthcare frameworks stay) and the
      reports say "regulated entity not set", never the NBFC default;
* M5  a scan stored before the posture change (29 / B for seven lows) reads 14 / A on the page, as in the PDF;
* M7  the PDF states how many library licences were resolved.

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_aibom_d5_review_6037909737.py -q
"""
from __future__ import annotations

import copy
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests import test_aibom_d5_qa2_profile as PROFILE  # noqa: E402
from backend.tests.test_cbom_consistency import FakeMongo  # noqa: E402

api = PROFILE.api
aibom_api = PROFILE.aibom_api
clinical_payload = PROFILE.clinical_payload
bank_payload = PROFILE.bank_payload
AUTH = PROFILE.AUTH
_HEALTH = {"fda_524b", "hipaa", "gmlp"}


@pytest.fixture()
def page(aibom_api, monkeypatch):
    """GET /scan as the results page calls it (findings in a stand-in Mongo, no chat history)."""
    from backend.routers import scans as scans_router
    from backend.utilities.db import findings as findings_mod

    http, engine, team_id, store = aibom_api
    mongo = FakeMongo()
    monkeypatch.setattr(findings_mod, "get_mongo_client_db", lambda: mongo)
    monkeypatch.setattr(scans_router, "get_mongo_client_db", lambda: mongo)
    monkeypatch.setattr(scans_router, "get_messages_from_scan", lambda **_k: [])
    monkeypatch.setattr("backend.utilities.dashboard.scan.get_db", lambda: engine)

    def get(payload: dict) -> tuple[dict, str]:
        base = store(payload)
        r = http.get(base, headers=AUTH)
        assert r.status_code == 200, r.text[:400]
        return r.json(), base

    return http, engine, team_id, get


def _pack_compliance(http, base: str) -> tuple[dict, bytes]:
    r = http.get(f"{base}/evidence-pack", headers=AUTH)
    assert r.status_code == 200, r.text[:300]
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        return json.loads(zf.read("compliance.json")), zf.read("report.pdf")


# --------------------------------------------------------------------------- M3


def test_bank_results_page_shows_only_binding_frameworks(page, clinical_payload):
    http, engine, team_id, get = page
    PROFILE._team(engine, team_id, "bank")
    body, _base = get(clinical_payload)
    app = body["scan_metadata"]["ai_bom_applicability"]
    assert app["regulatory_profile"]["entity"] == "bank"
    assert not (_HEALTH | {"sebi_cscrf_aibom"}) & set(app["binding"]), app["binding"]
    assert {e["framework"] for e in app["not_applicable"]} >= _HEALTH | {"sebi_cscrf_aibom"}
    # the Compliance Controls chart: no failure count of a framework that does not bind the team
    compliance = body["scan_metadata"]["ai_bom_compliance"]
    dropped = {k for k in _HEALTH | {"sebi_cscrf_aibom"}} | {
        compliance[k].get("title") for k in _HEALTH | {"sebi_cscrf_aibom"} if compliance[k].get("title")}
    controls = (body.get("dashboard") or {}).get("compliance_controls") or {}
    assert not dropped & set(controls), controls


def test_a_sebi_regulated_bank_sees_sebi_cscrf(page, bank_payload):
    http, engine, team_id, get = page
    PROFILE._team(engine, team_id, "bank", sebi_regulated=True)
    body, _base = get(bank_payload)
    assert "sebi_cscrf_aibom" in body["scan_metadata"]["ai_bom_applicability"]["binding"]


# --------------------------------------------------------------------------- M4


def test_an_undeclared_profile_is_no_filter(page, clinical_payload):
    http, _engine, _team_id, get = page  # no CbomCollectionSettings row
    body, base = get(clinical_payload)
    app = body["scan_metadata"]["ai_bom_applicability"]
    assert app["regulatory_profile"] is None and app["basis"] == "regulated entity not set"
    assert _HEALTH <= set(app["binding"]) and app["not_applicable"] == []
    doc, pdf = _pack_compliance(http, base)
    assert _HEALTH <= set(doc) and doc["applicability"]["basis"] == "regulated entity not set"
    text = PROFILE._pdf_text(pdf)
    assert "regulated entity not set" in text and "NBFC" not in text
    assert "FDA Section 524B" in text  # the in-scope healthcare framework is reported


def test_a_settings_row_without_an_entity_is_undeclared(page, clinical_payload):
    from sqlmodel import Session

    from backend.new_models import CbomCollectionSettings

    http, engine, team_id, get = page
    with Session(engine) as session:
        session.add(CbomCollectionSettings(team_id=team_id, aws_external_id="ext-test-0001", risk_model={}))
        session.commit()
    body, _base = get(clinical_payload)
    assert body["scan_metadata"]["ai_bom_applicability"]["regulatory_profile"] is None


# --------------------------------------------------------------------------- M5


def test_a_scan_stored_at_29_b_reads_14_a_on_the_page_and_in_the_pdf(page, bank_payload):
    http, engine, team_id, get = page
    PROFILE._team(engine, team_id, "bank")
    stored = copy.deepcopy(bank_payload)
    stored["ai_bom_scores"] = {**stored["ai_bom_scores"], "risk_normalized": 29.0, "risk_grade": "B",
                               "risk_band": "moderate", "risk_label": "Moderate risk",
                               "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 7}}
    stored["results"] = [r for r in stored["results"]][:7]
    for row in stored["results"]:
        row["impact"] = "Low"
    body, base = get(stored)
    scores = body["scan_metadata"]["ai_bom_scores"]
    assert (scores["risk_normalized"], scores["risk_grade"], scores["risk_band"], scores["risk_label"]) == (
        14.0, "A", "low", "Low risk")
    r = http.get(f"{base}/export", headers=AUTH)
    assert r.status_code == 200
    text = PROFILE._pdf_text(r.content)
    assert "Low risk" in text and "Moderate risk" not in text


# --------------------------------------------------------------------------- M7


def test_the_pdf_states_library_licence_coverage(page, bank_payload):
    http, engine, team_id, get = page
    stored = copy.deepcopy(bank_payload)
    props = stored["ai_bom_json"]["metadata"].setdefault("properties", [])
    props[:] = [p for p in props if not p["name"].startswith("aibom:licence_")] + [
        {"name": "aibom:licence_coverage", "value": "2/6"}, {"name": "aibom:licence_unknown", "value": "4"}]
    stored["results"].append({"title": "vllm", "component_name": "vllm", "component_type": "ml_framework",
                              "component_kind": "framework", "license": "NOASSERTION",
                              "license_status": "unknown", "impact": "Low",
                              "risk_category": "license_compliance_gap", "source": "pypi"})
    body, base = get(stored)
    assert body["dashboard"]["card_data"]["total_licence_unknown_assets"] == 1
    assert body["dashboard"]["card_data"]["total_unlicensed_assets"] == 0  # unknown is not unlicensed
    text = PROFILE._pdf_text(http.get(f"{base}/export", headers=AUTH).content)
    assert "Library licences resolved 2 of 6, 4 unknown" in text
