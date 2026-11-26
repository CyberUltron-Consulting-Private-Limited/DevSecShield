"""Staging QA round 2, Q2-08: the AI BOM's compliance.json (evidence pack) and its PDF report show only the
frameworks that bind the team's regulatory profile (``regulated_entity.team_profile``, #485).

The payloads are the engine's own output (``scan_to_devsecshield``) for two fixtures: the bank model router
(``aibom/tests/fixtures/aibom-bank-router``) and the clinical imaging example (``aibom/examples/clinical-imaging``,
whose healthcare frameworks are in scope). They go through the routes a customer calls: GET /export and GET
/evidence-pack.

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_aibom_d5_qa2_profile.py -q
"""
from __future__ import annotations

import io
import json
import pathlib
import re
import sys
import types
import zipfile

import pytest
from sqlmodel import Session

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from backend.tests import test_pdf_export_route as EXPORT  # noqa: E402
from backend.utilities.compliance import aibom_applicability as APPLICABILITY  # noqa: E402

api = EXPORT.api  # the hermetic SQLite + TestClient fixture of the export route tests
AUTH = {"Authorization": "Bearer test"}
_ROOT = pathlib.Path(__file__).resolve().parents[2]
_AIBOM_SRC = _ROOT / "aibom" / "src"
_BANK = _ROOT / "aibom" / "tests" / "fixtures" / "aibom-bank-router"
_CLINICAL = _ROOT / "aibom" / "examples" / "clinical-imaging"
# requirement rows of the healthcare frameworks (524B-1, HIPAA-4, GMLP-2 …)
_HEALTH_REQUIREMENT = re.compile(r"\b(?:524B|HIPAA|GMLP)-\d+\b")


def _engine(path: pathlib.Path) -> dict:
    pytest.importorskip("pydantic")
    saved = {k: sys.modules.pop(k) for k in list(sys.modules) if k == "aibom" or k.startswith("aibom.")}
    sys.path.insert(0, str(_AIBOM_SRC))
    try:
        try:
            from aibom.integrations.devsecshield import scan_to_devsecshield
        except ImportError as exc:  # the backend environment without the engine's dependencies
            pytest.skip(f"aibom engine not importable here: {exc}")
        return scan_to_devsecshield(path, level=4)
    finally:
        sys.path.remove(str(_AIBOM_SRC))
        for k in [k for k in sys.modules if k == "aibom" or k.startswith("aibom.")]:
            del sys.modules[k]
        sys.modules.update(saved)


@pytest.fixture(scope="module")
def bank_payload() -> dict:
    return _engine(_BANK)


@pytest.fixture(scope="module")
def clinical_payload() -> dict:
    return _engine(_CLINICAL)


def _team(engine, team_id: int, entity: str, **flags) -> None:
    from backend.new_models import CbomCollectionSettings

    with Session(engine) as session:
        session.add(CbomCollectionSettings(team_id=team_id, aws_external_id="ext-test-0000",
                                           risk_model={"regulated_entity": entity, **flags}))
        session.commit()


@pytest.fixture()
def aibom_api(api, monkeypatch):
    from backend.new_models import Scan
    from backend.routers import scans as scans_router

    http, ids = api
    engine = scans_router.get_db()

    async def fake_user(*_a, **_k):
        return types.SimpleNamespace(id=ids["user_id"])

    monkeypatch.setattr("backend.routers.certin.get_db", lambda: engine)
    monkeypatch.setattr("backend.routers.certin.check_if_user_is_in_team", lambda *_a, **_k: None)
    monkeypatch.setattr("backend.routers.certin.get_user_from_header_or_raise_exception", fake_user)
    scan_id = ids["scan_ids"]["ai_bom"]

    def store(payload: dict) -> str:
        with Session(engine) as session:
            scan = session.get(Scan, scan_id)
            scan.scan_data = json.loads(json.dumps(payload))
            scan.scan_metadata = {"repo_url": "https://github.com/acme/router.git", "branch": "main"}
            session.add(scan)
            session.commit()
        return f"/{ids['team_id']}/ai_bom/scan/{scan_id}"

    return http, engine, ids["team_id"], store


def _pdf_text(body: bytes) -> str:
    pypdf = pytest.importorskip("pypdf")
    reader = pypdf.PdfReader(io.BytesIO(body))
    return " ".join(" ".join(page.extract_text() or "" for page in reader.pages).split())


def _pack(http, base: str) -> dict[str, bytes]:
    r = http.get(f"{base}/evidence-pack", headers=AUTH)
    assert r.status_code == 200, r.text
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


# --------------------------------------------------------------------------- unit: who each framework binds


def test_a_bank_profile_binds_no_healthcare_framework(clinical_payload):
    compliance = clinical_payload["ai_bom_compliance"]
    assert {"fda_524b", "hipaa", "gmlp"} <= set(compliance)  # the engine keeps every framework
    bank = {"jurisdiction": "IN", "entity": "bank", "flags": []}
    kept, dropped = APPLICABILITY.split(compliance, bank)
    assert not {"fda_524b", "hipaa", "gmlp"} & set(kept)
    assert {"fda_524b", "hipaa", "gmlp", "sebi_cscrf_aibom"} <= set(dropped)
    assert {"cert_in_aibom", "rbi_free_ai", "nist_rmf", "eu_ai_act_annexIV"} <= set(kept)


def test_profiles_follow_the_knowledge_base_rules(clinical_payload):
    compliance = clinical_payload["ai_bom_compliance"]
    other = {"jurisdiction": "IN", "entity": "other", "flags": []}
    kept, _ = APPLICABILITY.split(compliance, other)
    assert "rbi_free_ai" not in kept  # RBI binds RBI-regulated entities only
    assert "fda_524b" in kept  # an "other" entity with a clinical model in scope keeps it
    sebi = {"jurisdiction": "IN", "entity": "nbfc", "flags": ["sebi_regulated"]}
    assert "sebi_cscrf_aibom" in APPLICABILITY.split(compliance, sebi)[0]
    # no profile (an offline render): the scan-scope rule alone, as before
    assert "fda_524b" in APPLICABILITY.split(compliance, None)[0]


# --------------------------------------------------------------------------- routes


def test_bank_evidence_pack_compliance_json_has_no_healthcare_blocks(aibom_api, clinical_payload):
    http, engine, team_id, store = aibom_api
    _team(engine, team_id, "bank")
    files = _pack(http, store(clinical_payload))
    doc = json.loads(files["compliance.json"])
    assert not {"fda_524b", "hipaa", "gmlp"} & set(doc), sorted(doc)
    assert {"cert_in_aibom", "rbi_free_ai", "nist_rmf", "eu_ai_act_annexIV"} <= set(doc)
    app = doc["applicability"]
    assert app["regulatory_profile"]["entity"] == "bank"
    assert {e["framework"] for e in app["not_applicable"]} >= {"fda_524b", "hipaa", "gmlp"}
    text = _pdf_text(files["report.pdf"])
    assert "AI BOM regulatory checks" in text
    assert "Commercial bank in India" in text and "Not applicable to it:" in text
    # no healthcare framework section and none of its requirement rows; the frameworks are named once, in the
    # "not applicable" sentence (finding text about a scanned clinical model is a fact of the scan, not a block)
    assert not _HEALTH_REQUIREMENT.search(text), _HEALTH_REQUIREMENT.search(text)
    for label in ("FDA Section 524B", "FDA GMLP"):  # section headings and summary rows would repeat them
        assert text.count(label) == 1, (label, text.count(label))
    assert "FDA Section 524B" in text.split("Not applicable to it:", 1)[1][:120]


def test_bank_export_pdf_follows_the_profile(aibom_api, clinical_payload):
    http, engine, team_id, store = aibom_api
    _team(engine, team_id, "bank")
    base = store(clinical_payload)
    r = http.get(f"{base}/export", headers=AUTH)
    assert r.status_code == 200, r.text[:300]
    text = _pdf_text(r.content)
    assert "FDA Section 524B" not in text.split("Not applicable to it:", 1)[0]
    assert "Requirement Title Result Evidence" in text or "AI BOM regulatory checks" in text


def test_other_entity_keeps_in_scope_healthcare_and_drops_rbi(aibom_api, clinical_payload):
    http, engine, team_id, store = aibom_api
    _team(engine, team_id, "other")
    doc = json.loads(_pack(http, store(clinical_payload))["compliance.json"])
    assert "fda_524b" in doc and "rbi_free_ai" not in doc


def test_nbfc_default_profile_for_the_bank_router(aibom_api, bank_payload):
    # a team that DECLARED NBFC (review 6037909737 of #498, M4: a team with no settings row is not filtered, see
    # test_aibom_d5_review_6037909737.test_an_undeclared_profile_is_no_filter)
    http, engine, team_id, store = aibom_api
    _team(engine, team_id, "nbfc")
    doc = json.loads(_pack(http, store(bank_payload))["compliance.json"])
    assert doc["applicability"]["regulatory_profile"]["entity"] == "nbfc"
    assert "rbi_free_ai" in doc and "hipaa" not in doc
