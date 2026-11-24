"""CB-23 PR-C: the quantum risk register PDF (deliverable #2), the family x source heat-map with drill-down, and
``not_correlated`` (qg-1 rule 6: correlation required and absent -> Q0, CB-21 ``NOT_CORRELATED``).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb23_register_pdf_heatmap.py -q
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support.pdf_text import pdf_pages_text  # noqa: E402
from test_cbom_cb20_estate import NOT_AFTER, SERIAL, SHA256, World, _sqlite, cert  # noqa: E402
from test_cbom_sources_api import api, world as api_world  # noqa: E402,F401
from test_cbom_wp10_outputs import two_runs  # noqa: E402,F401

from backend.new_models import CbomDriftEvent, CbomEstateAsset, CbomQ0Gap, CbomRiskRegister  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.cbom_sources import risk_register as REG  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view  # noqa: E402
from backend.utilities.pdf import cbom_risk_register_pdf as PDF  # noqa: E402
from backend.utilities.pdf.cbom_deliverables import DELIVERABLES  # noqa: E402

world = api_world
_FIXTURES = (api, two_runs)
MOSCA = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
NOW = dt.datetime(2026, 11, 14, 12, 0, tzinfo=dt.timezone.utc)
T0 = dt.datetime(2030, 1, 1, 12, 0, 0)


@pytest.fixture()
def lab(tmp_path):
    w = World(_sqlite(tmp_path / "pdf.db"))
    with Session(w.engine) as s:
        row = get_or_create_settings(s, 1)
        row.risk_model = MOSCA
        s.add(row)
        s.commit()
    yield w
    w.engine.dispose()


def register(w: World) -> dict[str, CbomRiskRegister]:
    with Session(w.engine) as s:
        return {r.item_key: r for r in s.exec(select(CbomRiskRegister).where(CbomRiskRegister.team_id == 1))}


def rsa(target: str, location: str, **facts) -> dict:
    return {**cert(target, location, **facts), "qv": True}


def key(name: str, alg: str, qv: bool | None, **facts) -> dict:
    return {"type": "private_key", "target": "app-01", "location": f"/etc/ssl/private/{name}.key", "name": name,
            "algorithm": alg, "qv": qv, "facts": {"key_alg": alg, **facts}}


# ----------------------------------------------------------------------------- not_correlated
def test_a_certificate_cb21_cannot_correlate_is_q0_not_correlated_and_closes_when_correlated(lab):
    s1 = lab.source("linux_servers", "linux")
    lonely = rsa("app-01", "/etc/ssl/lonely.pem")  # a certificate with nothing identifying: correlation required
    lab.finalise(lab.run({s1: {"rows": [lonely]}}))
    [asset] = lab.assets().values()
    assert asset.key_kind == "not_correlated"
    [row] = register(lab).values()
    assert (row.q_grade, row.q_reason) == ("Q0", "not_correlated")  # rule 6, before the X + Y > Z rules
    with Session(lab.engine) as s:
        [gap] = s.exec(select(CbomQ0Gap).where(CbomQ0Gap.item_kind == "asset")).all()
    assert gap.reason == "not_correlated" and gap.closed_at is None
    # the same certificate read again with its serial and fingerprint: CB-21 correlates it, the observation moves
    found = rsa("app-01", "/etc/ssl/lonely.pem", serial=SERIAL, not_after=NOT_AFTER, fingerprint_sha256=SHA256)
    lab.finalise(lab.run({s1: {"rows": [found]}}))
    [row] = register(lab).values()
    assert row.item_key.startswith("cert:") and row.q_grade in ("Q1", "Q2")
    with Session(lab.engine) as s:
        [gap] = s.exec(select(CbomQ0Gap).where(CbomQ0Gap.item_kind == "asset")).all()
        events = s.exec(select(CbomDriftEvent).where(CbomDriftEvent.kind == "q0_closed")).all()
    assert gap.close_cause == "observation"  # resolved (not a re-identification): forwarded
    assert [e.detail["cause"] for e in events] == ["observation"] and events[0].code == "not_correlated"


def test_not_correlated_keeps_unknown_and_no_grade_first():
    g = REG._Graded("Q0", "unknown_verdict", None, "RSA")
    assert REG.not_correlated(g, "not_correlated") is g  # rule 4 before rule 6
    none = REG._Graded(None, "not_applicable", None, "Other")
    assert REG.not_correlated(none, "not_correlated") is none  # rule 5 before rule 6
    known = REG._Graded("Q2", "qv_exceeds", "internal", "RSA")
    assert REG.not_correlated(known, "cross") is known
    assert (REG.not_correlated(known, "not_correlated").q_grade,
            REG.not_correlated(known, "not_correlated").q_reason) == ("Q0", "not_correlated")


# ----------------------------------------------------------------------------- heat-map
def _estate(lab):
    s1, s2 = lab.source("linux_servers", "linux"), lab.source("aws_account", "aws")
    rows1 = [key("a", "RSA", True), key("b", "RSA", True), key("c", "ML-KEM-768", False), key("u", "", None,
                                                                                             encrypted=True)]
    rows2 = [rsa("aws", f"arn:aws:acm:eu-west-1:1:certificate/{i}", serial=f"0A0B0C0D0E0F{i:04d}",
                 not_after=NOT_AFTER, subject=f"CN=s{i}", issuer="CN=ca") for i in range(3)]
    lab.finalise(lab.run({s1: {"rows": rows1}, s2: {"rows": rows2}}))
    return s1, s2


def test_heatmap_cells_count_every_register_row_and_drill_down_returns_exactly_the_cell(lab):
    _estate(lab)
    reg = register(lab)
    with Session(lab.engine) as s:
        hm = REG.heatmap(s, 1)
        assert hm["total"] == len(reg) == sum(c["total"] for c in hm["cells"])
        for cell in hm["cells"]:
            assert not cell["other"]
            known = [g for g in ("Q1", "Q2", "Q3", "Q4") if cell["counts"].get(g)]
            assert cell["worst"] == (known[0] if known else None)  # Q0 never hides a known grade
            page = REG.list_register(s, 1, cell["filter"], after=None, limit=500)
            assert page["total"] == cell["total"]
            assert all(i["family"] == cell["family"] and i["source_ref"] == cell["source_ref"] for i in page["items"])
    rsa_cells = [c for c in hm["cells"] if c["family"] == "RSA"]
    assert rsa_cells and any(c["counts"].get("Q0") for c in hm["cells"])  # the unknown key is counted apart


def test_heatmap_folds_the_long_tail_into_one_row_and_column(lab):
    _estate(lab)
    with Session(lab.engine) as s:
        hm = REG.heatmap(s, 1, rows=1, columns=1)
    assert hm["rows"][-1]["other"] and hm["columns"][-1]["other"]
    assert sum(c["total"] for c in hm["cells"]) == hm["total"]
    assert all(c["filter"] is None for c in hm["cells"] if c["other"])


def test_heatmap_api_and_drill_down_through_the_list(api, two_runs):
    assert DRIFT.record_pending_drift(two_runs["engine"], T0) == 2
    r = api("GET", "/1/cbom/register/heatmap")
    assert r.status_code == 200, r.text
    hm = r.json()
    total = api("GET", "/1/cbom/register/summary").json()["total"]
    assert hm["total"] == total == sum(c["total"] for c in hm["cells"])
    cell = next(c for c in hm["cells"] if c["filter"])
    page = api("GET", "/1/cbom/register", params={**cell["filter"], "limit": 500}).json()
    assert page["total"] == cell["total"]
    assert api("GET", "/1/cbom/register/heatmap", "carol").status_code in (403, 404)


# ----------------------------------------------------------------------------- the PDF (deliverable #2)
def test_the_register_pdf_prints_the_summary_heatmap_top_q1_and_q0_numbers_of_the_api(lab):
    _estate(lab)
    view = load_team_cbom_view(lab.engine, 1, now=NOW)
    assert view.register is not None
    pdf = DELIVERABLES["quantum-risk-register"].build(view)
    assert pdf.startswith(b"%PDF-")
    text = " ".join(pdf_pages_text(pdf))
    flat = " ".join(text.split())
    summary = view.register["summary"]
    assert "Quantum Risk Register" in flat and "CBOM-D02-T1" in flat
    assert f"Assets {summary['total']}" in flat or str(summary["total"]) in flat
    for section in ("A. Summary", "B. Heat-map", "C. Q1 Critical assets", "D. Q0 Unknown gaps",
                    "E. Quantum gaps opened / closed per week", "F. Every asset with its grade"):
        assert section in flat, section
    q1 = [r for r in register(lab).values() if r.q_grade == "Q1"]
    if q1:
        assert "No asset grades Q1 Critical" not in flat
    gaps_open = sum(summary["q0_gaps_open"].values())
    assert gaps_open and "Open Q0 gaps by reason" in flat
    assert f"Grade model: {summary['model_version']}" in flat
    # the PDF reads the same rows as the API
    with Session(lab.engine) as s:
        assert REG.summary(s, 1, NOW.replace(tzinfo=None))["q_grades"] == summary["q_grades"]


def test_an_empty_register_still_renders_with_its_explanation(lab):
    view = load_team_cbom_view(lab.engine, 1, now=NOW)
    flat = " ".join(" ".join(pdf_pages_text(PDF.build_pdf(view))).split())
    assert "The register has no assets yet" in flat and "No open Q0 gap." in flat
    assert "No graded assets to place on the heat-map" in flat and "No asset grades Q1 Critical" in flat


def test_a_register_that_failed_to_load_says_so(lab):
    view = load_team_cbom_view(lab.engine, 1, now=NOW)
    view.register = None
    flat = " ".join(" ".join(pdf_pages_text(PDF.build_pdf(view))).split())
    assert "could not be loaded" in flat


def test_registry_entry():
    spec = DELIVERABLES["quantum-risk-register"]
    assert (spec.number, spec.title, spec.report_key, spec.data_dependent) == (2, "Quantum Risk Register",
                                                                              "cbom_risk_register", False)
    assert spec.build is PDF.build_pdf
    with pytest.raises(KeyError):
        _ = DELIVERABLES["quantum-risk-register-v2"]
    assert CbomEstateAsset.__tablename__ == "cbomestateasset"
