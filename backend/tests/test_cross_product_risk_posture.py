"""One risk score across products: SBOM, DAST, SAST and LLM show the 0-100 posture score the AI BOM and the D3 code
scans show (``risk_scale.posture``, the engine's ``aibom/src/aibom/score/posture.py``), on their list rows, their
dashboard tiles, their per-scan dashboards and their PDF headlines, with the same grade bands and words.

Before: the SBOM / DAST lists sent a 0-10 average (Critical 10 ... Low 2.5), the LLM list a 0-10 average on another
formula (weight/4*10), the SAST list an unbounded weighted sum (``risk_score``: 15 Highs = 45), and the PDFs graded an
uncapped ``compute_risk_score`` (15 Highs = 100 / F "Critical risk" with no Critical finding). The older fields stay
on the API with their old values; ``risk_posture`` is added.
"""
from __future__ import annotations

import copy
import datetime as dt
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.utilities.dashboard import risk_scale
from backend.utilities.dashboard import scan as scan_mod
from backend.utilities.dashboard import scan_list as scan_list_mod
from backend.utilities.db.scan_list_item import (
    return_dast_list_item,
    return_iac_list_item,
    return_llm_list_item,
    return_mcp_list_item,
    return_sast_list_item,
    return_sbom_sca_list_item,
)
from backend.utilities.pdf.aibom_posture import posture_risk

_TESTS = Path(__file__).resolve().parent
if str(_TESTS) not in sys.path:  # test_pdf_export_smoke and support.pdf_text, imported by the PDF tests
    sys.path.insert(0, str(_TESTS))

CREATED = dt.datetime(2026, 11, 25, 9, 30, tzinfo=dt.timezone.utc)
OWNER = SimpleNamespace(email="o@example.test", first_name="O", last_name="Wner")


def _rows(impacts):
    return [{"title": f"finding {i}", "description": "d", "impact": imp, "category": "injection", "confidence": "high",
             "compliance_controls": {}, "owasp_top_10": {}} for i, imp in enumerate(impacts)]


INVENTORY_ROW = {"title": "Inventory: left-pad", "dependency": "left-pad==1.3.0", "impact": "Low", "inventory_only": True,
                 "description": "", "compliance_controls": {}, "owasp_top_10": {}}


def _results(scan_type, impacts):
    if scan_type == "sast":
        return [{"logical_component_title": "app", "vulnerabilities": _rows(impacts)}]
    if scan_type == "llm":
        return {"vulnerabilities": _rows(impacts), "model_vulnerabilities": {}}
    if scan_type == "mcp":
        return {"tools": [{"tool_name": "fetch", "tool_risk_level": "high", "tool_category": "web",
                           "vulnerabilities": _rows(impacts)}], "prompts": [], "resources": []}
    if scan_type == "sbom_sca":  # a package was inventoried: the scan covered something (an inventory row, not counted)
        return [dict(INVENTORY_ROW), *_rows(impacts)]
    return _rows(impacts)


def _scan(scan_type, impacts, status="success"):
    return SimpleNamespace(
        id=7, title="t", scan_type=scan_type, scan_status=status, created_at=CREATED, last_updated=CREATED,
        credit_consumed=1.0, info=None, owner_user=OWNER, scan_metadata={"target_url": "https://x.test"},
        scan_data={"results": _results(scan_type, impacts), "duration_of_scan": 2.0, "metadata": {}},
    )


LIST_ITEM = {"sast": return_sast_list_item, "sbom_sca": return_sbom_sca_list_item, "dast": return_dast_list_item,
             "llm": return_llm_list_item, "iac": return_iac_list_item, "mcp": return_mcp_list_item}
# impacts -> (score, grade, label): the engine's posture function, capped by the worst severity and floored by it
# (any Critical: at least 70 / F, any High: at least 50 / D; review 6064315680 of #505, finding 3)
CASES = [
    ([], (0, "A", "Low risk")),
    (["Low"] * 3, (12, "A", "Low risk")),
    (["Low"] * 7, (28, "B", "Moderate risk")),
    (["Medium"] * 4, (32, "C", "Elevated risk")),
    (["High"], (50, "D", "High risk")),  # floor: was 20 / B
    (["High"] * 15, (69, "D", "High risk")),  # uncapped: 300 -> 100 / F
    (["Critical"], (70, "F", "Critical risk")),  # floor: was 40 / C, in the "Medium" filter
    (["Critical", "Low"], (70, "F", "Critical risk")),  # floor: was 44 / C
    (["Critical"] * 2, (80, "F", "Critical risk")),
]
WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}


def _expected(score, grade, label, impacts=()):
    return {"score": score, "grade": grade, "label": label, "band": label.split(" ")[0].lower(),
            "weighted": sum(WEIGHT[i] for i in impacts)}


# ------------------------------------------------------------------------------------------------- the one helper
@pytest.mark.parametrize("impacts,want", CASES)
def test_posture_is_the_engine_function(impacts, want):
    counts = {s: impacts.count(s.title()) for s in risk_scale.SEVERITIES}
    assert posture_risk(counts["critical"], counts["high"], counts["medium"], counts["low"]) == want
    assert risk_scale.posture(counts) == _expected(*want, impacts)
    assert risk_scale.posture_of(impacts) == _expected(*want, impacts)
    # the keys may be stored as "Critical" (SAST risk_metrics) or "critical"; an impact outside the four is not counted
    assert risk_scale.posture({**{s.title(): n for s, n in counts.items()}, "Info": 9}) == _expected(*want, impacts)


def test_the_grade_bands_are_the_engine_table():
    from backend.utilities.pdf.aibom_posture import engine_posture

    bands: dict[str, list[int]] = {}
    for score in range(101):
        grade, _band = engine_posture().posture_grade(score)
        bands.setdefault(grade, []).append(score)
    assert {g: (min(s), max(s)) for g, s in bands.items()} == {
        "A": (0, 14), "B": (15, 29), "C": (30, 49), "D": (50, 69), "F": (70, 100)}


# ------------------------------------------------------------------------------------------------- list rows
@pytest.mark.parametrize("scan_type", sorted(LIST_ITEM))
@pytest.mark.parametrize("impacts,want", CASES)
def test_every_list_row_carries_the_one_score(scan_type, impacts, want):
    row = LIST_ITEM[scan_type](_scan(scan_type, impacts))
    assert row[risk_scale.POSTURE_KEY] == _expected(*want, impacts), (scan_type, impacts)
    assert row[risk_scale.STATUS_KEY] == "scored"


@pytest.mark.parametrize("scan_type", sorted(LIST_ITEM))
def test_a_scan_without_a_result_has_no_score_yet(scan_type):
    for status in ("pending", "started", "failure", "cancelled"):
        for impacts in ([], ["High"]):  # a failed scan with partial data has no score either, never A
            row = LIST_ITEM[scan_type](_scan(scan_type, impacts, status=status))
            assert row[risk_scale.POSTURE_KEY] is None and row[risk_scale.STATUS_KEY] == "not_scored", (status, impacts)


def test_the_older_fields_keep_their_values():
    # backward compatible: nothing removed, nothing re-meant
    highs = ["High"] * 15
    assert return_sast_list_item(_scan("sast", highs))["risk_score"] == 45  # the weighted sum, as before
    assert return_sbom_sca_list_item(_scan("sbom_sca", highs))["average_risk_score"] == 7.5
    assert return_dast_list_item(_scan("dast", highs))["average_risk_score"] == 7.5
    assert return_llm_list_item(_scan("llm", highs))["average_risk_score"] == 7.5
    assert return_sbom_sca_list_item(_scan("sbom_sca", []))["average_risk_score"] is None


# ------------------------------------------------------------------------------------------------- tiles
@pytest.fixture
def mongo(monkeypatch: pytest.MonkeyPatch):
    store: dict[int, list[dict]] = {}

    def findings(scan_id, *a, **k):
        return list(store.get(scan_id, []))

    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id", findings)
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", findings)
    return store


def _store(store, scan, impacts):
    store[scan.id] = [{"scan_id": scan.id, "finding_data": dict(r), "finding_status": "not_started",
                       "created_at": CREATED, "fixed_at": None, "ignored_at": None} for r in _rows(impacts)]


@pytest.mark.parametrize("impacts,want", [c for c in CASES if c[0]])
def test_the_tiles_show_the_score_of_the_rows(mongo, impacts, want):
    tiles = {
        "sbom_sca": lambda s: scan_list_mod.generate_sbom_sca_dashboard_data([s])["card_data"],
        "dast": lambda s: scan_list_mod.generate_dast_dashboard_data([s])["card_data"],
        "sast": lambda s: scan_list_mod.generate_sast_dashboard_data([s]),
        "llm": lambda s: scan_list_mod.generate_llm_dashboard_data([s])["card_data"],
        "iac": lambda s: scan_list_mod.generate_iac_dashboard_data([s])["card_data"],
        "mcp": lambda s: scan_list_mod.generate_mcp_dashboard_data([s])["card_data"],
    }
    for scan_type, tile in tiles.items():
        scan = _scan(scan_type, impacts)
        _store(mongo, scan, impacts)
        got = tile(scan)[risk_scale.POSTURE_KEY]
        assert got == LIST_ITEM[scan_type](scan)[risk_scale.POSTURE_KEY] == _expected(*want, impacts), scan_type


def test_a_team_without_a_successful_scan_has_no_tile_score(mongo):
    assert scan_list_mod.generate_dast_dashboard_data([])["card_data"][risk_scale.POSTURE_KEY] is None
    assert scan_list_mod.generate_sbom_sca_dashboard_data([])["card_data"][risk_scale.POSTURE_KEY] is None
    assert scan_list_mod.generate_llm_dashboard_data([])["card_data"][risk_scale.POSTURE_KEY] is None
    assert scan_list_mod.generate_sast_dashboard_data([])[risk_scale.POSTURE_KEY] is None
    assert scan_list_mod.generate_iac_dashboard_data([])["card_data"][risk_scale.POSTURE_KEY] is None
    assert scan_list_mod.generate_mcp_dashboard_data([])["card_data"][risk_scale.POSTURE_KEY] is None


# ------------------------------------------------------------------------------------------------- per-scan dashboards
@pytest.mark.parametrize("impacts,want", [c for c in CASES if c[0]])
def test_the_results_page_shows_the_score_of_the_row(mongo, monkeypatch, impacts, want):
    for scan_type in ("sast", "sbom_sca", "dast", "llm", "iac", "mcp"):
        scan = _scan(scan_type, impacts)
        _store(mongo, scan, impacts)
        dash = _per_scan(scan_type, scan, monkeypatch)
        got = (dash if scan_type in ("sast", "iac") else dash["card_data"])[risk_scale.POSTURE_KEY]
        assert got == LIST_ITEM[scan_type](scan)[risk_scale.POSTURE_KEY] == _expected(*want, impacts), scan_type


def _per_scan(scan_type, scan, monkeypatch):
    return scan_mod.generate_scan_dashboard(scan_type=scan_type, scan_object=scan)


# ------------------------------------------------------------------------------------------------- PDFs
def _payload(scan_type, n_high):
    import test_pdf_export_smoke as smoke

    payload = copy.deepcopy(smoke._typical_payload(scan_type))
    if scan_type == "sast":
        vuln = payload[0]["vulnerabilities"][0]
        payload[0]["vulnerabilities"] = [{**vuln, "title": f"{vuln['title']} {i}", "impact": "High"} for i in range(n_high)]
    elif scan_type == "llm":
        payload = {"duration_of_scan": 1, "metadata": {}, "results": {"model_vulnerabilities": {}, "vulnerabilities": [
            {"title": f"Prompt injection {i}", "impact": "High", "description": "d",
             "owasp_top_10_llm": {"LLM01": "Prompt Injection"}, "suggested_fix": "isolate"} for i in range(n_high)]}}
    elif scan_type == "mcp":
        payload = {"duration_of_scan": 1, "results": {"tools": [{"tool_name": "fetch", "vulnerabilities": [
            {"title": f"Tool exposes secrets {i}", "impact": "High", "description": "d", "suggested_fix": "redact"}
            for i in range(n_high)]}]}}
    elif scan_type == "sbom_sca":
        payload = {"duration_of_scan": 1, "results": [
            {"title": f"CVE in pkg{i}", "dependency": f"pkg{i}==1.0.0", "impact": "High", "description": "d",
             "cves": {f"CVE-2024-{1000 + i}": "nvd"}, "suggested_fix": f"upgrade pkg{i}"} for i in range(n_high)]}
    else:
        payload = [{**payload[0], "title": f"{payload[0]['title']} {i}", "impact": "High"} for i in range(n_high)]
    return payload


@pytest.mark.parametrize("scan_type", ["sast", "dast", "llm", "sbom_sca", "iac", "mcp"])
def test_the_pdf_headline_is_the_one_score(scan_type, tmp_path):
    from backend.utilities.pdf.combined import (
        generate_pdf_for_type,
        prepare_pdf_export_payload,
    )
    from support.pdf_text import pdf_pages_text

    out = str(tmp_path / f"{scan_type}.pdf")
    generate_pdf_for_type(scan_type, prepare_pdf_export_payload(scan_type, _payload(scan_type, 15)), out)
    first = pdf_pages_text(Path(out).read_bytes())[0]
    # 15 Highs, no Critical: 69 / D "High risk" (the list row's number), never the uncapped 100 / F "Critical risk"
    assert re.search(r"\nD\nRisk score\n69\nHigh risk\n", first), first[:1500]
    assert "Critical risk" not in first


def test_the_sbom_pdf_overview_has_the_one_score_not_the_0_10_average(tmp_path, monkeypatch):
    from backend.utilities.pdf import sbom_sca_pdf

    seen: dict = {}
    summary = sbom_sca_pdf.append_executive_summary

    def spy(story, **kw):
        seen.update(dict(kw["overview_rows"]))
        return summary(story, **kw)

    monkeypatch.setattr(sbom_sca_pdf, "append_executive_summary", spy)
    sbom_sca_pdf.generate_pdf(_payload("sbom_sca", 15), str(tmp_path / "sbom.pdf"))
    assert seen["Risk score"] == "69 / 100 · grade D · High risk"
    assert "Average risk score (0–10)" not in seen


# ------------------------------------------------------------------------------------------------- SBOM: 0 / A only when complete
def _sbom(results, status="success", **data):
    scan = _scan("sbom_sca", [], status=status)
    scan.scan_data = {"results": results, "duration_of_scan": 2.0, "metadata": {}, **data}
    return scan


GUESSED = {"title": "CVE in pillow", "dependency": "pillow==10.0", "impact": "High", "version_guessed_from": ">=10.0",
           "description": "d", "compliance_controls": {}, "owasp_top_10": {}}


@pytest.mark.parametrize("label,scan,want_status", [
    # completed, a package inventoried, no vulnerability: a real clean result, 0 / A
    ("clean", _sbom([dict(INVENTORY_ROW)]), "scored"),
    ("clean, stored SBOM only", _sbom([], sbom_json={"components": [{"name": "left-pad", "purl": "pkg:npm/left-pad@1.3.0"}]}),
     "scored"),
    # finished but nothing inventoried: "no vulnerability" means nothing
    ("no package", _sbom([]), "incomplete"),
    ("no results key", _sbom(None), "incomplete"),
    # every match on a guessed version (listed, not counted): not clean, not hidden either: the worst case, unverified
    ("guessed versions only", _sbom([dict(INVENTORY_ROW), dict(GUESSED)]), "unverified"),
    # failed, cancelled or still running, with or without partial rows: no score
    ("failed with rows", _sbom([dict(INVENTORY_ROW)], status="failure"), "not_scored"),
    ("cancelled", _sbom([], status="cancelled"), "not_scored"),
    ("running", _sbom([dict(INVENTORY_ROW)], status="started"), "not_scored"),
])
def test_an_sbom_scan_reads_0_a_only_when_it_completed_clean(mongo, label, scan, want_status):
    row = return_sbom_sca_list_item(scan)
    assert row[risk_scale.STATUS_KEY] == want_status, label
    if want_status == "scored":
        assert row[risk_scale.POSTURE_KEY] == _expected(0, "A", "Low risk"), label
    elif want_status == "unverified":  # one guessed High: 50 / D, marked unverified, never A
        assert row[risk_scale.POSTURE_KEY]["score"] == 50 and row[risk_scale.POSTURE_KEY]["grade"] == "D", label
    else:
        assert row[risk_scale.POSTURE_KEY] is None, label  # never A
    if scan.scan_data.get("results") is not None:
        card = scan_mod.generate_scan_dashboard(scan_type="sbom_sca", scan_object=scan)["card_data"]
        assert (card[risk_scale.STATUS_KEY], card[risk_scale.POSTURE_KEY]) == (
            row[risk_scale.STATUS_KEY], row[risk_scale.POSTURE_KEY]), label
    tile = scan_list_mod.generate_sbom_sca_dashboard_data([scan])["card_data"]
    assert tile[risk_scale.STATUS_KEY] == want_status, label


def test_the_sbom_tile_scores_the_complete_scans_only(mongo):
    clean, empty = _sbom([dict(INVENTORY_ROW), *_rows(["High"])]), _sbom([])
    tile = scan_list_mod.generate_sbom_sca_dashboard_data([clean, empty])["card_data"]
    assert tile[risk_scale.STATUS_KEY] == "scored" and tile[risk_scale.POSTURE_KEY]["score"] == 50


def test_a_failed_scan_with_data_has_no_score_on_its_results_page(mongo):
    for scan_type in ("sast", "dast", "llm", "iac", "mcp"):
        scan = _scan(scan_type, ["High"], status="failure")
        dash = scan_mod.generate_scan_dashboard(scan_type=scan_type, scan_object=scan)
        card = dash if scan_type in ("sast", "iac") else dash["card_data"]
        assert card[risk_scale.POSTURE_KEY] is None and card[risk_scale.STATUS_KEY] == "not_scored", scan_type


def test_the_sbom_pdf_says_incomplete_never_a(tmp_path):
    from support.pdf_text import pdf_pages_text

    from backend.utilities.pdf.combined import generate_pdf_for_type, prepare_pdf_export_payload

    for name, payload in (("empty", {"duration_of_scan": 1, "results": []}),):
        out = str(tmp_path / f"{name}.pdf")
        generate_pdf_for_type("sbom_sca", prepare_pdf_export_payload("sbom_sca", payload), out)
        first = pdf_pages_text(Path(out).read_bytes())[0]
        assert "Risk score\n—\nIncomplete scan" in first, (name, first[:1200])
        assert "\nA\nRisk score" not in first and "Low risk" not in first, name
    out = str(tmp_path / "clean.pdf")
    generate_pdf_for_type("sbom_sca", prepare_pdf_export_payload("sbom_sca", {"duration_of_scan": 1,
                                                                             "results": [dict(INVENTORY_ROW)]}), out)
    assert "A\nRisk score\n0\nLow risk" in pdf_pages_text(Path(out).read_bytes())[0]


def test_the_mcp_trend_is_the_one_score_per_server(mongo):
    scan = _scan("mcp", ["High"] * 15)
    scan.scan_metadata = {"server_url": "https://tools.example.com/mcp"}
    dash = scan_list_mod.generate_mcp_dashboard_data([scan])
    assert list(dash["risk_posture_trend"].values()) == [69]
    assert list(dash["risk_score_trend"].values()) == [7.5]  # the older 0-10 field, unchanged
