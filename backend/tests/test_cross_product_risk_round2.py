"""Review 6064315680 of #505 (round 2): the reviewer's probes, as tests.

1. A team tile scores the latest successful scan of each target (risk_rollup), so it reads what the rows read and
   improves after a rescan that fixed everything.
2. A failed or running scan's findings never reach a tile (DAST and MCP counted them).
3. The worst severity sets a floor: one Critical is 70 / F (it was 40 / C, in the "Medium" filter), one High 50 / D.
   ``weighted`` (10C + 5H + 2M + 1L) sorts scans the score cannot tell apart (4 Highs and 1000 are both 69 / D).
4. A CBOM scan that did not succeed has no score on its row, tile and results card, also over #500's flat fields.
5. An SBOM scan's guessed-version matches are flagged, not dropped: the confirmed score with an "unverified" note, or
   the worst case marked "unverified" when they are all it found.
6. The SBOM PDF lists the frameworks that bind the team, as the SBOM page.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.utilities.compliance import bom_applicability as ba
from backend.utilities.dashboard import risk_rollup, risk_scale
from backend.utilities.dashboard import scan as scan_mod
from backend.utilities.dashboard import scan_list as scan_list_mod
from backend.utilities.db import scan_list_item as items

_TESTS = Path(__file__).resolve().parent
if str(_TESTS) not in sys.path:  # support.pdf_text
    sys.path.insert(0, str(_TESTS))

T0 = dt.datetime(2026, 11, 20, 9, 0, tzinfo=dt.timezone.utc)
OWNER = SimpleNamespace(email="o@example.test", first_name="O", last_name="Wner")
INVENTORY = {"title": "Inventory: left-pad", "dependency": "left-pad==1.3.0", "impact": "Low", "inventory_only": True,
             "description": "", "compliance_controls": {}, "owasp_top_10": {}}


def _rows(impacts, **extra):
    return [{"title": f"f{i}", "description": "d", "impact": imp, "category": "injection", "confidence": "high",
             "compliance_controls": {}, "owasp_top_10": {}, **extra} for i, imp in enumerate(impacts)]


def _results(scan_type, impacts):
    if scan_type == "sast":
        return [{"logical_component_title": "app", "vulnerabilities": _rows(impacts)}]
    if scan_type == "llm":
        return {"vulnerabilities": _rows(impacts), "model_vulnerabilities": {}}
    if scan_type == "mcp":
        return {"tools": [{"tool_name": "fetch", "tool_risk_level": "high", "tool_category": "web",
                           "vulnerabilities": _rows(impacts)}], "prompts": [], "resources": []}
    if scan_type == "sbom_sca":
        return [dict(INVENTORY), *_rows(impacts, dependency="pkg==1.0")]
    return _rows(impacts)


TARGET = {
    "sast": {"repo_url": "https://github.com/acme/app", "branch": "main"},
    "sbom_sca": {"repo_url": "https://github.com/acme/app", "branch": "main"},
    "iac": {"repo_url": "https://github.com/acme/infra", "branch": "main"},
    "dast": {"target_url": "https://shop.example.com"},
    "llm": {"model_type": "openai", "model_name": "gpt-4o"},
    "mcp": {"server_url": "https://tools.example.com/mcp"},
}
TILE = {
    "sast": lambda scans: scan_list_mod.generate_sast_dashboard_data(scans),
    "sbom_sca": lambda scans: scan_list_mod.generate_sbom_sca_dashboard_data(scans)["card_data"],
    "dast": lambda scans: scan_list_mod.generate_dast_dashboard_data(scans)["card_data"],
    "llm": lambda scans: scan_list_mod.generate_llm_dashboard_data(scans)["card_data"],
    "iac": lambda scans: scan_list_mod.generate_iac_dashboard_data(scans)["card_data"],
    "mcp": lambda scans: scan_list_mod.generate_mcp_dashboard_data(scans)["card_data"],
}
ROW = {"sast": items.return_sast_list_item, "sbom_sca": items.return_sbom_sca_list_item,
       "dast": items.return_dast_list_item, "llm": items.return_llm_list_item, "iac": items.return_iac_list_item,
       "mcp": items.return_mcp_list_item}


def _scan(scan_type, impacts, *, sid, hours=0, status="success", target=None):
    return SimpleNamespace(
        id=sid, title=f"scan {sid}", scan_type=scan_type, scan_status=status, team_id=1,
        created_at=T0 + dt.timedelta(hours=hours), last_updated=T0 + dt.timedelta(hours=hours),
        credit_consumed=1.0, info=None, owner_user=OWNER, scan_metadata=dict(TARGET[scan_type] if target is None else target),
        scan_data={"results": _results(scan_type, impacts), "duration_of_scan": 2.0, "metadata": {}},
    )


@pytest.fixture(autouse=True)
def mongo(monkeypatch: pytest.MonkeyPatch):
    store: dict[int, list[dict]] = {}

    def findings(scan_id, *a, **k):
        return list(store.get(scan_id, []))

    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id", findings)
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", findings)
    return store


def _store(store, scan, impacts):
    store[scan.id] = [{"scan_id": scan.id, "finding_data": dict(r), "finding_status": "not_started", "created_at": T0,
                       "fixed_at": None, "ignored_at": None} for r in _rows(impacts)]


def _sg(card):
    p = card[risk_scale.POSTURE_KEY]
    return None if p is None else (p["score"], p["grade"])


# ------------------------------------------------------------------------------------------------- 1. current state
@pytest.mark.parametrize("scan_type", sorted(TILE))
def test_rescans_of_one_target_read_the_row_not_their_sum(mongo, scan_type):
    """The reviewer's probe: 4 scans of one target, 1 High each. Rows 50 / D (20 / B before the floor); the tile was
    69 / D (the 4 Highs summed)."""
    scans = [_scan(scan_type, ["High"], sid=i + 1, hours=i) for i in range(4)]
    for s in scans:
        _store(mongo, s, ["High"])
    row = _sg(ROW[scan_type](scans[-1]))
    tile = TILE[scan_type](scans)
    assert row == _sg(tile) == (50, "D"), scan_type
    assert tile["risk_posture_scope"]["scan_ids"] == [4] and tile["risk_posture_scope"]["targets"] == 1


@pytest.mark.parametrize("scan_type", sorted(TILE))
def test_a_rescan_that_fixed_everything_improves_the_tile(mongo, scan_type):
    old = _scan(scan_type, ["Critical"] * 3, sid=1, hours=0)
    fixed = _scan(scan_type, [], sid=2, hours=5)
    _store(mongo, old, ["Critical"] * 3)
    before = _sg(TILE[scan_type]([old]))
    after = _sg(TILE[scan_type]([old, fixed]))
    assert before == (100, "F") and after == (0, "A"), (scan_type, before, after)


@pytest.mark.parametrize("scan_type", sorted(TILE))
def test_two_targets_add_up_their_current_scans(mongo, scan_type):
    other = {"sast": {"repo_url": "https://github.com/acme/api", "branch": "main"},
             "sbom_sca": {"repo_url": "https://github.com/acme/app", "branch": "release"},
             "iac": {"repo_url": "https://github.com/acme/infra", "branch": "dev"},
             "dast": {"target_url": "https://admin.example.com"},
             "llm": {"model_type": "openai", "model_name": "gpt-4o-mini"},
             "mcp": {"server_url": "https://files.example.com/mcp"}}[scan_type]
    a_old = _scan(scan_type, ["Critical"], sid=1, hours=0)
    a_new = _scan(scan_type, ["High"], sid=2, hours=1)
    b = _scan(scan_type, ["High"], sid=3, hours=2, target=other)
    for s, imp in ((a_old, ["Critical"]), (a_new, ["High"]), (b, ["High"])):
        _store(mongo, s, imp)
    tile = TILE[scan_type]([a_old, a_new, b])
    assert _sg(tile) == (50, "D") and tile[risk_scale.POSTURE_KEY]["weighted"] == 10, scan_type  # 2 Highs, no Critical
    assert tile["risk_posture_scope"]["scan_ids"] == [2, 3]


def test_targets_are_keyed_per_product():
    k = risk_rollup.target_key
    assert k("sast", _scan("sast", [], sid=1)) == k("sast", _scan("sast", [], sid=2))
    assert k("sast", _scan("sast", [], sid=1)) != k("sast", _scan("sast", [], sid=2, target={
        "repo_url": "https://github.com/acme/app", "branch": "dev"}))
    assert k("dast", _scan("dast", [], sid=1, target={"target_url": "https://Shop.example.com/"})) == \
        k("dast", _scan("dast", [], sid=2))
    assert k("dast", _scan("dast", [], sid=5, target={}))[0] == "scan"  # no target recorded: its own


# ------------------------------------------------------------------------------------------------- 2. status
@pytest.mark.parametrize("scan_type", sorted(TILE))
def test_failed_and_running_scans_reach_no_tile(mongo, scan_type):
    """The reviewer's probe: one clean successful scan, plus a failed and a running one with 3 stored Criticals each.
    DAST and MCP read 100 / F."""
    clean = _scan(scan_type, [], sid=1, hours=0)
    failed = _scan(scan_type, ["Critical"] * 3, sid=2, hours=1, status="failure")
    running = _scan(scan_type, ["Critical"] * 3, sid=3, hours=2, status="started")
    for s in (failed, running):
        _store(mongo, s, ["Critical"] * 3)
    tile = TILE[scan_type]([clean, failed, running])
    assert _sg(tile) == (0, "A"), scan_type
    if scan_type in ("dast", "mcp"):  # their issue counts too
        assert tile["total_critical_issues"] == 0, scan_type


# ------------------------------------------------------------------------------------------------- 3. floor and sort
def test_one_critical_is_f_and_in_the_critical_tier():
    p = risk_scale.posture({"critical": 1})
    assert (p["score"], p["grade"], p["label"]) == (70, "F", "Critical risk")
    p = risk_scale.posture({"high": 1})
    assert (p["score"], p["grade"], p["label"]) == (50, "D", "High risk")
    src = (Path(__file__).resolve().parents[2] / "frontend" / "utils" / "riskPosture.ts").read_text(encoding="utf-8")
    assert 'if (tier === "critical") return score >= 70;' in src  # 70 is in "Critical"


def test_the_raw_weighted_sum_sorts_what_the_cap_ties():
    four, many = risk_scale.posture({"high": 4}), risk_scale.posture({"high": 1000})
    assert four["score"] == many["score"] == 69
    assert (four["weighted"], many["weighted"]) == (20, 5000)


def test_the_pdf_prints_the_method():
    from backend.utilities.pdf.report_branding import POSTURE_METHOD

    assert "any Critical scores at least 70 (F)" in POSTURE_METHOD and "any High at least 50" in POSTURE_METHOD


# ------------------------------------------------------------------------------------------------- 4. CBOM
def _cbom(status):
    return SimpleNamespace(
        id=11, title="c", scan_type="cbom", scan_status=status, team_id=1, created_at=T0, last_updated=T0,
        credit_consumed=1.0, info=None, owner_user=OWNER, scan_metadata={"repo_url": "https://github.com/acme/app"},
        scan_data={"results": [{"title": "MD5", "algorithm_name": "MD5", "impact": "Critical", "weak": True,
                                "finding_codes": ["WEAK_ALGORITHM"], "crypto_strength": "weak"}]})


@pytest.mark.parametrize("status", ["failure", "started", "cancelled", "pending"])
def test_a_cbom_scan_that_did_not_succeed_has_no_score(status):
    row = items.return_cbom_list_item(_cbom(status))
    assert row[risk_scale.POSTURE_KEY] is None and row[risk_scale.STATUS_KEY] == "not_scored"
    # #500 spreads flat risk_score / risk_grade / risk_label before this gate; the gate's nulls come last and win
    assert (row["risk_score"], row["risk_grade"], row["risk_label"]) == (None, None, None)
    merged = items._cbom_gate(_cbom(status), {"risk_score": 0, "risk_grade": "A", "risk_label": "Low risk"}, [])
    assert (merged["risk_score"], merged["risk_grade"]) == (None, None)
    card = risk_scale.gate_dashboard("cbom", {"card_data": {"risk_score": 0, "risk_grade": "A", "risk_label": "Low risk",
                                                            "average_risk_score": 0.0}}, status)["card_data"]
    assert (card["risk_score"], card["risk_grade"], card[risk_scale.POSTURE_KEY]) == (None, None, None)
    assert card["average_risk_score"] == 0.0  # the older field is kept


def test_a_successful_cbom_scan_keeps_its_score():
    row = items.return_cbom_list_item(_cbom("success"))
    assert row[risk_scale.STATUS_KEY] == "scored" and row[risk_scale.POSTURE_KEY]["grade"] == "F"
    if "risk_score" in row:  # #500 merged: its flat fields stay #500's and say what risk_posture says (round 3)
        p = row[risk_scale.POSTURE_KEY]
        assert (row["risk_score"], row["risk_grade"], row["risk_label"]) == (p["score"], p["grade"], p["label"])
    card = {"card_data": {"risk_score": 70}}
    assert risk_scale.gate_dashboard("cbom", card, "success") is card


def test_the_cbom_tile_of_a_team_whose_scans_failed_has_no_score():
    tile = scan_list_mod._gate_cbom_tile([], SimpleNamespace(rows=[]), {
        "card_data": {"risk_score": 0, "risk_grade": "A", "risk_label": "Low risk"}, "severity_distribution": {}}, {})
    card = tile["card_data"]
    assert card[risk_scale.STATUS_KEY] == "not_scored" and card["risk_score"] is None and card["risk_grade"] is None
    scored = scan_list_mod._gate_cbom_tile([object()], SimpleNamespace(rows=[]), {
        "card_data": {"risk_score": 70}, "severity_distribution": {"critical": 1, "informational": 4}},
        {"critical": 1})["card_data"]
    assert scored["risk_score"] == 70 and scored[risk_scale.POSTURE_KEY]["score"] == 70


def test_get_scan_gates_every_results_dashboard():
    src = (Path(__file__).resolve().parents[1] / "routers" / "scans.py").read_text(encoding="utf-8")
    body = src[src.index("async def get_scan("):src.index("def _payload_section(")]
    assert "dashboard_data = risk_scale.gate_dashboard(type, dashboard_data, SCAN_STATUS)" in body


# ------------------------------------------------------------------------------------------------- 5. guessed versions
GUESSED = {"dependency": "pillow==10.0", "version_guessed_from": ">=10.0"}


def _sbom(confirmed, guessed):
    scan = _scan("sbom_sca", [], sid=21)
    scan.scan_data["results"] = [dict(INVENTORY), *_rows(confirmed, dependency="ok==1.0"), *_rows(guessed, **GUESSED)]
    return scan


def test_confirmed_score_with_an_unverified_note():
    """The reviewer's probe: 1 verified Low + 10 guessed Criticals read 4 · A with nothing said."""
    scan = _sbom(["Low"], ["Critical"] * 10)
    row = items.return_sbom_sca_list_item(scan)
    card = scan_mod.generate_scan_dashboard(scan_type="sbom_sca", scan_object=scan)["card_data"]
    tile = scan_list_mod.generate_sbom_sca_dashboard_data([scan])["card_data"]
    for got in (row, card, tile):
        assert _sg(got) == (4, "A") and got[risk_scale.STATUS_KEY] == "scored"
        unverified = got[risk_scale.UNVERIFIED_KEY]
        assert (unverified["count"], unverified["worst"]) == (10, "critical")
        assert unverified["worst_case"]["score"] == 100  # the filter and the sort read it (round 3, 6)
    assert risk_scale.unverified_note(row[risk_scale.UNVERIFIED_KEY]) == \
        "unverified: 10 guessed-version matches (worst: Critical)"


def test_only_guessed_matches_score_their_worst_case_marked_unverified():
    scan = _sbom([], ["Critical"] * 10)
    row = items.return_sbom_sca_list_item(scan)
    card = scan_mod.generate_scan_dashboard(scan_type="sbom_sca", scan_object=scan)["card_data"]
    for got in (row, card):
        assert _sg(got) == (100, "F") and got[risk_scale.STATUS_KEY] == "unverified"  # in the "Critical" tier
    assert items.return_sbom_sca_list_item(_sbom(["Low"], []))[risk_scale.UNVERIFIED_KEY] is None


def test_the_sbom_pdf_flags_unverified_matches(tmp_path, monkeypatch):
    from support.pdf_text import pdf_pages_text

    from backend.utilities.pdf import sbom_sca_pdf

    seen: dict = {}
    summary = sbom_sca_pdf.append_executive_summary

    def spy(story, **kw):
        seen.update(dict(kw["overview_rows"]))
        return summary(story, **kw)

    monkeypatch.setattr(sbom_sca_pdf, "append_executive_summary", spy)
    sbom_sca_pdf.generate_pdf(_sbom(["Low"], ["Critical"] * 10).scan_data, str(tmp_path / "a.pdf"))
    assert seen["Risk score"] == "4 / 100 · grade A · Low risk · unverified: 10 guessed-version matches (worst: Critical)"
    out = str(tmp_path / "b.pdf")
    sbom_sca_pdf.generate_pdf(_sbom([], ["Critical"] * 10).scan_data, out)
    assert seen["Risk score"].startswith("100 / 100 · grade F · Critical risk (unverified")
    assert "F\nRisk score\n100\nCritical risk (unverified)" in pdf_pages_text(Path(out).read_bytes())[0]


# ------------------------------------------------------------------------------------------------- 6. SBOM PDF frameworks
REPORT = {"pass": 1, "fail": 1, "na": 0, "coverage": 0.5, "requirements": []}
SBOM_COMPLIANCE = {k: dict(REPORT) for k in ("ntia_minimum_elements", "cert_in_sbom", "sebi_cscrf_sbom",
                                               "rbi_free_ai_supply", "nist_ssdf")}


def test_the_sbom_pdf_lists_the_frameworks_that_bind_the_team(tmp_path):
    from support.pdf_text import pdf_pages_text

    from backend.utilities.cbom_sources import regulated_entity
    from backend.utilities.pdf import sbom_sca_pdf

    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
           "version": 1, "metadata": {"component": {"name": "app", "type": "application", "bom-ref": "app"}},
           "components": [{"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0", "type": "library",
                           "bom-ref": "pkg:npm/left-pad@1.3.0"}]}
    base = {"duration_of_scan": 1, "results": [dict(INVENTORY)], "sbom_compliance": dict(SBOM_COMPLIANCE),
            "sbom_json": bom}
    bank = {**base, ba.PDF_PROFILE_KEY: {"profile": regulated_entity.profile("other"), "declared": True}}
    text = {}
    for name, payload in (("all", base), ("other", bank)):
        out = str(tmp_path / f"{name}.pdf")
        sbom_sca_pdf.generate_pdf(payload, out)
        text[name] = "\n".join(pdf_pages_text(Path(out).read_bytes()))
    assert "SEBI CSCRF (SBOM)" in text["all"] and "RBI FREE-AI (supply chain)" in text["all"]
    # an "other" entity: SEBI CSCRF and RBI FREE-AI do not bind it; the page says so, as the SBOM page does
    assert "SEBI CSCRF (SBOM)" not in text["other"] and "RBI FREE-AI (supply chain)" not in text["other"]
    assert "Not applicable to it: RBI FREE-AI (Supply Chain), SEBI CSCRF." in " ".join(text["other"].split())


def test_the_export_carries_the_profile():
    src = (Path(__file__).resolve().parents[1] / "routers" / "scans.py").read_text(encoding="utf-8")
    body = src[src.index("def _build_scan_report("):src.index("async def export_scan(")]
    assert 'scan_data = bom_applicability.with_pdf_profile("sbom_sca", scan_data, session, team_id)' in body
