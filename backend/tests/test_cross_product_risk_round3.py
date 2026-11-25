"""Review 6065663183 of #505 (round 3): the reviewer's probes, as tests.

1. Merged with #500, the CBOM gate only gates: a judged scan or team keeps #500's ``risk_posture`` and flat
   ``risk_score`` / ``risk_grade`` / ``risk_label``; without them, the score counts what #500's ``summary.scored``
   counts (no test code, no unconfirmed setting), never ``summary.severity``.
2. The SBOM tile scores each target by its row's rule, then combines: never a better tier than its worst row.
3. The floor reaches every score: the CBOM Board Report (D14), a stored AI BOM scan's "Risk by Component", and every
   PDF headline that took the unfloored ``compute_risk_score``.
4. Tile target keys: uploads by content hash, custom LLM models by endpoint, repository URLs normalised, a scan with
   no branch on the repository's recorded default branch, DAST paths kept as typed.
5. The CERT-In evidence pack's SBOM report.pdf lists the frameworks that bind the team, as /export.
6. 1 confirmed Low + guessed Criticals: the confirmed score is shown, the worst case (``risk_unverified.worst_case``)
   is what the risk filter and the sort read.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.utilities.dashboard import risk_rollup, risk_scale
from backend.utilities.dashboard import scan as scan_mod
from backend.utilities.dashboard import scan_list as scan_list_mod
from backend.utilities.db import scan_list_item as items

T0 = dt.datetime(2026, 11, 24, 9, 0, tzinfo=dt.timezone.utc)
OWNER = SimpleNamespace(email="o@example.test", first_name="O", last_name="Wner")
P, S = risk_scale.POSTURE_KEY, risk_scale.STATUS_KEY


@pytest.fixture(autouse=True)
def _no_mongo(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: [])


def _sg(obj):
    p = obj.get(P)
    return None if p is None else (p["score"], p["grade"])


# ------------------------------------------------------------------------------------------------- 1. CBOM gate
def _crypto(impact, i, **extra):
    return {"title": f"MD5-{i}", "algorithm_name": "MD5", "algorithm_type": "hash", "impact": impact, "weak": True,
            "finding_codes": ["WEAK_ALGORITHM"], "crypto_strength": "weak", "quantum_safe": False,
            "owasp_top_10": {}, "compliance_controls": {}, "file_path": f"src/f{i}.py", **extra}


TEST_HIGHS = [_crypto("High", i, code_context="test", file_path=f"tests/t{i}.py") for i in range(6)]
APP_LOW = [_crypto("Low", 99)]
UNCONFIRMED_CRIT = [_crypto("Critical", 50, config_status="unconfirmed")]


def _cbom(rows, status="success", sid=11):
    return SimpleNamespace(
        id=sid, title="c", scan_type="cbom", scan_status=status, team_id=1, created_at=T0, last_updated=T0,
        credit_consumed=1.0, info=None, owner_user=OWNER,
        scan_metadata={"repo_url": "https://github.com/acme/app", "branch": "main"},
        scan_data={"results": rows, "duration_of_scan": 1.0})


def _flat(obj):
    return (obj.get("risk_score"), obj.get("risk_grade"))


def _agree(obj, want, where):
    """``risk_posture`` is ``want``; #500's flat fields, when present, say the same."""
    assert _sg(obj) == want, (where, obj.get(P))
    if "risk_score" in obj:  # #500 merged
        assert _flat(obj) == want, (where, _flat(obj))


@pytest.mark.parametrize("rows, want", [
    (TEST_HIGHS, (0, "A")),  # the reviewer's probe: 6 Highs, all in test code, read 69 · D
    (APP_LOW + TEST_HIGHS, (4, "A")),  # 1 app Low + the 6 test Highs read 69 · D
    (APP_LOW + UNCONFIRMED_CRIT, (4, "A")),  # a setting no crypto call is proven to read is listed, not scored
], ids=["test-code-only", "app-low-plus-test-highs", "unconfirmed-setting"])
def test_cbom_scores_count_what_500_scores(rows, want):
    scan = _cbom(rows)
    _agree(items.return_cbom_list_item(scan), want, "row")
    tile = scan_list_mod.generate_cbom_dashboard_data([scan])["card_data"]
    _agree(tile, want, "tile")
    assert tile[S] == "scored"
    card = scan_mod.generate_scan_dashboard(scan_type="cbom", scan_object=scan)["card_data"]
    if P in card or "risk_score" in card:  # the results card carries a score once #500 is merged
        _agree(card, want, "card")


def test_the_cbom_gate_only_gates_a_judged_scan():
    """Merged with #500 the row already carries its posture: the gate adds the status and changes nothing else."""
    scan = _cbom(TEST_HIGHS)
    p500 = {"score": 0, "grade": "A", "label": "Low risk", "band": "low"}
    row = {"risk_score": 0, "risk_grade": "A", "risk_label": "Low risk", P: dict(p500)}
    out = items._cbom_gate(scan, row, scan.scan_data["results"])
    assert out[P] == p500 and _flat(out) == (0, "A") and out[S] == "scored"
    # without #500's fields: the scored counts (test code out), never summary.severity (6 Highs = 69 · D)
    out = items._cbom_gate(scan, {}, scan.scan_data["results"])
    assert _sg(out) == (0, "A") and out[S] == "scored" and "risk_score" not in out


@pytest.mark.parametrize("status", ["failure", "started", "cancelled", "pending"])
def test_the_cbom_gate_blanks_a_scan_that_did_not_succeed(status):
    row = {"risk_score": 70, "risk_grade": "F", "risk_label": "Critical risk", P: {"score": 70, "grade": "F"}}
    out = items._cbom_gate(_cbom(APP_LOW, status), row, APP_LOW)
    assert out[P] is None and out[S] == "not_scored" and _flat(out) == (None, None) and out["risk_label"] is None


def test_the_cbom_tile_gate_only_gates_a_judged_team():
    p500 = {"score": 4, "grade": "A", "label": "Low risk", "band": "low"}
    out = {"card_data": {"risk_score": 4, "risk_grade": "A", "risk_label": "Low risk", P: dict(p500)},
           "severity_distribution": {"high": 6, "low": 1, "informational": 0}}
    card = scan_list_mod._gate_cbom_tile([object()], SimpleNamespace(rows=[]), out, APP_LOW)["card_data"]
    assert card[P] == p500 and _flat(card) == (4, "A") and card[S] == "scored"
    # no #500 fields: the scored counts, not the severity distribution (6 Highs + 1 Low = 69 · D)
    card = scan_list_mod._gate_cbom_tile([object()], SimpleNamespace(rows=[]), {
        "card_data": {}, "severity_distribution": {"high": 6, "low": 1}}, APP_LOW + TEST_HIGHS)["card_data"]
    assert _sg(card) == (4, "A") and "risk_score" not in card


def test_scored_counts_follow_500s_rule():
    counts = risk_rollup.cbom_scored_counts(APP_LOW + TEST_HIGHS + UNCONFIRMED_CRIT + [
        {"algorithm_name": "AES-256-GCM", "finding_codes": [], "impact": None}, "not a row"])
    assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 1}


# ------------------------------------------------------------------------------------------------- 2. SBOM tile
INVENTORY = {"title": "Inventory: left-pad", "dependency": "left-pad==1.3.0", "impact": "Low", "inventory_only": True,
             "description": "", "compliance_controls": {}, "owasp_top_10": {}}
GUESSED = {"dependency": "pillow==10.0", "version_guessed_from": ">=10.0"}


def _vulns(impacts, **extra):
    return [{"title": f"v{i}", "description": "d", "impact": imp, "category": "vuln", "confidence": "high",
             "compliance_controls": {}, "owasp_top_10": {}, "dependency": "ok==1.0", **extra}
            for i, imp in enumerate(impacts)]


def _sbom(confirmed, guessed, *, sid, repo):
    return SimpleNamespace(
        id=sid, title=f"s{sid}", scan_type="sbom_sca", scan_status="success", team_id=1,
        created_at=T0 + dt.timedelta(hours=sid), last_updated=T0, credit_consumed=1.0, info=None, owner_user=OWNER,
        scan_metadata={"repo_url": f"https://github.com/acme/{repo}", "branch": "main"},
        scan_data={"results": [dict(INVENTORY), *_vulns(confirmed), *_vulns(guessed, **GUESSED)],
                   "duration_of_scan": 1.0, "metadata": {}})


GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def _tile(scans):
    return scan_list_mod.generate_sbom_sca_dashboard_data(scans)["card_data"]


def test_the_sbom_tile_is_never_better_than_its_worst_row():
    """The reviewer's probe: A has only guessed Criticals (row 100 · F unverified), B one confirmed Low (4 · A); the
    tile read 4 · A scored."""
    a, b = _sbom([], ["Critical"] * 10, sid=1, repo="a"), _sbom(["Low"], [], sid=2, repo="b")
    rows = [items.return_sbom_sca_list_item(s) for s in (a, b)]
    assert [(_sg(r), r[S]) for r in rows] == [((100, "F"), "unverified"), ((4, "A"), "scored")]
    tile = _tile([a, b])
    assert _sg(tile) == (100, "F") and tile[S] == "unverified"
    assert tile[risk_scale.UNVERIFIED_KEY]["count"] == 10


@pytest.mark.parametrize("targets", [
    [([], ["Critical"]), (["Low"], [])],
    [([], ["High"] * 3), (["Medium"], []), (["Low"] * 2, ["Critical"])],
    [(["Low"], ["Critical"] * 10), (["Medium"], [])],
    [([], ["Medium"]), ([], ["Low"])],
    [(["High"], []), (["Low"], ["Medium"])],
])
def test_the_sbom_tile_tier_is_at_least_every_rows(targets):
    scans = [_sbom(c, g, sid=i + 1, repo=f"r{i}") for i, (c, g) in enumerate(targets)]
    rows = [items.return_sbom_sca_list_item(s) for s in scans]
    tile = _tile(scans)
    assert GRADE_RANK[tile[P]["grade"]] >= max(GRADE_RANK[r[P]["grade"]] for r in rows)
    assert tile[P]["score"] >= max(r[P]["score"] for r in rows)
    want = "unverified" if any(r[S] == "unverified" for r in rows) else "scored"
    assert tile[S] == want
    assert (tile[risk_scale.UNVERIFIED_KEY] is not None) == any(g for _c, g in targets)


def test_the_sbom_tile_of_confirmed_targets_is_their_sum():
    scans = [_sbom(["High"], [], sid=1, repo="a"), _sbom(["Low"], [], sid=2, repo="b")]
    tile = _tile(scans)
    assert _sg(tile) == (50, "D") and tile[S] == "scored" and tile[risk_scale.UNVERIFIED_KEY] is None


# ------------------------------------------------------------------------------------------------- 6. mixed SBOM
def test_mixed_confirmed_and_guessed_show_confirmed_and_triage_on_the_worst_case():
    """1 confirmed Low + 10 guessed Criticals: shown 4 · A with the note; the filter and the sort read the worst case
    (confirmed + guessed), 100 · F, so the scan is also under Critical (unverified)."""
    scan = _sbom(["Low"], ["Critical"] * 10, sid=3, repo="m")
    row = items.return_sbom_sca_list_item(scan)
    card = scan_mod.generate_scan_dashboard(scan_type="sbom_sca", scan_object=scan)["card_data"]
    for got in (row, card):
        assert _sg(got) == (4, "A") and got[S] == "scored"
        worst = got[risk_scale.UNVERIFIED_KEY]["worst_case"]
        assert (worst["score"], worst["grade"]) == (100, "F") and worst["weighted"] == 101
    only = items.return_sbom_sca_list_item(_sbom([], ["High"], sid=4, repo="n"))
    assert _sg(only) == (50, "D") and only[risk_scale.UNVERIFIED_KEY]["worst_case"]["score"] == 50
    assert items.return_sbom_sca_list_item(_sbom(["Low"], [], sid=5, repo="o"))[risk_scale.UNVERIFIED_KEY] is None


# ------------------------------------------------------------------------------------------------- 3. the floor
def test_compute_risk_score_is_the_shared_posture():
    from backend.utilities.pdf.report_branding import compute_posture_risk_score, compute_risk_score

    for counts, want in (((1, 0, 0, 0), (70, "F", "Critical risk")), ((0, 15, 0, 0), (69, "D", "High risk")),
                         ((0, 1, 0, 0), (50, "D", "High risk")), ((0, 0, 0, 0), (0, "A", "Low risk"))):
        assert compute_risk_score(*counts) == compute_posture_risk_score(*counts) == want, counts


def test_the_board_report_grades_with_the_shared_posture(monkeypatch):
    from backend.utilities.pdf import cbom_board_report_pdf as board

    def view(c, h, m, low):
        return SimpleNamespace(issue_by_impact={"Critical": c, "High": h, "Medium": m, "Low": low})

    monkeypatch.setattr(board, "posture_active", lambda v: False)
    monkeypatch.setattr(board, "_not_assessed_reason", lambda v: None)
    one_critical = board.posture_grade(view(1, 0, 0, 0))
    assert (one_critical.score, one_critical.grade, one_critical.band) == (70, "F", "Critical risk")  # read 40 C
    many_highs = board.posture_grade(view(0, 15, 0, 0))
    assert (many_highs.score, many_highs.grade) == (69, "D")  # read 100 F
    assert many_highs.weighted_points == 75


def test_the_board_report_prints_the_bounded_formula():
    from backend.utilities.pdf import cbom_board_report_pdf as board
    from backend.utilities.pdf import cbom_deliverable_text as text
    from backend.utilities.pdf.report_branding import POSTURE_METHOD

    assert "at least 70" in text.GRADE_FORMULA and "at most 69" in text.GRADE_FORMULA
    assert text.GRADE_FLOORS == {"Critical": 70, "High": 50}
    assert text.GRADE_CAPS == {"Critical": 100, "High": 69, "Medium": 49, "Low": 29}
    assert POSTURE_METHOD  # the per-scan PDFs' line says the same rule
    posture = board.PostureGrade(True, "F", 70, "Critical risk", None, 1, 0, 0, 0, 10)
    assert board.worked_grade_text(posture) == (
        "Weighted points: 10. Score = min(100, 4 x 10) = 40, raised to 70 by the Critical floor. "
        "Grade F (Critical risk).")
    posture = board.PostureGrade(True, "D", 69, "High risk", None, 0, 15, 0, 0, 75)
    assert board.worked_grade_text(posture) == (
        "Weighted points: 75. Score = min(100, 4 x 75) = 100, capped at 69 when the worst finding is High. "
        "Grade D (High risk).")
    posture = board.PostureGrade(True, "F", 100, "Critical risk", None, 1, 25, 5, 0, 145)
    assert board.worked_grade_text(posture) == (
        "Weighted points: 145. Score = min(100, 4 x 145) = 100. Grade F (Critical risk).")


def test_every_pdf_headline_defaults_to_the_shared_posture(tmp_path):
    """append_executive_summary's default (the CBOM Sources-run PDF and, before #500, the CBOM scan PDF use it)."""
    import inspect

    from backend.utilities.pdf import report_branding

    src = inspect.getsource(report_branding.append_executive_summary)
    assert "(risk_score_fn or compute_posture_risk_score)(" in src


def test_a_stored_ai_bom_scan_reads_risk_by_component_on_the_floor():
    """Stored before the floor: 1 Critical saved as 40 / elevated; the page's "Risk by Component" read it."""
    stored = {"risk_total": 9.0, "risk_normalized": 40.0, "risk_band": "elevated", "risk_grade": "C",
              "risk_label": "Elevated risk", "by_component": {"model.pt": 9.0},
              "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0}}
    now = risk_scale.ai_bom_scores_now(stored, [])
    assert (now["risk_normalized"], now["risk_band"], now["risk_grade"], now["risk_label"]) == \
        (70.0, "critical", "F", "Critical risk")
    assert now["by_component"] == {"model.pt": 9.0} and stored["risk_normalized"] == 40.0  # not mutated
    # older still: no stored severity counts; the scan's rows by impact, as its headline and PDF count them
    older = {k: v for k, v in stored.items() if k != "severity_counts"}
    now = risk_scale.ai_bom_scores_now(older, [{"impact": "High"}, {"impact": "Low"}, {"impact": None}])
    assert (now["risk_normalized"], now["risk_grade"]) == (50.0, "D")
    assert risk_scale.ai_bom_scores_now(None, []) is None


def test_the_ai_bom_metadata_serves_the_recomputed_scores():
    from backend.utilities.dashboard.scan_metadata import get_scan_metadata

    scan = SimpleNamespace(id=5, scan_type="ai_bom", scan_status="success", scan_metadata={}, scan_data={
        "results": [{"impact": "Critical"}],
        "ai_bom_scores": {"risk_normalized": 40.0, "risk_band": "elevated",
                          "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0}}})
    scores = get_scan_metadata("ai_bom", scan)["ai_bom_scores"]
    assert (scores["risk_normalized"], scores["risk_band"]) == (70.0, "critical")


# ------------------------------------------------------------------------------------------------- 4. target keys
def _scan(scan_type, meta, *, sid=1, title="t", estimate=None):
    return SimpleNamespace(id=sid, title=title, scan_type=scan_type, scan_status="success", scan_metadata=meta,
                           scan_data={}, credit_estimate=estimate, created_at=T0)


def test_uploads_are_never_keyed_on_the_bare_title_case():
    """Round 3 keyed uploads on their file hash; round 4 (review 6066492618) keys them on the project
    (test_cross_product_risk_round4.py). Kept here: an upload's key never depends on the title's case or extension."""
    k = risk_rollup.target_key
    up = {"zip_file_used": True}
    a = _scan("sast", up, sid=1, title="App.ZIP", estimate={"file_sha256": "a" * 64})
    b = _scan("sast", up, sid=2, title="app.zip", estimate={"file_sha256": "b" * 64})
    assert k("sast", a) == k("sast", b) == ("upload", "app")


def test_custom_llm_models_are_keyed_by_endpoint_and_model():
    k = risk_rollup.target_key

    def llm(sid, **meta):
        return _scan("llm", meta, sid=sid)

    one = llm(1, model_type="custom", model_name="chat", model_uri="https://ml.acme.test/v1/")
    other = llm(2, model_type="custom", model_name="chat", model_uri="https://ml.other.test/v1")
    again = llm(3, model_type="custom", model_name="chat", model_uri="HTTPS://ML.acme.test/v1")
    assert k("llm", one) != k("llm", other) and k("llm", one) == k("llm", again)
    # endpoint not recorded (a scan stored before round 3): grouped by its name (round 4)
    assert k("llm", llm(4, model_type="custom", model_name="chat")) == ("model", "custom", "chat")
    assert k("llm", llm(5, model_type="openai", model_name="gpt-4o")) != k("llm", llm(6, model_type="azure",
                                                                                      model_name="gpt-4o"))
    assert k("llm", llm(7, model_type="openai", model_name="gpt-4o")) == k("llm", llm(8, model_type="openai",
                                                                                      model_name="gpt-4o"))


def test_llm_metadata_records_the_endpoint_without_credentials():
    from backend.utilities.db.metadata import get_scan_metadata_for_type

    llm = SimpleNamespace(model_type="custom", model_name="chat", generations=1, probes=[],
                          model_uri="https://user:secret@ml.acme.test:8443/v1/chat?api_key=k#x")
    meta = get_scan_metadata_for_type("llm", SimpleNamespace(llm=llm))
    assert meta["model_uri"] == "https://ml.acme.test:8443/v1/chat"
    assert "secret" not in repr(meta) and "api_key" not in repr(meta)
    llm.model_uri = None
    assert get_scan_metadata_for_type("llm", SimpleNamespace(llm=llm))["model_uri"] is None


@pytest.mark.parametrize("a, b", [
    ("https://github.com/acme/app.git", "https://github.com/acme/app"),
    ("https://GitHub.com/acme/app/", "https://github.com/acme/app"),
    ("http://github.com/acme/app", "https://github.com/acme/app"),
    ("git@github.com:acme/app.git", "https://github.com/acme/app"),
    ("https://token@github.com/acme/app.git/", "https://github.com/acme/app"),
])
def test_repository_urls_are_normalised(a, b):
    k = risk_rollup.target_key
    assert k("sast", _scan("sast", {"repo_url": a, "branch": "main"})) == \
        k("sast", _scan("sast", {"repo_url": b, "branch": "main"}))


def test_a_scan_without_a_branch():
    k = risk_rollup.target_key
    repo = "https://github.com/acme/app"
    main = k("sast", _scan("sast", {"repo_url": repo, "branch": "main"}))
    # the repository's default branch, when the scan records it: the same code as a "main" scan
    assert k("sast", _scan("sast", {"repo_url": repo, "branch": None, "default_branch": "main"})) == main
    # not recorded: its own target (the repository's unnamed default), one for every such scan of the repository
    none1 = k("sast", _scan("sast", {"repo_url": repo, "branch": None}, sid=1))
    none2 = k("sast", _scan("sast", {"repo_url": repo, "branch": ""}, sid=2))
    assert none1 == none2 != main


def test_dast_lowercases_scheme_and_host_never_the_path():
    k = risk_rollup.target_key

    def dast(url):
        return k("dast", _scan("dast", {"target_url": url}))

    assert dast("HTTPS://Shop.Example.com/App/") == dast("https://shop.example.com/App")
    assert dast("https://shop.example.com/App") != dast("https://shop.example.com/app")
    assert dast("https://shop.example.com/") == dast("https://shop.example.com")


# ------------------------------------------------------------------------------------------------- 5. evidence pack
def test_the_evidence_pack_sbom_pdf_carries_the_team_profile():
    src = (Path(__file__).resolve().parents[1] / "routers" / "certin.py").read_text(encoding="utf-8")
    body = src[src.index("def _build_evidence_pack("):src.index("def _pack_members(")]
    assert 'data = bom_applicability.with_pdf_profile("sbom_sca", data, session, team_id)' in body
    # after the scan data was saved: the profile is never stored on the scan
    assert body.index("with_pdf_profile") > body.index("_save_scan_data(")


def test_the_evidence_pack_pdf_lists_the_frameworks_that_bind_the_team(monkeypatch):
    from backend.routers import certin
    from backend.utilities.compliance import bom_applicability as ba

    seen = {}
    monkeypatch.setattr(certin, "_pack_pdf", lambda scan_type, data, ctx: seen.update(data=data) or b"%PDF")
    monkeypatch.setattr(certin.SIGN, "pack_files", lambda files, **k: [])
    data = {"results": [], ba.PDF_PROFILE_KEY: {"profile": {"entity_type": "other"}, "declared": True}}
    certin._pack_members("sbom_sca", 9, 1, data, None, SimpleNamespace(), subject_name="app")
    assert seen["data"][ba.PDF_PROFILE_KEY] == {"profile": {"entity_type": "other"}, "declared": True}
