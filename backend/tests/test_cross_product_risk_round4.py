"""Review 6066492618 of #505 (round 4): the reviewer's probes, as tests.

1. An upload's tile target is its project: the uploaded BOM's subject (``metadata.component.name``, version-less), else
   the upload title without extension or version; the file hash only when neither names one.
2. The CBOM gate passes any ``risk_posture_status`` through (#500's coming ``unverified`` too): it computes only when
   neither #500 field is there, and never turns ``unverified`` or ``incomplete`` into ``scored 0 · A``.
3. The Board Report (D14) counts as the other surfaces: test code is not scored; an unconfirmed setting is
   "unverified" (its worst case when it is all the team has, else a note). Board Report = dashboard tile.
4. Every posture PDF prints the "Risk score" method line, the CBOM scan and run PDFs too, with the CBOM sentence.
5. A custom LLM scan stored before the endpoint was recorded groups by its model name.
"""
from __future__ import annotations

import datetime as dt
import itertools
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.utilities.dashboard import risk_rollup, risk_scale
from backend.utilities.dashboard import scan as scan_mod
from backend.utilities.dashboard import scan_list as scan_list_mod
from backend.utilities.db import scan_list_item as items

T0 = dt.datetime(2026, 11, 25, 9, 0, tzinfo=dt.timezone.utc)
OWNER = SimpleNamespace(email="o@example.test", first_name="O", last_name="Wner")
P, S, U = risk_scale.POSTURE_KEY, risk_scale.STATUS_KEY, risk_scale.UNVERIFIED_KEY
_IDS = itertools.count(4000)


@pytest.fixture(autouse=True)
def _no_mongo(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: [])


def _sg(obj):
    p = obj.get(P)
    return None if p is None else (p["score"], p["grade"])


# ------------------------------------------------------------------------------------------------- 1. uploads
def _upload(scan_type, title, *, sid, sha=None, bom=None, flag="zip_file_used"):
    data = {"results": []}
    if bom is not None:
        data[{"sbom_sca": "sbom_json", "cbom": "cbom_json", "ai_bom": "ai_bom_json"}[scan_type]] = bom
    return SimpleNamespace(id=sid, title=title, scan_type=scan_type, scan_status="success", scan_metadata={flag: True},
                           scan_data=data, credit_estimate={"file_sha256": sha} if sha else None, created_at=T0)


def _cdx(name, version=None):
    comp = {"type": "application", "name": name, **({"version": version} if version else {})}
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": comp}, "components": []}


def test_two_uploads_of_one_project_are_one_target_and_another_project_is_not():
    """The reviewer's probe: each weekly zip of one project was a new target (its own hash), so the tile added them."""
    k = risk_rollup.target_key
    week1 = _upload("sast", "acme-shop-v1.2.zip", sid=1, sha="a" * 64)
    week2 = _upload("sast", "Acme Shop v1.3.ZIP", sid=2, sha="b" * 64)
    dated = _upload("sast", "acme_shop 2026-11-20.tar.gz", sid=3, sha="c" * 64)
    other = _upload("sast", "billing-api-v1.2.zip", sid=4, sha="d" * 64)
    assert k("sast", week1) == k("sast", week2) == k("sast", dated) == ("upload", "acme-shop")
    assert k("sast", other) == ("upload", "billing-api") != k("sast", week1)


def test_an_uploaded_bom_is_keyed_on_its_subject_without_the_version():
    k = risk_rollup.target_key
    a = _upload("sbom_sca", "first import.json", sid=5, bom=_cdx("acme-shop", "1.2.0"), flag="sbom_file_used")
    b = _upload("sbom_sca", "sbom-final.json", sid=6, bom=_cdx("Acme-Shop@1.3.0"), flag="sbom_file_used")
    c = _upload("sbom_sca", "first import.json", sid=7, bom=_cdx("billing-api", "1.2.0"), flag="sbom_file_used")
    assert k("sbom_sca", a) == k("sbom_sca", b) == ("upload", "acme-shop")
    assert k("sbom_sca", c) == ("upload", "billing-api")  # same title, another project
    spdx = {"spdxVersion": "SPDX-2.3", "name": "doc", "documentDescribes": ["SPDXRef-root"],
            "packages": [{"SPDXID": "SPDXRef-root", "name": "acme-shop", "versionInfo": "2.0"}]}
    d = _upload("sbom_sca", "x.spdx.json", sid=8, bom=spdx, flag="sbom_file_used")
    assert k("sbom_sca", d) == ("upload", "acme-shop")
    # a placeholder subject the worker writes for an upload (no repository) is not a project name: the title is
    e = _upload("cbom", "acme-shop-2.zip", sid=9, bom=_cdx("unknown"))
    assert k("cbom", e) == ("upload", "acme-shop")


def test_the_hash_is_only_the_fallback():
    k = risk_rollup.target_key
    assert k("sast", _upload("sast", "v1.2.zip", sid=10, sha="E" * 64)) == ("upload-file", "e" * 64)
    assert k("sast", _upload("sast", "1.0.zip", sid=11)) == ("scan", 11)


def test_the_tile_reads_the_latest_upload_of_a_project(monkeypatch):
    def up(sid, title, hours, impacts):
        scan = _upload("sast", title, sid=sid, sha=str(sid) * 64)
        scan.created_at = scan.last_updated = T0 + dt.timedelta(hours=hours)
        scan.owner_user, scan.credit_consumed, scan.info, scan.team_id = OWNER, 1.0, None, 1
        scan.scan_data = {"results": [{"logical_component_title": "app", "vulnerabilities": [
            {"title": f"f{i}", "impact": imp, "description": "d"} for i, imp in enumerate(impacts)]}]}
        return scan

    scans = [up(1, "shop-v1.zip", 0, ["High"]), up(2, "shop-v2.zip", 1, ["High"]), up(3, "shop-v3.zip", 2, ["High"]),
             up(4, "billing.zip", 3, ["Low"])]
    tile = scan_list_mod.generate_sast_dashboard_data(scans)
    assert tile["risk_posture_scope"]["scan_ids"] == [3, 4]  # one target per project
    assert _sg(tile) == (50, "D")  # 1 High + 1 Low, not 3 Highs added up


# ------------------------------------------------------------------------------------------------- 2. CBOM gate
def _crypto(impact, i, **extra):
    return {"title": f"MD5-{i}", "algorithm_name": "MD5", "algorithm_type": "hash", "impact": impact, "weak": True,
            "finding_codes": ["WEAK_ALGORITHM"], "crypto_strength": "weak", "quantum_safe": False,
            "owasp_top_10": {}, "compliance_controls": {}, "file_path": f"src/f{i}.py", "location": f"src/f{i}.py",
            **extra}


def _cbom(rows, status="success"):
    sid = next(_IDS)
    return SimpleNamespace(
        id=sid, title=f"c{sid}", scan_type="cbom", scan_status=status, team_id=sid, created_at=T0,
        last_updated=T0 + dt.timedelta(seconds=sid), credit_consumed=1.0, info=None, owner_user=OWNER,
        scan_metadata={"repo_url": f"https://github.com/acme/app{sid}", "branch": "main"},
        scan_data={"results": rows, "duration_of_scan": 1.0})


@pytest.mark.parametrize("given", [
    {P: None, S: "unverified"},  # the reviewer's probe: read back as 0 · A "scored"
    {P: {"score": 70, "grade": "F", "label": "Critical risk"}, S: "unverified", "risk_score": 70, "risk_grade": "F"},
    {P: None, S: "incomplete", "risk_score": None, "risk_grade": None},
    {P: {"score": 4, "grade": "A", "label": "Low risk"}, S: "scored", "risk_score": 4, "risk_grade": "A"},
], ids=["unverified-no-posture", "unverified-worst-case", "incomplete", "scored"])
def test_the_cbom_gate_passes_a_status_through(given):
    scan = _cbom([_crypto("Critical", 1)])
    row = items._cbom_gate(scan, dict(given), scan.scan_data["results"])
    assert row == given
    out = scan_list_mod._gate_cbom_tile([object()], SimpleNamespace(rows=[]), {"card_data": dict(given)},
                                        scan.scan_data["results"])["card_data"]
    assert out == given
    for got in (row, out):
        assert not (got[S] == "scored" and _sg(got) == (0, "A") and given[S] != "scored")


def test_the_cbom_gate_computes_only_without_500s_fields():
    scan = _cbom([_crypto("Critical", 1)])
    row = items._cbom_gate(scan, {"title": "x"}, scan.scan_data["results"])
    assert _sg(row) == (70, "F") and row[S] == "scored"
    # #500's posture without a status: kept, and called what it is
    p500 = {"score": 4, "grade": "A", "label": "Low risk"}
    assert items._cbom_gate(scan, {P: dict(p500)}, [])[S] == "scored"
    assert items._cbom_gate(scan, {P: None}, [])[S] == "not_scored"  # never a computed 0 · A under a null posture


# ------------------------------------------------------------------------------------------------- 3. Board Report
def _board_and_tile(rows):
    from backend.utilities.cbom_sources import reconciliation as RECON
    from backend.utilities.cbom_sources.collections_view import SourcesResult
    from backend.utilities.pdf import cbom_board_report_pdf as board

    scan = _cbom(rows)
    tile = scan_list_mod.generate_cbom_dashboard_data([scan], team_id=scan.team_id)["card_data"]
    view = RECON.team_view(scan.team_id, [scan], SourcesResult(), None)
    return board.posture_grade(view), tile, items.return_cbom_list_item(scan)


TEST_HIGHS = [_crypto("High", i, code_context="test", file_path=f"tests/t{i}.py", location=f"tests/t{i}.py")
              for i in range(6)]
UNCONFIRMED_CRIT = [_crypto("Critical", 50, config_status="unconfirmed", location="conf/app.yaml")]


def test_board_report_test_code_only_team_reads_0_a_as_the_tile():
    """The reviewer's probe: 6 test-code Highs read 0 · A on row, card and tile, 69 · D on the Board Report."""
    grade, tile, row = _board_and_tile(TEST_HIGHS)
    assert (grade.score, grade.grade, grade.status) == (0, "A", "scored")
    assert (grade.score, grade.grade) == _sg(tile) == _sg(row)
    assert grade.excluded_test == 6


def test_board_report_unconfirmed_only_team_reads_its_worst_case_unverified():
    """The reviewer's probe: 1 unconfirmed Critical setting read 70 · F scored on the Board Report, 0 · A elsewhere."""
    grade, tile, row = _board_and_tile(UNCONFIRMED_CRIT)
    assert (grade.score, grade.grade, grade.status) == (70, "F", "unverified")
    assert grade.band == "Critical risk (unverified)"
    for got in (tile, row):
        assert _sg(got) == (70, "F") and got[S] == "unverified"
        assert got[U]["kind"] == "unconfirmed_setting" and got[U]["count"] == 1
    assert risk_scale.unverified_note(row[U]) == "unverified: 1 unconfirmed setting (worst: Critical)"


def test_board_report_mixed_team_shows_the_confirmed_score_with_a_note():
    grade, tile, row = _board_and_tile([_crypto("Low", 99)] + UNCONFIRMED_CRIT + TEST_HIGHS)
    assert (grade.score, grade.grade, grade.status) == (4, "A", "scored")
    assert grade.note == "unverified: 1 unconfirmed setting (worst: Critical)"
    for got in (tile, row):
        assert _sg(got) == (4, "A") and got[S] == "scored"
        assert risk_scale.unverified_note(got[U]) == grade.note
        assert got[U]["worst_case"]["score"] == 70  # what the filter and the sort read


@pytest.mark.parametrize("rows", [
    [_crypto("High", 1)], [_crypto("Critical", 1), _crypto("Low", 2)], [_crypto("Medium", i) for i in range(8)],
    TEST_HIGHS, UNCONFIRMED_CRIT, [_crypto("Low", 99)] + UNCONFIRMED_CRIT,
])
def test_board_report_equals_the_dashboard_tile(rows):
    grade, tile, _row = _board_and_tile(rows)
    assert (grade.score, grade.grade) == _sg(tile)
    assert grade.status == tile[S]


def test_board_report_prints_the_exclusion_and_the_unverified_mark():
    from backend.utilities.pdf import cbom_board_report_pdf as board
    from backend.utilities.pdf import cbom_deliverable_text as text

    assert "test, fixture or example code" in text.GRADE_EXCLUSION and "unverified" in text.GRADE_EXCLUSION
    src = Path(board.__file__).read_text(encoding="utf-8")
    assert "_para(authored.GRADE_EXCLUSION, styles)" in src  # Appendix A prints it after the grade input
    grade = board.PostureGrade(True, "A", 4, "Low risk", None, 0, 0, 0, 1, 1, status="scored",
                               note="unverified: 1 unconfirmed setting (worst: Critical)")
    assert board.worked_grade_text(grade).endswith(
        "Grade A (Low risk). Not in the score: unverified: 1 unconfirmed setting (worst: Critical).")


# ------------------------------------------------------------------------------------------------- 4. method line
def _summary_text(**kw):
    from backend.utilities.pdf.report_branding import append_executive_summary, get_report_styles

    story: list = []
    append_executive_summary(story, report_key="cbom", overview_rows=[("Scan type", "CBOM")],
                             severity_counts={"High": 1}, styles=get_report_styles(), project_name="x",
                             scan_time="1s", meta_chips=[("Scan type", "CBOM")], **kw)

    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_pdf_branding import _walk_markup

    return " ".join(_walk_markup(story))


def test_the_method_line_is_an_explicit_flag():
    from backend.utilities.pdf.report_branding import CBOM_METHOD_NOTE

    assert "Risk score:" in _summary_text(posture_method=True)
    assert "Risk score:" in _summary_text()  # no function given: the headline is the shared posture
    assert "Risk score:" in _summary_text(risk_score_fn=lambda *c: (50, "D", "High risk"), posture_method=True)
    assert "Risk score:" not in _summary_text(risk_score_fn=lambda *c: (50, "D", "High risk"))
    text = _summary_text(posture_method=True, method_note=CBOM_METHOD_NOTE)
    assert CBOM_METHOD_NOTE.split(";")[0] in text
    assert "test, fixture or example code" in CBOM_METHOD_NOTE and "unverified" in CBOM_METHOD_NOTE


@pytest.mark.parametrize("module", ["cbom_pdf", "cbom_run_pdf"])
def test_the_cbom_scan_and_run_pdfs_ask_for_the_method_line(module):
    src = (Path(__file__).resolve().parents[1] / "utilities" / "pdf" / f"{module}.py").read_text(encoding="utf-8")
    assert "posture_method=True" in src and "method_note=CBOM_METHOD_NOTE" in src


def test_the_cbom_scan_pdf_prints_the_method_and_the_exclusion(tmp_path):
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import test_pdf_export_smoke as smoke
    from support.pdf_text import pdf_pages_text

    from backend.utilities.pdf.combined import generate_pdf_for_type, prepare_pdf_export_payload

    out = str(tmp_path / "c.pdf")
    generate_pdf_for_type("cbom", prepare_pdf_export_payload("cbom", smoke._typical_payload("cbom")), out)
    page = " ".join(pdf_pages_text(Path(out).read_bytes())[0].split())
    assert "Risk score: 0 to 100 = 4 x (10 per Critical" in page
    assert "Findings in test, fixture or example code are listed but not scored" in page


# ------------------------------------------------------------------------------------------------- 5. legacy LLM
def test_a_legacy_custom_llm_scan_groups_by_its_model_name():
    k = risk_rollup.target_key

    def llm(sid, **meta):
        return SimpleNamespace(id=sid, scan_metadata=meta, scan_data={}, created_at=T0)

    a, b = llm(1, model_type="custom", model_name="chat"), llm(2, model_type="custom", model_name="Chat")
    assert k("llm", a) == k("llm", b) == ("model", "custom", "chat")
    with_endpoint = llm(3, model_type="custom", model_name="chat", model_uri="https://ml.acme.test/v1")
    assert k("llm", with_endpoint) != k("llm", a)
