"""The AI BOM risk score is one function, bounded by the findings (audit-C G-D5-4) and the PDF shows the SOW checks.

Staging (peva3/SmarterRouter, ai_bom #9): 0 critical, 0 high, 10 medium, 32 low rows, yet the PDF printed
"F 100 Critical risk", the engine's heatmap "100/100 HIGH", and the dashboard card 3.1 from a third formula. Now:

* the PDF grade uses ``report_branding.compute_posture_risk_score``, the same formula as the engine's
  ``aibom.score.scorer.posture_score`` (pinned below over a grid of counts), never worse than the worst severity;
* the PDF's summary rows and the results tile show that same posture score, grade and words, never a second 0-10
  average (PR #500 takeover);
* the PDF lists the SOW AI BOM checks (CERT-In AIBOM, RBI FREE-AI, SEBI CSCRF, NIST AI RMF, EU AI Act Annex IV) with
  every requirement's verdict, and no out-of-scope healthcare framework row.

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_aibom_risk_score_consistency.py -q
"""
from __future__ import annotations

import io
import itertools
import pathlib
import sys

import pytest

from backend.utilities.dashboard.risk_scale import average_risk_of
from backend.utilities.pdf.ai_bom_pdf import generate_pdf
from backend.utilities.pdf.report_branding import compute_posture_risk_score, compute_risk_score

_AIBOM_SRC = pathlib.Path(__file__).resolve().parents[2] / "aibom" / "src"


@pytest.fixture(scope="module")
def engine_posture_score():
    # import the engine from aibom/src without leaking it: another test may have left a namespace ``aibom`` (the
    # repository folder) in sys.modules, and later tests must see sys.modules as they left it
    saved = {k: sys.modules.pop(k) for k in list(sys.modules) if k == "aibom" or k.startswith("aibom.")}
    sys.path.insert(0, str(_AIBOM_SRC))
    try:
        from aibom.score.scorer import posture_score
    finally:
        sys.path.remove(str(_AIBOM_SRC))
        for k in [k for k in sys.modules if k == "aibom" or k.startswith("aibom.")]:
            del sys.modules[k]
        sys.modules.update(saved)
    return posture_score


def test_pdf_grade_and_engine_score_are_one_function(engine_posture_score):
    values = (0, 1, 2, 5, 10, 32)
    for counts in itertools.product(values, repeat=4):
        score, grade, band = compute_posture_risk_score(*counts)
        assert score == engine_posture_score(*counts), counts
        critical, high, medium, low = counts
        if not critical:
            assert grade != "F", counts
        if not critical and not high:
            assert grade not in ("F", "D"), counts
        if not critical and not high and not medium:
            assert grade in ("A", "B"), counts
        if critical:  # with a critical finding nothing is capped: the shared grade stands
            assert (score, grade, band) == compute_risk_score(*counts)


def _rows(medium: int, low: int) -> list[dict]:
    rows = [{"component_name": f"lib-{i}", "component_type": "ml_framework", "impact": "Medium",
             "risk_category": "license_compliance_gap", "title": f"lib-{i}"} for i in range(medium)]
    rows += [{"component_name": f"model-{i}", "component_type": "local_model_file", "impact": "Low",
              "risk_category": "missing_model_card_lineage", "title": f"model-{i}"} for i in range(low)]
    return rows


def _requirement(rid: str, verdict: str) -> dict:
    return {"id": rid, "title": f"title {rid}", "verdict": verdict, "evidence": f"evidence {rid}", "refs": []}


def _framework(*verdicts: str) -> dict:
    reqs = [_requirement(f"R-{i}", v) for i, v in enumerate(verdicts)]
    counts = {k: sum(1 for v in verdicts if v == k) for k in
              ("pass", "pass_with_evidence", "fail", "out_of_scope", "not_bom_evidenceable", "na")}
    applicable = counts["pass"] + counts["pass_with_evidence"] + counts["fail"]
    return {**counts, "coverage": round((counts["pass"] + counts["pass_with_evidence"]) / applicable, 3)
            if applicable else None, "requirements": reqs}


def _payload() -> dict:
    return {
        "results": _rows(10, 32),
        "duration_of_scan": 1.2,
        "ai_bom_json": {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "machine-learning-model", "name": "gpt-4o", "bom-ref": "m1"}],
            "services": [{"bom-ref": "s1", "name": "OpenAI API"}],
            "metadata": {"properties": [{"name": "aibom:model_mentions_catalog", "value": "59"},
                                        {"name": "aibom:dependencies_excluded_dev_tools", "value": "7"}]}},
        "ai_bom_compliance": {
            "cert_in_aibom": _framework("pass", "pass", "fail", "not_bom_evidenceable"),
            "rbi_free_ai": _framework("fail", "not_bom_evidenceable", "na"),
            "sebi_cscrf_aibom": _framework("pass", "fail"),
            "nist_rmf": _framework("fail", "not_bom_evidenceable"),
            "eu_ai_act_annexIV": _framework("fail", "pass_with_evidence"),
            "fda_524b": _framework("out_of_scope", "out_of_scope"),
            "hipaa": _framework("out_of_scope"),
            "disclaimer": "Regulatory and standards mappings are advisory only.",
        },
    }


def _pdf_text(tmp_path: pathlib.Path, payload: dict) -> str:
    pypdf = pytest.importorskip("pypdf")
    out = tmp_path / "aibom.pdf"
    generate_pdf(payload, str(out))
    reader = pypdf.PdfReader(io.BytesIO(out.read_bytes()))
    return " ".join(" ".join(page.extract_text() or "" for page in reader.pages).split())


def test_smarterrouter_counts_no_longer_print_critical_risk(tmp_path):
    text = _pdf_text(tmp_path, _payload())
    assert "Critical risk" not in text
    score, grade, band = compute_posture_risk_score(0, 0, 10, 32)
    assert (score, grade, band) == (49, "C", "Elevated risk")
    assert band in text and str(score) in text
    # the summary rows print the headline's number, not a 0-10 average (PR #500 takeover)
    assert "Risk score 49 / 100 · grade C · Elevated risk" in text
    assert "Average risk score" not in text and f"{average_risk_of(['Medium'] * 10 + ['Low'] * 32):.1f}" not in text


def test_aibom_results_tile_reads_the_posture_score(monkeypatch):
    import types

    from backend.utilities.dashboard import scan as dashboard
    from backend.utilities.dashboard.scan import generate_scan_dashboard

    monkeypatch.setattr(dashboard, "get_findings_for_scan_id", lambda *a, **k: [])

    rows = [{"impact": "Medium", "component_type": "python_package"}] * 10 + \
        [{"impact": "Low", "component_type": "python_package"}] * 32
    card = generate_scan_dashboard("ai_bom", scan_object=types.SimpleNamespace(
        id=1, scan_data={"results": rows}))["card_data"]
    assert (card["risk_score"], card["risk_grade"], card["risk_label"]) == (49, "C", "Elevated risk")


def test_pdf_lists_the_sow_aibom_checks_with_every_requirement(tmp_path):
    text = _pdf_text(tmp_path, _payload())
    assert "AI BOM regulatory checks" in text
    for label in ("CERT-In AIBOM", "RBI FREE-AI Framework", "SEBI CSCRF", "NIST AI RMF", "EU AI Act Annex IV"):
        assert label in text, label
    for verdict in ("Pass (attested)", "Needs evidence", "Fail"):
        assert verdict in text
    assert "evidence R-0" in text
    # out-of-scope healthcare frameworks are not listed (not in the summary tables either)
    assert "FDA Section 524B" not in text and "fda_524b" not in text and "hipaa" not in text
    # what the AI BOM left out is said, not silently dropped
    assert "Models in use" in text and "catalogs (not counted)" in text


def test_healthcare_framework_in_scope_is_listed(tmp_path):
    payload = _payload()
    payload["ai_bom_compliance"]["hipaa"] = _framework("fail", "pass")
    text = _pdf_text(tmp_path, payload)
    assert "HIPAA" in text
