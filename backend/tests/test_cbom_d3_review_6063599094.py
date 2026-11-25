"""PR #500 re-review 6063599094 (backend): unconfirmed settings and test code are listed but not scored on every
surface, the PDF states the rule, and the flat risk_score / risk_grade agree with a ``risk_posture`` object wherever
one is present (so #505's object plugs in on the same number)."""
from __future__ import annotations

import io
import types

import pytest

from backend.utilities.cbom_sources.cbom_metrics import summarize_code_rows


def _row(title: str, impact: str, location: str, **extra) -> dict:
    return {"title": title, "algorithm_name": title, "impact": impact, "finding_codes": ["WEAK_ALGORITHM"],
            "weak": True, "crypto_strength": "weak", "location": location, **extra}


APP = [_row("MD5", "High", "app/crypto.py")]
UNCONFIRMED = [_row("MD5", "Low", "app/conf.py", config_status="unconfirmed", confidence="low",
                    config_binding="checksum")]
TEST_ONLY = [_row("MD5", "Low", "tests/test_h.py", code_context="test")]


def _scan(rows: list[dict]) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        id=1, scan_data={"results": rows, "duration_of_scan": 1.0}, scan_status="success", scan_metadata={},
        title="t", created_at=None, last_updated=None, credit_consumed=0, info=None, team_id=1,
        owner_user=types.SimpleNamespace(email="e@example.com", first_name="a", last_name="b", full_name="a b"))


def _surfaces(rows: list[dict], monkeypatch) -> dict[str, dict]:
    from backend.utilities.dashboard import scan as dashboard
    from backend.utilities.dashboard import scan_list as scan_list_mod
    from backend.utilities.db.scan_list_item import return_cbom_list_item

    monkeypatch.setattr(dashboard, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id", lambda *a, **k: [])
    return {
        "list_row": return_cbom_list_item(_scan(rows)),
        "list_tile": scan_list_mod.generate_cbom_dashboard_data([_scan(rows)])["card_data"],
        "results_tile": dashboard.generate_scan_dashboard("cbom", scan_object=_scan(rows))["card_data"],
    }


def test_an_unconfirmed_setting_alone_scores_zero_a(monkeypatch):
    summary = summarize_code_rows(UNCONFIRMED)
    assert (summary.risk["risk_score"], summary.risk["risk_grade"]) == (0, "A")
    assert summary.findings == 1 and summary.findings_unconfirmed == 1, "listed, not scored"
    for name, s in _surfaces(UNCONFIRMED, monkeypatch).items():
        assert (s["risk_score"], s["risk_grade"]) == (0, "A"), name


def test_a_test_code_only_scan_is_zero_a_everywhere(monkeypatch, tmp_path):
    for name, s in _surfaces(TEST_ONLY, monkeypatch).items():
        assert (s["risk_score"], s["risk_grade"]) == (0, "A"), name
    text = _pdf_text({"results": TEST_ONLY, "duration_of_scan": 1.0}, tmp_path)
    assert "A Risk score 0 Low risk" in text


@pytest.mark.parametrize("rows", [APP, APP + UNCONFIRMED + TEST_ONLY, TEST_ONLY, []])
def test_flat_risk_fields_agree_with_a_risk_posture_object(rows, monkeypatch):
    """Wherever a ``risk_posture`` object (#505's ``risk_scale.posture_field`` shape: score, grade, label, band) sits
    next to the flat fields, both say the same number."""
    for name, s in _surfaces(rows, monkeypatch).items():
        posture = s.get("risk_posture")
        if posture is None:
            continue
        assert (posture["score"], posture["grade"], posture["label"]) == (
            s["risk_score"], s["risk_grade"], s["risk_label"]), name


def _pdf_text(data: dict, tmp_path) -> str:
    pypdf = pytest.importorskip("pypdf")
    from backend.utilities.pdf.cbom_pdf import generate_pdf

    out = tmp_path / "d3.pdf"
    generate_pdf(data, str(out))
    reader = pypdf.PdfReader(io.BytesIO(out.read_bytes()))
    return " ".join(" ".join(page.extract_text() or "" for page in reader.pages).split())


def test_pdf_states_the_unconfirmed_rule_and_counts_them(tmp_path):
    text = _pdf_text({"results": APP + UNCONFIRMED, "duration_of_scan": 1.0}, tmp_path)
    risk = summarize_code_rows(APP).risk
    assert f"{risk['risk_grade']} Risk score {risk['risk_score']} {risk['risk_label']}" in text
    assert "unconfirmed (configuration only)" in text
    assert "Unconfirmed settings (configuration only; listed, not scored) 1" in text
