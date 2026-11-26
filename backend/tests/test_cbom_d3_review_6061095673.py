"""PR #500 review 6061095673 (backend): test code is listed but not scored, the configuration mentions are served and
printed, and BOM-Link fragments are percent-encoded."""
from __future__ import annotations

import io
import types

import pytest

from backend.utilities.cbom_sources import vex_semantics as VEX
from backend.utilities.cbom_sources.cbom_metrics import risk_posture, summarize_code_rows


def _row(title: str, impact: str, location: str, test: bool = False) -> dict:
    return {"title": title, "algorithm_name": title, "impact": impact, "finding_codes": ["WEAK_ALGORITHM"],
            "weak": True, "crypto_strength": "weak", "location": location,
            "code_context": "test" if test else None}


APP = [_row("MD5", "High", "app/crypto.py")]
TESTS = [_row(n, "Low", f"tests/test_{i}.py", test=True) for i in range(6) for n in ("MD5", "SHA-1", "DES")]


def test_test_code_never_moves_the_backend_risk_score():
    base = summarize_code_rows(APP)
    more = summarize_code_rows(APP + TESTS)
    assert more.risk == base.risk == risk_posture({"critical": 0, "high": 1, "medium": 0, "low": 0})
    assert more.findings == base.findings + len(TESTS), "still listed and counted as findings"
    assert more.findings_in_test_code == len(TESTS)


def _pdf_text(data: dict, tmp_path) -> str:
    pypdf = pytest.importorskip("pypdf")
    from backend.utilities.pdf.cbom_pdf import generate_pdf

    out = tmp_path / "d3.pdf"
    generate_pdf(data, str(out))
    reader = pypdf.PdfReader(io.BytesIO(out.read_bytes()))
    return " ".join(" ".join(page.extract_text() or "" for page in reader.pages).split())


def test_pdf_headline_ignores_test_code_and_states_the_rule(tmp_path):
    text = _pdf_text({"results": APP + TESTS, "duration_of_scan": 1.0}, tmp_path)
    risk = summarize_code_rows(APP).risk
    assert f"{risk['risk_grade']} Risk score {risk['risk_score']} {risk['risk_label']}" in text
    assert "not counted in the score" in text and "test code" in text


def test_pdf_appendix_lists_configuration_mentions(tmp_path):
    mentions = [{"location": "app/conf.py", "line": i, "algorithm": "md5", "binding": "algo", "value": "md5"}
                for i in range(1, 61)]
    text = _pdf_text({"results": APP, "duration_of_scan": 1.0, "config_evidence": mentions,
                      "config_evidence_total": 75}, tmp_path)
    assert "Configuration mentions (not counted)" in text
    assert "75 place(s)" in text and "the first 50 are listed" in text
    assert "app/conf.py:1" in text and "app/conf.py:51" not in text


def test_scan_metadata_serves_the_mentions_and_their_total():
    from backend.utilities.dashboard.scan_metadata import get_scan_metadata

    data = {"results": APP, "config_evidence": [{"location": "a.py", "line": 2}], "config_evidence_total": 9}
    meta = get_scan_metadata("cbom", types.SimpleNamespace(scan_metadata={}, scan_data=data))
    assert meta["config_evidence"] == data["config_evidence"] and meta["config_evidence_total"] == 9


@pytest.mark.parametrize(("ref", "fragment"), [
    ("crypto-algo-md5-app-py", "crypto-algo-md5-app-py"),
    ("a#b c%d/e", "a%23b%20c%25d%2Fe"),
])
def test_bom_link_fragments_are_percent_encoded(ref, fragment):
    link = VEX.bom_link("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", 2, ref)
    assert link == f"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/2#{fragment}"
