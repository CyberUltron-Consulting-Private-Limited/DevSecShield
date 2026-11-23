"""Review of #487 (D5 AI BOM PDF): the bank PDF names no healthcare requirement, one model count, one grade word.

The payload is the engine's own output for ``aibom/tests/fixtures/aibom-bank-router`` (a bank's model router), so
the PDF is checked against what a real AI BOM scan stores.

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_aibom_d5_review_pdf.py -q
"""
from __future__ import annotations

import io
import pathlib
import re
import sys

import pytest

from backend.utilities.pdf.ai_bom_pdf import _bom_scope_rows, generate_pdf
from backend.utilities.pdf.report_branding import compute_posture_risk_score

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_AIBOM_SRC = _ROOT / "aibom" / "src"
_BANK = _ROOT / "aibom" / "tests" / "fixtures" / "aibom-bank-router"


@pytest.fixture(scope="module")
def bank_payload() -> dict:
    # the engine from aibom/src, without leaking it into sys.modules for later tests
    pytest.importorskip("pydantic")
    saved = {k: sys.modules.pop(k) for k in list(sys.modules) if k == "aibom" or k.startswith("aibom.")}
    sys.path.insert(0, str(_AIBOM_SRC))
    try:
        try:
            from aibom.integrations.devsecshield import scan_to_devsecshield
        except ImportError as exc:  # the backend environment without the engine's dependencies
            pytest.skip(f"aibom engine not importable here: {exc}")
        return scan_to_devsecshield(_BANK, level=4)
    finally:
        sys.path.remove(str(_AIBOM_SRC))
        for k in [k for k in sys.modules if k == "aibom" or k.startswith("aibom.")]:
            del sys.modules[k]
        sys.modules.update(saved)


def _pdf_text(tmp_path: pathlib.Path, payload: dict) -> str:
    pypdf = pytest.importorskip("pypdf")
    out = tmp_path / "aibom.pdf"
    generate_pdf(payload, str(out))
    reader = pypdf.PdfReader(io.BytesIO(out.read_bytes()))
    return " ".join(" ".join(page.extract_text() or "" for page in reader.pages).split())


def test_bank_pdf_names_no_healthcare_requirement(tmp_path, bank_payload):
    text = _pdf_text(tmp_path, bank_payload)
    assert "AI BOM regulatory checks" in text
    assert not re.findall(r"\b(?:BAA|MDR|PHI|HIPAA|FDA)\b", text)
    # the frameworks are listed once: no raw-key rollup repeating them
    assert "eu_ai_act_annexIV" not in text and "RBI FREE-AI Compliance (Advisory)" not in text


def test_one_model_count(bank_payload):
    rows = dict(_bom_scope_rows(bank_payload))
    in_use = [r for r in bank_payload["results"] if r["component_name"] in ("gpt-4o", "Qwen2.5-1.5B-Instruct")]
    assert rows["Models in use"] == str(len(in_use)) == "2"  # not the catalog names kept in the BOM


def test_weight_files_are_counted_apart():
    bom = {"components": [
        {"type": "machine-learning-model", "name": "gpt-4o",
         "properties": [{"name": "model:reference_type", "value": "usage"}]},
        {"type": "machine-learning-model", "name": "w.bin",
         "properties": [{"name": "model:weight_file", "value": "true"}]},
        {"type": "machine-learning-model", "name": "gpt-4-turbo",
         "properties": [{"name": "model:reference_type", "value": "catalog"}]},
    ], "services": []}
    rows = dict(_bom_scope_rows({"ai_bom_json": bom}))
    assert (rows["Models in use"], rows["Model weight files"]) == ("1", "1")


def test_pdf_grade_word_is_the_engine_band(tmp_path, bank_payload):
    scores = bank_payload["ai_bom_scores"]
    counts = scores["severity_counts"]
    score, grade, label = compute_posture_risk_score(counts["critical"], counts["high"], counts["medium"],
                                                     counts["low"])
    assert (score, grade, label) == (int(scores["risk_normalized"]), scores["risk_grade"], scores["risk_label"])
    assert label.split()[0].lower() == scores["risk_band"]
    assert label in _pdf_text(tmp_path, bank_payload)


@pytest.mark.parametrize(
    ("row", "provider"),
    [({"component_name": "Google Gemini API", "component_type": "external_provider", "source": "local"}, "google"),
     ({"component_name": "Groq API", "component_type": "external_provider"}, "groq"),
     ({"component_name": "OpenRouter API", "component_type": "external_provider"}, "openrouter"),
     ({"component_name": "xAI API", "component_type": "external_provider"}, "xai"),
     ({"component_name": "gemini-1.5-flash", "component_type": "local_model_file", "source": "google"}, "google")],
)
def test_saas_provider_column(row, provider):
    """The provider column says who serves the API (review of #487 m7). A stored ``local`` is the old adapter's
    fallback, so it is re-derived when the row names a known SaaS API."""
    from backend.utilities.dashboard.aibom_provider import resolve_aibom_provider

    assert resolve_aibom_provider(row) == provider
