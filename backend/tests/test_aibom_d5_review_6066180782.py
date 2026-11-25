"""Review 6066180782 of #498 (D5 AI BOM, round 8), R7-M1 through the routes a customer calls: a call whose model is
chosen at run time from 40 candidates is ONE model on the results page and in the PDF; its candidates reach the
finding as ``model_candidates`` (the page lists them collapsed) and the PDF names the first ones, then "and N more".

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_aibom_d5_review_6066180782.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests import test_aibom_d5_review_6063929550 as R6  # noqa: E402

api = R6.api
aibom_api = R6.aibom_api
page = R6.page
PROFILE = R6.PROFILE
AUTH = R6.AUTH

_PRICES = "PRICES = {" + ", ".join(f'"m{i}": "llama3.1:{i}b"' for i in range(1, 41)) + "}\n"
_APP = "import ollama, sys\n" + _PRICES + "k = sys.argv[1]\nollama.chat(model=PRICES[k], messages=[])\n"
_NAME = "unidentified model (one of 40 candidates)"


def _payload(tmp_path: Path) -> dict:
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(_APP)
    return PROFILE._engine(root)


def test_the_page_gets_one_model_with_its_candidates(tmp_path, monkeypatch):
    """The findings the results page reads (``get_findings_for_scan_type``) carry the candidates of the one entry."""
    from backend.utilities.db import findings as findings_mod

    rows = _payload(tmp_path)["results"]
    monkeypatch.setattr(findings_mod, "get_findings_for_scan_id", lambda **_k: [
        {"_id": i, "finding_data": row, "finding_status": "open"} for i, row in enumerate(rows)])
    findings = findings_mod.get_findings_for_scan_type("ai_bom", 1)
    models = [f for f in findings if f.get("asset_kind") == "model"]
    assert [f["asset_name"] for f in models] == [_NAME]
    cands = models[0]["model_candidates"]
    assert len(cands) == 40 and cands[0] == {"name": "llama3.1:1b", "provider": "Ollama"}
    assert all(f["model_candidates"] == [] for f in findings if f.get("asset_kind") != "model")


def test_the_pdf_lists_the_first_candidates_and_a_count(page, tmp_path):
    http, _engine, _team, get = page
    _body, base = get(_payload(tmp_path))
    text = PROFILE._pdf_text(http.get(f"{base}/export", headers=AUTH).content)
    flat = " ".join(text.split())
    assert "40 candidates" in flat
    assert "llama3.1:1b (Ollama)" in flat and "llama3.1:10b (Ollama)" in flat
    assert "and 30 more" in flat
    assert "llama3.1:11b (Ollama)" not in flat  # collapsed after the first ten
