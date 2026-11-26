"""#498 round 3 follow-up (D5 AI BOM), through the routes a customer calls (GET /scan, GET /export):

* a local Ollama server is a self-hosted model server: not an "External Provider", not an unlicensed library, its row
  licence is the served model's open-weights licence (never proprietary);
* a LangChain ``ChatOpenAI()`` with no model is stated on the PDF with the library version that decides the default
  model, never a silent "0 models".

The payloads are the engine's own output (``scan_to_devsecshield``) for small repositories written to ``tmp_path``.
Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_aibom_d5_qa2_round3.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests import test_aibom_d5_qa2_profile as PROFILE  # noqa: E402
from backend.tests import test_aibom_d5_review_6037909737 as REVIEW  # noqa: E402

api = PROFILE.api
aibom_api = PROFILE.aibom_api
page = REVIEW.page
AUTH = REVIEW.AUTH


def _repo(tmp_path: Path, files: dict[str, str]) -> dict:
    root = tmp_path / "repo"
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return PROFILE._engine(root)


def test_a_local_ollama_server_is_no_external_provider(page, tmp_path):
    http, _engine, _team, get = page
    payload = _repo(tmp_path, {
        "app.py": "import ollama\n"
        'def ask(q):\n    return ollama.chat(model="mistral:7b", messages=[])\n',
        "requirements.txt": "ollama==0.4.4\n",
    })
    rows = {r["component_name"]: r for r in payload["results"]}
    assert rows["Ollama (local)"]["component_type"] == "local_model_server"
    assert rows["Ollama (local)"]["license"] == "Apache-2.0"  # the one model it serves
    body, base = get(payload)
    card = body["dashboard"]["card_data"]
    assert card["total_external_providers"] == 0
    assert card["total_unlicensed_assets"] == 0
    assert card["total_licence_unknown_assets"] == 0
    text = PROFILE._pdf_text(http.get(f"{base}/export", headers=AUTH).content)
    assert "local_model_server" in text and "LicenseRef-proprietary" not in text


def test_the_pdf_states_model_calls_that_name_no_model(page, tmp_path):
    http, _engine, _team, get = page
    payload = _repo(tmp_path, {
        "app.py": "from langchain.chat_models import ChatOpenAI\n"
        "from langchain.embeddings import OpenAIEmbeddings\n"
        "llm = ChatOpenAI()\nemb = OpenAIEmbeddings()\n",
        "requirements.txt": "langchain==0.0.184\nopenai==0.27.6\n",
    })
    body, base = get(payload)
    # the two unidentified model entries are models in use: page, PDF and checks agree
    assert body["dashboard"]["card_data"]["total_models"] == 2
    certin = body["scan_metadata"]["ai_bom_compliance"]["cert_in_aibom"]
    assert certin["out_of_scope"] == 0 and certin["pass"] == 0
    text = PROFILE._pdf_text(http.get(f"{base}/export", headers=AUTH).content)
    assert "Model calls whose model is not identified (library default or configuration)" in text
    assert "2 (langchain 0.0.184): ChatOpenAI() in app.py; OpenAIEmbeddings() in app.py" in text
    assert "Models in use 2 (0 identified, 2 not identified)" in text
    assert body["dashboard"]["card_data"]["total_unidentified_models"] == 2
    assert "unidentified model (ChatOpenAI)" in text
    assert "no AI models detected" not in text
    assert "AI model use detected; model not identified (library default applies)" in text


def test_a_mixed_licence_ollama_row_is_no_unknown_library(page, tmp_path):
    """Two models with different licences behind one server: the server row is NOASSERTION, which is a serving
    surface's licence, not a library's: neither "unlicensed" nor "licence unknown" (both count libraries)."""
    _http, _engine, _team, get = page
    payload = _repo(tmp_path, {
        "app.py": "import ollama\n"
        'def a(q):\n    return ollama.chat(model="llama3.1:8b", messages=[])\n'
        'def b(q):\n    return ollama.chat(model="gemma2:9b", messages=[])\n',
        "requirements.txt": "ollama==0.4.4\n",
    })
    rows = {r["component_name"]: r for r in payload["results"]}
    assert rows["Ollama (local)"]["license"] == "NOASSERTION"
    body, _base = get(payload)
    card = body["dashboard"]["card_data"]
    assert card["total_licence_unknown_assets"] == 0
    assert card["total_unlicensed_assets"] == 0
    assert card["total_external_providers"] == 0


def test_unidentified_models_count_the_same_on_the_list_the_scan_and_the_team_views(page, tmp_path):
    """Review 6062066749 of #498, m1: one unidentified model per client class per scan; the scan list, the scan
    dashboard and the team dashboard count models the same way, and the team view keeps two repositories'
    unidentified models apart (they can run different library defaults)."""
    from types import SimpleNamespace

    from backend.utilities.dashboard.scan_list import generate_ai_bom_dashboard_data
    from backend.utilities.db.scan_list_item import return_ai_bom_list_item

    _http, _engine, _team, get = page
    payload = _repo(tmp_path, {
        "a.py": "from langchain_openai import ChatOpenAI\nllm = ChatOpenAI()\n",
        "b.py": "from langchain_openai import ChatOpenAI\nfrom openai import OpenAI\n"
        'llm = ChatOpenAI()\nr = OpenAI().chat.completions.create(model="gpt-4o", messages=[])\n',
    })
    body, _base = get(payload)
    card = body["dashboard"]["card_data"]
    assert (card["total_models"], card["total_unidentified_models"]) == (2, 1)
    class _Scan(SimpleNamespace):  # a stored scan row: any other column reads None
        def __getattr__(self, _name):
            return None

    owner = SimpleNamespace(email="o@example.invalid", first_name="O", last_name="W", id=1)
    scan = _Scan(id=1, scan_status="success", scan_data=payload, info={}, owner_user=owner)
    item = return_ai_bom_list_item(scan)
    assert item["risk_data"]["total_models"] == 2
    other = _Scan(**{**scan.__dict__, "id": 2})
    team = generate_ai_bom_dashboard_data([scan, other])
    cards = team.get("card_data", team)
    # gpt-4o is one model across both scans; each scan's unidentified ChatOpenAI stays its own
    assert (cards["total_models"], cards["total_unidentified_models"]) == (3, 2)


def test_a_partial_scan_is_said_on_the_page_and_the_pdf_and_withholds_the_grade(page, tmp_path, monkeypatch):
    """Review 6063080163 of #498, R4-M2: a scanner that did not finish (and notebooks read as raw text) reach the
    results page (ai_bom_completeness) and the PDF ("Scan completeness"), and no clean grade is given."""
    import json as _json

    http, _engine, _team, get = page
    payload = _repo(tmp_path, {
        "app.py": "from openai import OpenAI\nc = OpenAI()\nr = c.chat.completions.create(model=\"gpt-4o\", messages=[])\n",
        "bad.ipynb": '{"cells": {"a": 1}}',
    })
    props = payload["ai_bom_json"]["metadata"]["properties"]
    props.append({"name": "aibom:scanner_errors", "value": "model-ref: KeyError (unexpected)"})
    payload["ai_bom_scores"] = {**payload["ai_bom_scores"], "completeness": "partial"}
    body, base = get(payload)
    meta = body["scan_metadata"]
    assert meta["ai_bom_completeness"] == {"status": "partial", "scanner_errors": "model-ref: KeyError (unexpected)",
                                           "notebooks_unreadable": "bad.ipynb"}
    assert (meta["ai_bom_scores"]["risk_grade"], meta["ai_bom_scores"]["risk_label"]) == (
        "—", "Grade withheld: scan incomplete")
    text = PROFILE._pdf_text(http.get(f"{base}/export", headers=AUTH).content)
    # customer wording; the scanner id and exception class in the footnote (review 6063929550 of #498, nit)
    assert "Scan completeness Partial: grade withheld because the model reference scanner did not finish" in text
    assert "model-ref: KeyError (unexpected)" in text
    assert "Notebooks read as raw text (not valid notebooks) bad.ipynb" in text
    assert "Grade withheld: scan incomplete" in text
    assert _json.dumps(meta).count("Low risk") == 0
