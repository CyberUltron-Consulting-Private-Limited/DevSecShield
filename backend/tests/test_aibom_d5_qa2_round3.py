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
        'def ask(q):\n    return ollama.chat(model="mistral-7b-instruct", messages=[])\n',
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
    assert body["dashboard"]["card_data"]["total_models"] == 0
    text = PROFILE._pdf_text(http.get(f"{base}/export", headers=AUTH).content)
    assert "Model calls naming no model (library default applies, model not identified)" in text
    assert "2 (langchain 0.0.184): ChatOpenAI() in app.py; OpenAIEmbeddings() in app.py" in text


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
