# ruff: noqa: E501 - the reviewer's probe sources are kept verbatim (long lines)
"""Review 6066180782 of #498 (D5 AI BOM, round 8): the reviewer's probes as tests.

R7-M1 (coordinator's design) a call whose model is chosen by a dynamic key is ONE
      model in use, "unidentified model (one of N candidates)"; its candidates are
      evidence (a property, the row's ``model_candidates``), never components of
      their own; counts and compliance see one model, needs-information;
R7-M2 the one entry is served by the Ollama server only when every candidate is
      an Ollama tag; a mix of hosted and Ollama tags leaves the server unknown, so
      no hosted model is ever put on the local server; each candidate is listed
      with its own provider;
R7-M3 a LiteLLM route links to the provider its own prefix names, never to the
      nearest earlier route;
minors: vendored / third-party paths and ``.py`` under docs/ are no Ollama
evidence; evidence is scoped to the package (nearest manifest root); a lookup into
a loaded JSON / YAML config counts once; a wrapper in another file counts once.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from aibom.compliance import run_all
from aibom.emit.cyclonedx import emit_cyclonedx
from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.model.result import REL_SERVED_BY
from aibom.scan.pipeline import scan_repo


def _repo(tmp_path, files: dict[str, str]) -> pathlib.Path:
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return tmp_path


def _scan(tmp_path, files):
    return scan_repo(_repo(tmp_path, files), level=4)


def _models(result) -> dict:
    return {c.name: c for c in result.components if c.kind == "model"}


def _in_use(result) -> set[str]:
    return {n for n, c in _models(result).items()
            if (c.properties or {}).get("model:reference_type") not in ("catalog", "test")}


def _served(result, name: str) -> list[str]:
    model = _models(result)[name]
    by_ref = {c.bom_ref: c for c in result.components}
    return [by_ref[e.dst].name for e in result.edges if e.src == model.bom_ref and e.rel == REL_SERVED_BY]


def _choice(result) -> str:
    """The one run-time choice entry (its name is a stable hash since round 9)."""
    (entry,) = [c for c in result.components if c.kind == "model"
                and (c.properties or {}).get("model:selection") == "candidates"]
    return entry.name


def _rows(tmp_path, files) -> dict:
    return {r["component_name"]: r for r in scan_to_devsecshield(_repo(tmp_path, files), level=4)["results"]}


_PRICES = "PRICES = {" + ", ".join(f'"m{i}": "llama3.1:{i}b"' for i in range(1, 41)) + "}\n"
_FORTY = {"app.py": "import ollama, sys\n" + _PRICES + "k = sys.argv[1]\nollama.chat(model=PRICES[k], messages=[])\n"}
_MIXED = {"app.py": (
    "import ollama, sys\n"
    'OPTIONS = {"fast": "phi3:mini", "smart": "gpt-4o", "local": "llama3.1:8b", "claude": "claude-3-5-sonnet-20241022"}\n'
    "choice = sys.argv[1]\n"
    "ollama.chat(model=OPTIONS[choice], messages=[])\n"
)}


# --------------------------------------------------------------------------- R7-M1


def test_forty_candidates_are_one_model_in_use(tmp_path) -> None:
    result = _scan(tmp_path, _FORTY)
    name = _choice(result)
    assert _in_use(result) == {name}
    entry = _models(result)[name]
    props = entry.properties or {}
    assert props["model:identified"] == "false"
    assert props["model:selection"] == "candidates"
    assert props["model:candidate_count"] == "40"
    assert [c["provider"] for c in json.loads(props["model:candidates"])] == ["Ollama"] * 40
    assert "PRICES[k]" in props["discovery:snippet"]
    # no candidate is a component of its own in use
    assert not any(n.startswith("llama3.1:") for n in _in_use(result))
    assert _served(result, name) == ["Ollama (local)"]


def test_forty_candidates_count_once_in_rows_and_scores(tmp_path) -> None:
    out = scan_to_devsecshield(_repo(tmp_path, _FORTY), level=4)
    models = [r for r in out["results"] if r["component_kind"] == "model"]
    assert len(models) == 1
    (row,) = models
    assert row["model_identified"] is False
    assert len(row["model_candidates"]) == 40
    assert row["model_candidates"][0] == {"name": "llama3.1:1b", "provider": "Ollama"}
    others = [r for r in out["results"] if r["component_kind"] != "model"]
    assert all(r["model_candidates"] is None for r in others)


def test_forty_candidates_are_assessed_once_as_needs_information(tmp_path) -> None:
    result = _scan(tmp_path, _FORTY)
    report = run_all(result)
    eu = report["eu_ai_act_annexIV"]
    assert eu["fail"] == 0
    texts = " ".join(r["evidence"] for r in eu["requirements"])
    assert "40 model(s)" not in texts
    assert "40 candidates" in texts
    needs = [r for r in eu["requirements"] if r["verdict"] == "not_bom_evidenceable"]
    assert needs and any("one of 40 candidates" in r["evidence"] or "40 candidates" in r["evidence"] for r in needs)


def test_the_cyclonedx_entry_carries_the_candidates_as_evidence(tmp_path) -> None:
    bom = emit_cyclonedx(_scan(tmp_path, _FORTY))
    (entry,) = [c for c in bom["components"] if c.get("name", "").startswith("unidentified model (run-time choice")]
    props = {p["name"]: p["value"] for p in entry.get("properties", [])}
    assert props["model:candidate_count"] == "40"
    method = entry["evidence"]["identity"][0]["methods"][0]
    assert "40 candidates" in method["value"]
    assert not [c for c in bom["components"] if c.get("name", "").startswith("llama3.1:") and any(
        p["name"] == "model:reference_type" and p["value"] == "usage" for p in c.get("properties", []))]


def test_two_calls_on_the_same_dict_are_one_entry_with_both_call_sites(tmp_path) -> None:
    files = {"app.py": "import ollama, sys\n" + _PRICES + "k = sys.argv[1]\nollama.chat(model=PRICES[k], messages=[])\nollama.generate(model=PRICES[k], prompt='x')\nollama.chat(model=PRICES[k], messages=[])\n"}
    result = _scan(tmp_path, files)
    assert _in_use(result) == {_choice(result)}


# --------------------------------------------------------------------------- R7-M2


def test_a_mixed_candidate_dict_follows_the_ollama_client_and_lists_providers(tmp_path) -> None:
    # round 9 (review 6066860842, R8-M2): the entry follows the client actually
    # called; the hosted candidates are never models of their own
    result = _scan(tmp_path, _MIXED)
    name = _choice(result)
    assert _in_use(result) == {name}
    assert _served(result, name) == ["Ollama (local)"]
    for hosted in ("gpt-4o", "claude-3-5-sonnet-20241022"):
        model = _models(result).get(hosted)
        assert model is None or (model.properties or {}).get("model:reference_type") == "catalog"
        if model is not None:
            assert _served(result, hosted) == []
    cands = {(c["name"], c["provider"]) for c in json.loads((_models(result)[name].properties or {})["model:candidates"])}
    assert {("gpt-4o", "OpenAI"), ("claude-3-5-sonnet-20241022", "Anthropic"), ("phi3:mini", "Ollama"),
            ("llama3.1:8b", "Ollama")} == cands
    rows = _rows(tmp_path / "rows", _MIXED)
    assert "gpt-4o" not in rows or rows["gpt-4o"]["component_type"] != "self_hosted_model"


def test_hosted_candidates_of_one_vendor_are_served_by_its_api(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import sys\nfrom openai import OpenAI\nc = OpenAI()\n"
        'TIERS = {"a": "gpt-4o", "b": "gpt-4o-mini"}\n'
        "c.chat.completions.create(model=TIERS[sys.argv[1]], messages=[])\n"
    )})
    name = _choice(result)
    assert _in_use(result) == {name}
    assert _served(result, name) == ["OpenAI API"]


# --------------------------------------------------------------------------- R7-M3


def test_litellm_routes_in_one_file_link_to_their_own_providers(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import litellm\n"
        'litellm.completion(model="groq/llama3-8b-8192", messages=[])\n'
        'litellm.completion(model="openai/gpt-4o", messages=[])\n'
        'litellm.completion(model="together_ai/meta-llama/Llama-3-8b-chat-hf", messages=[])\n'
        'litellm.completion(model="anthropic/claude-3-5-sonnet-20241022", messages=[])\n'
    )})
    assert _served(result, "gpt-4o") == ["OpenAI API"]
    assert _served(result, "claude-3-5-sonnet-20241022") == ["Anthropic API"]
    assert _served(result, "llama3-8b-8192") == ["Groq API"]
    assert _served(result, "Llama-3-8b-chat-hf") == ["Together AI API"]


# --------------------------------------------------------------------------- m1 vendored


_CONST = {"app.py": 'DEFAULT_MODEL = "llama3.1:8b"\n'}


@pytest.mark.parametrize("files", [
    {"third_party/ollama_client/client.py": "import ollama\nollama.chat(model='x')\n"},
    {"external/lib/ollama_api.py": "import ollama\n"},
    {"extern/ollama/client.py": "import ollama\n"},
    {"libs/ollama-python/pyproject.toml": '[project]\nname = "ollama"\n', "libs/ollama-python/ollama/_client.py": "import ollama\n"},
    {"docs/setup.py": "import ollama\n"},
], ids=["third_party", "external", "extern", "libs-own-manifest", "docs-py"])
def test_vendored_code_and_docs_python_are_no_ollama_evidence(tmp_path, files) -> None:
    result = _scan(tmp_path, {**_CONST, **files})
    assert "llama3.1:8b" not in _in_use(result)


# --------------------------------------------------------------------------- m2 monorepo


def test_ollama_evidence_is_scoped_to_its_package(tmp_path) -> None:
    result = _scan(tmp_path, {
        "packages/chatbot/pyproject.toml": '[project]\nname = "chatbot"\n',
        "packages/chatbot/app.py": 'import ollama\nollama.chat(model="phi3:mini", messages=[])\n',
        "packages/billing/pyproject.toml": '[project]\nname = "billing"\n',
        "packages/billing/settings.py": 'DEFAULT_MODEL = "llama3.1:8b"\n',
    })
    assert "phi3:mini" in _in_use(result)
    assert "llama3.1:8b" not in _in_use(result)


def test_the_same_package_still_counts(tmp_path) -> None:
    result = _scan(tmp_path, {
        "packages/chatbot/pyproject.toml": '[project]\nname = "chatbot"\n',
        "packages/chatbot/app.py": "import ollama\n",
        "packages/chatbot/settings.py": 'DEFAULT_MODEL = "llama3.1:8b"\n',
    })
    assert "llama3.1:8b" in _in_use(result)


# --------------------------------------------------------------------------- m3 config files


@pytest.mark.parametrize(("files", "model"), [
    ({"config.json": '{"llm": {"model": "gpt-4o"}}\n',
      "app.py": 'import json\nfrom langchain_openai import ChatOpenAI\nCFG = json.load(open("config.json"))\nllm = ChatOpenAI(model=CFG["llm"]["model"])\n'}, "gpt-4o"),
    ({"config.yaml": "llm:\n  model: gpt-4o\n",
      "app.py": 'import yaml\nfrom langchain_openai import ChatOpenAI\nwith open("config.yaml") as f:\n    CFG = yaml.safe_load(f)\nllm = ChatOpenAI(model=CFG["llm"]["model"])\n'}, "gpt-4o"),
    ({"config.yaml": "model: llama3.1:8b\n",
      "app.py": 'import ollama, yaml\nCFG = yaml.safe_load(open("config.yaml"))\nollama.chat(model=CFG["model"], messages=[])\n'}, "llama3.1:8b"),
], ids=["json", "yaml-with", "yaml-ollama"])
def test_a_lookup_into_a_loaded_config_counts_once(tmp_path, files, model) -> None:
    result = _scan(tmp_path, files)
    assert _in_use(result) == {model}


# --------------------------------------------------------------------------- m4 wrapper


def test_a_wrapper_in_another_file_counts_once(tmp_path) -> None:
    result = _scan(tmp_path, {
        "svc.py": "import ollama\n\ndef ask(m, q):\n    return ollama.chat(model=m, messages=[q])\n",
        "app.py": 'from svc import ask\nDEFAULT_MODEL = "llama3.1:8b"\nask(DEFAULT_MODEL, "hi")\n',
    })
    assert _in_use(result) == {"llama3.1:8b"}
