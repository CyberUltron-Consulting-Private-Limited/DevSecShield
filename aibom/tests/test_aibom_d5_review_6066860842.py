# ruff: noqa: E501 - the reviewer's probe sources are kept verbatim (long lines)
"""Review 6066860842 of #498 (D5 AI BOM, round 9): the reviewer's probes as tests.

R8-M1 an unprefixed LiteLLM model follows LiteLLM's own default routing (the
      provider inferred from the model name: gpt-*/o* OpenAI, claude-* Anthropic,
      gemini-* Google …), never an earlier route's provider; not inferable, unknown;
R8-M2 a mixed-candidate call follows the client actually called: an Ollama call is
      served by the Ollama server and typed self-hosted (the hosted-looking names
      noted in the evidence); a generic client (LiteLLM, an OpenAI client with an
      unknown base URL) leaves the server unknown, typed external, and the vendor
      checks read it as a possible external processor, never "na";
minors: vendored code creates no Ollama servers or models, and the app's call of a
vendored wrapper with a literal counts once; a root compose's Ollama / OLLAMA_HOST
reach only the packages it builds or runs; a top-level dir under services/, apps/
or packages/ is a package; the candidate entry's identity is a hash of the sorted
candidate set and the call site (no count), a set of one is that model; config
paths built from ``__file__`` resolve; candidates are stored as JSON.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from aibom.compliance import run_all
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


def _choices(result) -> list:
    return [c for c in result.components if c.kind == "model"
            and (c.properties or {}).get("model:selection") == "candidates"]


def _served(result, name: str) -> list[str]:
    model = _models(result)[name]
    by_ref = {c.bom_ref: c for c in result.components}
    return [by_ref[e.dst].name for e in result.edges if e.src == model.bom_ref and e.rel == REL_SERVED_BY]


def _rows(root) -> dict:
    return {r["component_name"]: r for r in scan_to_devsecshield(root, level=4)["results"]}


# --------------------------------------------------------------------------- R8-M1


@pytest.mark.parametrize(("model", "service"), [
    ("gpt-4o", "OpenAI API"),
    ("o3-mini", "OpenAI API"),
    ("claude-3-5-sonnet-20241022", "Anthropic API"),
    ("gemini-1.5-flash", "Google Gemini API"),
])
def test_an_unprefixed_litellm_model_follows_litellms_default_routing(tmp_path, model, service) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import litellm\n"
        'litellm.completion(model="groq/llama3-8b-8192", messages=[])\n'
        f'litellm.completion(model="{model}", messages=[])\n'
    )})
    assert _served(result, model) == [service]
    assert _served(result, "llama3-8b-8192") == ["Groq API"]


def test_an_unprefixed_model_litellm_cannot_route_has_no_provider(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import litellm\n"
        'litellm.completion(model="groq/llama3-8b-8192", messages=[])\n'
        'litellm.completion(model="Llama-3-70b-chat-hf", messages=[])\n'
    )})
    assert _served(result, "Llama-3-70b-chat-hf") == []


# --------------------------------------------------------------------------- R8-M2


_MIXED = 'OPTIONS = {"fast": "phi3:mini", "smart": "gpt-4o", "local": "llama3.1:8b", "claude": "claude-3-5-sonnet-20241022"}\n'


def test_a_mixed_ollama_call_is_served_by_ollama_and_self_hosted_everywhere(tmp_path) -> None:
    root = _repo(tmp_path, {"app.py": "import ollama, sys\n" + _MIXED + "ollama.chat(model=OPTIONS[sys.argv[1]], messages=[])\n"})
    result = scan_repo(root, level=4)
    (entry,) = _choices(result)
    assert _served(result, entry.name) == ["Ollama (local)"]
    note = (entry.properties or {}).get("model:candidate_note", "")
    assert "gpt-4o" in note and "claude-3-5-sonnet-20241022" in note
    rows = _rows(root)
    assert rows[entry.name]["component_type"] == "self_hosted_model"
    report = run_all(result)
    # no external processor anywhere: the type and the vendor checks agree
    assert not [r for r in rows.values() if r["component_type"] == "external_provider"]
    fr = {r["id"]: r for r in report["rbi_free_ai"]["requirements"]}
    assert fr["FREEAI-19-1"]["verdict"] == "na"


@pytest.mark.parametrize("files", [
    {"app.py": "import litellm, sys\n" + _MIXED + "litellm.completion(model=OPTIONS[sys.argv[1]], messages=[])\n"},
    {"app.py": "import os, sys\nfrom openai import OpenAI\nc = OpenAI(base_url=os.environ['LLM_URL'])\n" + _MIXED + "c.chat.completions.create(model=OPTIONS[sys.argv[1]], messages=[])\n"},
], ids=["litellm", "openai-unknown-base"])
def test_a_mixed_generic_call_is_a_possible_external_processor_everywhere(tmp_path, files) -> None:
    root = _repo(tmp_path, files)
    result = scan_repo(root, level=4)
    (entry,) = _choices(result)
    served = _served(result, entry.name)
    assert served and all("Ollama" not in s for s in served)
    rows = _rows(root)
    assert rows[entry.name]["component_type"] == "external_provider"
    report = run_all(result)
    fr = {r["id"]: r for r in report["rbi_free_ai"]["requirements"]}
    assert fr["FREEAI-19-1"]["verdict"] == "not_bom_evidenceable", fr["FREEAI-19-1"]
    nist = {r["id"]: r for r in report["nist_rmf"]["requirements"]}
    gv2 = [r for k, r in nist.items() if k.startswith("GV-2")]
    assert gv2 and all(r["verdict"] != "na" for r in gv2)


# --------------------------------------------------------------------------- m1 vendored


def test_vendored_code_creates_no_ollama_server_or_model(tmp_path) -> None:
    result = _scan(tmp_path, {
        "app.py": "X = 1\n",
        "third_party/oc/client.py": "import ollama\n\ndef chat(m):\n    return ollama.chat(model='x', messages=[])\n",
    })
    assert not [c for c in result.components if "Ollama" in c.name]
    assert not _models(result)


def test_the_apps_call_of_a_vendored_wrapper_counts_once(tmp_path) -> None:
    result = _scan(tmp_path, {
        "app.py": 'from third_party.oc.client import chat\nchat("llama3.1:8b")\n',
        "third_party/oc/client.py": "import ollama\n\ndef chat(m):\n    return ollama.chat(model=m, messages=[])\n",
    })
    assert _in_use(result) == {"llama3.1:8b"}


# --------------------------------------------------------------------------- m2 monorepo


_ROOT_COMPOSE = (
    "services:\n  chat:\n    build: ./packages/chat\n    environment:\n      OLLAMA_HOST: http://ollama:11434\n"
    "  ollama:\n    image: ollama/ollama:latest\n"
)


def test_a_root_compose_reaches_only_the_packages_it_builds(tmp_path) -> None:
    result = _scan(tmp_path, {
        "docker-compose.yml": _ROOT_COMPOSE,
        "packages/chat/pyproject.toml": '[project]\nname = "chat"\n',
        "packages/chat/settings.py": 'CHAT_MODEL = "phi3:mini"\n',
        "packages/billing/pyproject.toml": '[project]\nname = "billing"\n',
        "packages/billing/settings.py": 'DEFAULT_MODEL = "llama3.1:8b"\n',
    })
    assert "phi3:mini" in _in_use(result)
    assert "llama3.1:8b" not in _in_use(result)


def test_a_top_level_dir_under_services_is_a_package_without_a_manifest(tmp_path) -> None:
    result = _scan(tmp_path, {
        "services/chatbot/app.py": "import ollama\n",
        "services/billing/settings.py": 'DEFAULT_MODEL = "llama3.1:8b"\n',
    })
    assert "llama3.1:8b" not in _in_use(result)


# --------------------------------------------------------------------------- m3 identity


def _choice_files(extra: str = "") -> dict[str, str]:
    return {"app.py": "import ollama, sys\nOPTIONS = {" + '"a": "phi3:mini", "b": "llama3.1:8b"' + extra + "}\nollama.chat(model=OPTIONS[sys.argv[1]], messages=[])\n"}


def test_the_candidate_identity_has_no_count_and_is_stable(tmp_path) -> None:
    (one,) = _choices(_scan(tmp_path / "a", _choice_files()))
    (two,) = _choices(_scan(tmp_path / "b", _choice_files()))
    assert (one.name, one.bom_ref) == (two.name, two.bom_ref)
    assert "candidates)" not in one.name and "of 2" not in one.name
    assert (one.properties or {})["model:candidate_count"] == "2"
    # the identity is the hash of the sorted candidate set and the call site
    reordered = {"app.py": "import ollama, sys\nOPTIONS = {" + '"b": "llama3.1:8b", "a": "phi3:mini"' + "}\nollama.chat(model=OPTIONS[sys.argv[1]], messages=[])\n"}
    (three,) = _choices(_scan(tmp_path / "c", reordered))
    assert three.bom_ref == one.bom_ref


def test_a_set_of_one_is_that_model(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": 'import ollama, sys\nOPTIONS = {"only": "phi3:mini"}\nollama.chat(model=OPTIONS[sys.argv[1]], messages=[])\n'})
    assert _in_use(result) == {"phi3:mini"}
    assert not _choices(result)


# --------------------------------------------------------------------------- m4 config paths


@pytest.mark.parametrize("load", [
    'P = os.path.join(os.path.dirname(__file__), "config.json")\nCFG = json.load(open(P))\n',
    'CFG = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")))\n',
    'CFG = json.loads((Path(__file__).parent / "config.json").read_text())\n',
    'P = Path(__file__).resolve().parent / "config.json"\nwith open(P) as f:\n    CFG = json.load(f)\n',
], ids=["join-var", "join-inline", "path-div", "path-with"])
def test_a_config_path_built_from_file_resolves(tmp_path, load) -> None:
    result = _scan(tmp_path, {
        "config.json": '{"llm": {"model": "gpt-4o"}}\n',
        "app.py": "import json, os\nfrom pathlib import Path\nfrom langchain_openai import ChatOpenAI\n" + load + 'llm = ChatOpenAI(model=CFG["llm"]["model"])\n',
    })
    assert _in_use(result) == {"gpt-4o"}


# --------------------------------------------------------------------------- m5 structured


def test_candidates_are_stored_as_json_and_survive_odd_names(tmp_path) -> None:
    root = _repo(tmp_path, {"app.py": (
        "import ollama, sys\n"
        'OPTIONS = {"a": "phi3:mini", "b": "llama3.1:8b", "c": "gpt-4o"}\n'
        "ollama.chat(model=OPTIONS[sys.argv[1]], messages=[])\n"
    )})
    (entry,) = _choices(scan_repo(root, level=4))
    data = json.loads((entry.properties or {})["model:candidates"])
    assert data == [{"name": "phi3:mini", "provider": "Ollama"}, {"name": "llama3.1:8b", "provider": "Ollama"},
                    {"name": "gpt-4o", "provider": "OpenAI"}]
    assert _rows(root)[entry.name]["model_candidates"] == data


def test_the_row_reader_takes_json_with_separators_in_names() -> None:
    from aibom.integrations.devsecshield import _candidates
    from aibom.model.component import ModelComponent

    odd = [{"name": "a; b (c)", "provider": "x (y)"}, {"name": "d", "provider": "Ollama"}]
    comp = ModelComponent(bom_ref="m", name="m", properties={"model:candidates": json.dumps(odd)})
    assert _candidates(comp) == odd
