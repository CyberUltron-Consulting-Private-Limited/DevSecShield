# ruff: noqa: E501 - the reviewer's probe sources are kept verbatim (long lines)
"""Review 6065595627 of #498 (D5 AI BOM, round 7): the reviewer's probes as tests.

R6-M1 Ollama evidence is real code or deployment use only: an SDK / client import
      in application source, a REST call to an Ollama endpoint, a LangChain /
      LiteLLM Ollama class or route, an ``ollama/ollama`` container, OLLAMA_HOST in
      the application's real environment. Docs, tests, a plain "ollama" string, a
      declared-but-never-imported dependency and ``.env.example`` never count, and
      an example file never creates a service row;
R6-M2 a model chosen by subscript / lookup resolves against the project's literal
      dicts and constants; a dynamic key lists the dict's values as low-confidence
      candidates of that call; a real Ollama / OpenAI call never reads "no AI model";
minors: an argparse / getenv default plus the config-driven call is one model;
LiteLLM ``ollama/`` routes are served by an Ollama server (``api_base`` is that
server, not a gateway), the proxy ``config.yaml`` ``model_list`` is read, and
``groq/`` / ``together_ai/`` routes are hosted-provider models; the compose
container and the server it is named by are one row; a bare alias stays next to its
tagged forms; partial verdicts are qualified whatever the verdict.
"""

from __future__ import annotations

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


def _ollama_services(result) -> dict:
    return {c.name: c for c in result.components
            if (c.properties or {}).get("service:platform") == "ollama"}


def _services(result) -> dict:
    return {c.name: c for c in result.components if c.kind in ("cloud_service", "endpoint", "service", "container")}


def _served(result, name: str) -> list[str]:
    model = _models(result)[name]
    by_ref = {c.bom_ref: c for c in result.components}
    return [by_ref[e.dst].name for e in result.edges if e.src == model.bom_ref and e.rel == REL_SERVED_BY]


def _rows(tmp_path, files) -> dict:
    return {r["component_name"]: r for r in scan_to_devsecshield(_repo(tmp_path, files), level=4)["results"]}


_CONST = 'DEFAULT_MODEL = "{tag}"\n'


# --------------------------------------------------------------------------- R6-M1


@pytest.mark.parametrize(("name", "files", "tag"), [
    ("readme", {"README.md": "Also works with Ollama: set `OLLAMA_HOST=http://localhost:11434`.\n"}, "llama3.1:70b"),
    ("docs", {"docs/setup.md": "```python\nimport ollama\nollama.chat(model='x')\n```\n"}, "mistral:7b"),
    ("test-only", {"tests/test_o.py": "import ollama\n\ndef test_x():\n    ollama.chat(model='llama3.1:8b')\n"}, "llama3.1:8b"),
    ("provider-string", {"providers.py": 'PROVIDERS = ["openai", "ollama"]\n'}, "llama3.1:8b"),
    ("env-example", {".env.example": "OLLAMA_HOST=http://localhost:11434\n"}, "llama3.1:8b"),
    ("env-sample", {".env.sample": "OLLAMA_HOST=http://localhost:11434\n"}, "llama3.1:8b"),
    ("package-json", {"package.json": '{"name": "x", "dependencies": {"ollama": "^0.5.0"}}\n'}, "llama3.1:8b"),
    ("requirements", {"requirements.txt": "ollama==0.4\n"}, "llama3.1:8b"),
    ("pyproject", {"pyproject.toml": '[project]\nname = "x"\ndependencies = ["ollama>=0.4"]\n'}, "llama3.1:8b"),
    ("docstring", {"lib.py": '"""Usage:\n\nimport ollama\n"""\nX = 1\n'}, "llama3.1:8b"),
])
def test_only_real_use_is_ollama_evidence(tmp_path, name, files, tag) -> None:
    result = _scan(tmp_path, {"app.py": _CONST.format(tag=tag), **files})
    assert tag not in _in_use(result), name


@pytest.mark.parametrize(("name", "files"), [
    ("sdk-import", {"client.py": "import ollama\n"}),
    ("sdk-js", {"client.mjs": "import ollama from 'ollama'\nawait ollama.chat({model: 'x'})\n"}),
    ("rest", {"client.py": 'import requests\nrequests.post("http://localhost:11434/api/chat", json={})\n'}),
    ("rest-env", {"client.py": 'import os, requests\nrequests.post(os.environ["OLLAMA_HOST"] + "/api/generate", json={})\n'}),
    ("langchain", {"client.py": "from langchain_ollama import ChatOllama\nllm = ChatOllama(model=MODEL)\n"}),
    ("litellm", {"client.py": 'import litellm\nlitellm.completion(model="ollama/phi3:mini", messages=[])\n'}),
    ("compose", {"docker-compose.yml": "services:\n  ollama:\n    image: ollama/ollama:latest\n"}),
    ("k8s", {"deploy/ollama.yaml": "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: ollama\n          image: ollama/ollama:0.5.7\n"}),
    ("env", {".env": "OLLAMA_HOST=http://10.0.0.5:11434\n"}),
])
def test_real_ollama_use_still_counts(tmp_path, name, files) -> None:
    result = _scan(tmp_path, {"app.py": _CONST.format(tag="llama3.1:8b"), **files})
    assert "llama3.1:8b" in _in_use(result), name


def test_an_example_env_file_never_creates_a_service_row(tmp_path) -> None:
    result = _scan(tmp_path, {
        "app.py": 'import ollama\nollama.chat(model="llama3.1:8b", messages=[])\n',
        ".env.example": "OLLAMA_HOST=http://localhost:11434\n",
    })
    for comp in _services(result).values():
        assert (comp.properties or {}).get("discovery:source") != ".env.example", comp.name
    # the example value is a default at most: the server is "endpoint unknown"
    assert _served(result, "llama3.1:8b") == ["Ollama server (endpoint unknown)"]


def test_an_example_env_file_alone_creates_no_service(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": "X = 1\n", ".env.example": "OLLAMA_HOST=http://localhost:11434\nOPENAI_BASE=https://api.openai.com/v1\n"})
    assert not _services(result)


# --------------------------------------------------------------------------- R6-M2


def _cert_in_all_out_of_scope(result) -> bool:
    fw = run_all(result)["cert_in_aibom"]
    return all(r["verdict"] == "out_of_scope" for r in fw["requirements"])


def test_a_subscript_with_a_literal_key_resolves_to_the_dict_value(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import ollama\n"
        'OPTIONS = {"fast": "phi3:mini", "smart": "llama3.1:70b"}\n'
        'ollama.chat(model=OPTIONS["fast"], messages=[])\n'
    )})
    assert "phi3:mini" in _in_use(result)
    assert "llama3.1:70b" not in _in_use(result)
    assert not any(n.startswith("unidentified") for n in _models(result))
    assert _served(result, "phi3:mini") == ["Ollama (local)"]
    assert not _cert_in_all_out_of_scope(result)


def test_an_openai_subscript_resolves_across_one_import(tmp_path) -> None:
    result = _scan(tmp_path, {
        "cfg.py": 'CFG = {"m": "gpt-4o", "e": "text-embedding-3-small"}\n',
        "app.py": (
            "from cfg import CFG\nfrom langchain_openai import ChatOpenAI\n"
            'llm = ChatOpenAI(model=CFG["m"])\n'
        ),
    })
    assert "gpt-4o" in _in_use(result)
    assert not any(n.startswith("unidentified") for n in _models(result))
    assert _served(result, "gpt-4o") == ["OpenAI API"]
    assert not _cert_in_all_out_of_scope(result)


def test_a_nested_subscript_resolves(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import ollama\n"
        'SETTINGS = {"llm": {"model": "qwen2.5:7b", "temperature": 0.2}}\n'
        'ollama.chat(model=SETTINGS["llm"]["model"], messages=[])\n'
    )})
    assert "qwen2.5:7b" in _in_use(result)
    assert not any(n.startswith("unidentified") for n in _models(result))


def test_a_dynamic_key_is_one_model_with_its_candidates_as_evidence(tmp_path) -> None:
    # round 8 (review 6066180782, R7-M1, the coordinator's design) replaces the
    # round-7 candidate rows: one entry per call, the candidates are evidence
    result = _scan(tmp_path, {"app.py": (
        "import ollama, sys\n"
        'OPTIONS = {"fast": "phi3:mini", "smart": "llama3.1:70b"}\n'
        "choice = sys.argv[1]\n"
        "ollama.chat(model=OPTIONS[choice], messages=[])\n"
    )})
    assert _in_use(result) == {"unidentified model (one of 2 candidates)"}
    props = _models(result)["unidentified model (one of 2 candidates)"].properties or {}
    assert props["model:candidates"] == "phi3:mini (Ollama); llama3.1:70b (Ollama)"
    assert props["discovery:confidence"] == "low"
    assert props["discovery:source"] == "app.py"
    assert "ollama.chat" in props["discovery:snippet"]


def test_an_unresolvable_subscript_is_an_unidentified_model_not_no_model(tmp_path) -> None:
    result = _scan(tmp_path, {
        "app.py": (
            "import json\nfrom langchain_openai import ChatOpenAI\n"
            'CFG = json.load(open("cfg.json"))\n'
            'llm = ChatOpenAI(model=CFG["m"])\n'
        ),
    })
    assert "unidentified model (ChatOpenAI)" in _in_use(result)
    assert not _cert_in_all_out_of_scope(result)


def test_an_ollama_call_with_an_unresolvable_subscript_is_unidentified(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import ollama, yaml\n"
        'cfg = yaml.safe_load(open("c.yaml"))\n'
        'ollama.chat(model=cfg["llm"]["model"], messages=[])\n'
    )})
    assert "unidentified model (Ollama)" in _in_use(result)
    assert not _cert_in_all_out_of_scope(result)


def test_a_settings_attribute_resolves_against_its_class_default(tmp_path) -> None:
    result = _scan(tmp_path, {
        "settings.py": (
            "from pydantic_settings import BaseSettings\n\n"
            "class Settings(BaseSettings):\n    llm_model: str = \"gpt-4o-mini\"\n\nsettings = Settings()\n"
        ),
        "app.py": (
            "from settings import settings\nfrom openai import OpenAI\nc = OpenAI()\n"
            "c.chat.completions.create(model=settings.llm_model, messages=[])\n"
        ),
    })
    assert "gpt-4o-mini" in _in_use(result)
    assert not any(n.startswith("unidentified") for n in _models(result))


def test_a_module_attribute_resolves_against_its_constant(tmp_path) -> None:
    result = _scan(tmp_path, {
        "config.py": 'MODEL = "mistral:7b"\n',
        "app.py": "import ollama\nimport config\nollama.chat(model=config.MODEL, messages=[])\n",
    })
    assert "mistral:7b" in _in_use(result)
    assert not any(n.startswith("unidentified") for n in _models(result))


# --------------------------------------------------------------------------- m1


@pytest.mark.parametrize(("source", "tag"), [
    ('import argparse, ollama\np = argparse.ArgumentParser()\np.add_argument("--model", default="llama3.1:8b")\na = p.parse_args()\nollama.chat(model=a.model, messages=[])\n', "llama3.1:8b"),
    ('import os, ollama\nM = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")\nollama.chat(model=M, messages=[])\n', "qwen2.5:7b"),
    ('import argparse, ollama\np = argparse.ArgumentParser()\np.add_argument("-m", "--model-name", default="mistral:7b")\nargs = p.parse_args()\nollama.chat(model=args.model_name, messages=[])\n', "mistral:7b"),
])
def test_a_default_and_the_config_driven_call_are_one_model(tmp_path, source, tag) -> None:
    result = _scan(tmp_path, {"app.py": source})
    assert _in_use(result) == {tag}


def test_an_argparse_option_with_no_default_stays_unidentified(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        'import argparse, ollama\np = argparse.ArgumentParser()\np.add_argument("--model")\n'
        "a = p.parse_args()\nollama.chat(model=a.model, messages=[])\n"
    )})
    assert "unidentified model (Ollama)" in _in_use(result)


# --------------------------------------------------------------------------- m2 LiteLLM


def test_a_litellm_ollama_route_is_served_by_the_litellm_default_server(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": 'import litellm\nlitellm.completion(model="ollama/llama3:8b", messages=[])\n'})
    assert _served(result, "llama3:8b") == ["Ollama (local)"]


def test_a_litellm_api_base_on_an_ollama_route_is_that_server_not_a_gateway(tmp_path) -> None:
    files = {"app.py": 'import litellm\nlitellm.completion(model="ollama/llama3:8b", api_base="http://gpu-box:11434", messages=[])\n'}
    result = _scan(tmp_path, files)
    assert _served(result, "llama3:8b") == ["Ollama server (gpu-box:11434)"]
    assert not any(n.startswith("AI gateway") for n in _services(result))
    rows = _rows(tmp_path / "rows", files)
    assert rows["llama3:8b"]["component_type"] == "self_hosted_model"
    assert rows["Ollama server (gpu-box:11434)"]["component_type"] == "self_hosted_model_server"


_PROXY = (
    "model_list:\n"
    "  - model_name: local\n    litellm_params:\n      model: ollama/phi3:mini\n      api_base: http://ollama:11434\n"
    "  - model_name: gpt\n    litellm_params:\n      model: openai/gpt-4o\n      api_key: os.environ/OPENAI_API_KEY\n"
    "  - model_name: fast\n    litellm_params:\n      model: groq/llama3-8b-8192\n"
)


def test_the_litellm_proxy_config_model_list_is_read(tmp_path) -> None:
    result = _scan(tmp_path, {"config.yaml": _PROXY})
    assert {"phi3:mini", "gpt-4o"} <= _in_use(result)
    assert _served(result, "phi3:mini") == ["Ollama server (ollama:11434)"]
    assert _served(result, "gpt-4o") == ["OpenAI API"]
    assert "OpenAI" not in _services(result)  # no endpoint-less provider node
    served_fast = [n for n in _in_use(result) if "8192" in n or n.startswith("llama3-8b")]
    assert served_fast and _served(result, served_fast[0]) == ["Groq API"]


@pytest.mark.parametrize(("route", "service"), [
    ("groq/llama3-8b-8192", "Groq API"),
    ("together_ai/meta-llama/Llama-3-70b-chat-hf", "Together AI API"),
])
def test_hosted_litellm_routes_are_provider_models_not_weight_files(tmp_path, route, service) -> None:
    files = {"app.py": f'import litellm\nlitellm.completion(model="{route}", messages=[])\n'}
    result = _scan(tmp_path, files)
    in_use = _in_use(result)
    assert in_use, _models(result)
    for name in in_use:
        assert _served(result, name) == [service], name
    rows = _rows(tmp_path / "rows", files)
    for name in in_use:
        assert rows[name]["component_type"] == "external_provider", (name, rows[name]["component_type"])


# --------------------------------------------------------------------------- m3


def test_the_compose_ollama_container_and_its_server_are_one_row(tmp_path) -> None:
    compose = (
        "services:\n  app:\n    build: .\n    environment:\n      OLLAMA_HOST: http://ollama:11434\n"
        "  ollama:\n    image: ollama/ollama:latest\n"
    )
    result = _scan(tmp_path, {"app.py": 'import ollama\nollama.chat(model="llama3.1:8b", messages=[])\n',
                              "docker-compose.yml": compose})
    rows = [c for c in result.components if (c.properties or {}).get("service:platform") == "ollama"]
    assert [c.name for c in rows] == ["Ollama server (ollama:11434)"]
    (server,) = rows
    assert (server.properties or {}).get("discovery:image") == "ollama/ollama:latest"
    assert _served(result, "llama3.1:8b") == ["Ollama server (ollama:11434)"]


def test_a_conflict_leaves_no_unused_local_row(tmp_path) -> None:
    manifest = (
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n"
        "        - name: app\n          image: app:1\n          env:\n"
        "            - name: OLLAMA_HOST\n              value: http://127.0.0.1:11434\n"
    )
    compose = ("services:\n  app:\n    build: .\n    environment:\n      OLLAMA_HOST: http://ollama:11434\n"
               "  ollama:\n    image: ollama/ollama:latest\n")
    result = _scan(tmp_path, {"app.py": 'import ollama\nollama.chat(model="llama3.1:8b", messages=[])\n',
                              "deploy/a.yaml": manifest, "docker-compose.yml": compose})
    ollama_rows = {n for n in _services(result) if "ollama" in n.lower()}
    assert "Ollama (local)" not in ollama_rows
    assert "Ollama server (endpoint unknown)" in ollama_rows
    assert _served(result, "llama3.1:8b") == ["Ollama server (endpoint unknown)"]


# --------------------------------------------------------------------------- m4


def test_a_bare_alias_stays_next_to_its_tagged_form(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import ollama\n"
        'ollama.chat(model="gemma3n", messages=[])\n'
        'ollama.chat(model="gemma3n:e4b", messages=[])\n'
        'ollama.chat(model="gemma3n:latest", messages=[])\n'
    )})
    in_use = _in_use(result)
    assert {"gemma3n", "gemma3n:e4b"} <= in_use
    # ``:latest`` is the bare alias: one model, not two
    assert len([n for n in in_use if n.split(":")[0] == "gemma3n"]) == 2


# --------------------------------------------------------------------------- nit


def test_every_verdict_on_a_partial_scan_is_qualified(tmp_path, monkeypatch) -> None:
    from aibom.scan.scanners import net_env_scan

    def boom(self, ctx):
        raise RuntimeError("engine bug")

    monkeypatch.setattr(net_env_scan.NetEnvScanner, "scan", boom)
    result = _scan(tmp_path, {
        "requirements.txt": "openai==1.50.0\n",
        "app.py": 'from openai import OpenAI\nc = OpenAI()\nc.chat.completions.create(model="gpt-4o", messages=[])\n',
    })
    report = run_all(result)
    reqs = [r for fw in report.values() if isinstance(fw, dict) and "requirements" in fw for r in fw["requirements"]]
    for verdict in ("na", "not_bom_evidenceable"):
        some = [r for r in reqs if r["verdict"] == verdict]
        assert some, verdict
        assert all("based on an incomplete scan" in r["evidence"] for r in some), verdict
