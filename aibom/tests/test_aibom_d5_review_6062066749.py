# ruff: noqa: E501 - the reviewer's probe sources are kept verbatim (long lines)
"""Review 6062066749 of #498 (D5 AI BOM, round 4): the reviewer's probes as tests.

M1 a remote / env / unknown Ollama endpoint is never claimed as the local one, and a
   model is linked to a server at call-site scope, never repo-wide;
M2 Ollama library tags are open-weights models of their family (never the maker's
   hosted product), ``-cloud`` tags and ollama.com are Ollama Cloud;
M3 a malformed notebook never aborts the scan;
M4 a model chosen from configuration is an unidentified model, never "no AI model";
m1-m6 the minors. Every credential below is a fake placeholder.
"""

from __future__ import annotations

import json
import pathlib

from aibom.compliance import run_all
from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.model.result import REL_SERVED_BY
from aibom.scan.parsers.code_imports import read_notebook
from aibom.scan.parsers.license_resolver import resolve_license
from aibom.scan.pipeline import scan_repo


def _repo(tmp_path: pathlib.Path, files: dict[str, str]) -> pathlib.Path:
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return tmp_path


def _scan(tmp_path, files):
    return scan_repo(_repo(tmp_path, files), level=4)  # the worker's level


def _models(result) -> dict:
    return {c.name: c for c in result.components if c.kind == "model"}


def _services(result) -> dict:
    return {c.name: c for c in result.components if c.kind in ("cloud_service", "endpoint", "service")}


def _served(result, name: str) -> list[str]:
    model = _models(result)[name]
    by_ref = {c.bom_ref: c for c in result.components}
    return [by_ref[e.dst].name for e in result.edges if e.src == model.bom_ref and e.rel == REL_SERVED_BY]


def _licence(comp) -> str | None:
    if not comp.licenses:
        return None
    if "expression" in comp.licenses[0]:
        return comp.licenses[0]["expression"]
    lic = comp.licenses[0]["license"]
    return lic.get("id") or lic.get("name")


def _rows(root) -> dict:
    return {r["component_name"]: r for r in scan_to_devsecshield(root, level=4)["results"]}


# --------------------------------------------------------------------------- M1


def test_a_positional_ollama_host_is_that_remote_server(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "from ollama import Client\n"
        'c = Client("http://gpu-box:11434")\n'
        'r = c.chat(model="llama3.1:8b", messages=[])\n'
    )})
    services = _services(result)
    assert "Ollama (local)" not in services
    server = services["Ollama server (gpu-box:11434)"]
    assert server.properties["service:endpoint"] == "http://gpu-box:11434"
    assert server.properties["service:trust_zone"] != "local"
    assert _served(result, "llama3.1:8b") == ["Ollama server (gpu-box:11434)"]
    # never an invented, endpoint-less "Meta" vendor node
    assert "Meta" not in services


def test_ollama_host_from_the_env_file_is_used(tmp_path) -> None:
    result = _scan(tmp_path, {
        ".env": "OLLAMA_HOST=http://10.0.0.5:11434\n",
        "app.py": 'import ollama\nr = ollama.chat(model="llama3.1:8b", messages=[])\n',
    })
    services = _services(result)
    assert "Ollama (local)" not in services
    server = services["Ollama server (10.0.0.5:11434)"]
    assert server.properties["service:endpoint_basis"] == "env-file"
    assert server.properties["service:endpoint_env"] == "OLLAMA_HOST"


def test_a_variable_ollama_host_is_an_unknown_endpoint(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import os, ollama\nc = ollama.Client(host=os.environ['OLLAMA_URL'])\n"
        'r = c.chat(model="llama3.1:8b", messages=[])\n'
    )})
    services = _services(result)
    assert "Ollama (local)" not in services
    (server,) = [s for n, s in services.items() if n.startswith("Ollama server")]
    assert server.name == "Ollama server (endpoint unknown)"
    assert "service:endpoint" not in server.properties
    assert server.properties["service:endpoint_env"] == "OLLAMA_URL"
    assert server.properties["service:trust_zone"] == "unknown"
    assert _served(result, "llama3.1:8b") == ["Ollama server (endpoint unknown)"]


def test_no_repo_wide_local_link_and_the_vendor_checks_assess_the_env_endpoint(tmp_path) -> None:
    root = _repo(tmp_path, {
        "dev.py": 'import ollama\nr = ollama.chat(model="llama3.1:8b", messages=[])\n',
        "prod.py": "import os\nfrom openai import OpenAI\n"
        'c = OpenAI(base_url=os.environ["TOGETHER_URL"])\n'
        'r = c.chat.completions.create(model="llama-3.1-70b-instruct", messages=[])\n',
    })
    result = scan_repo(root, level=4)
    assert _served(result, "llama-3.1-70b-instruct") == ["AI endpoint (TOGETHER_URL)"]
    assert _services(result)["AI endpoint (TOGETHER_URL)"].properties["service:endpoint_env"] == "TOGETHER_URL"
    run_all(result)
    for fw, rid in (("rbi_free_ai", "FREEAI-19-1"), ("nist_rmf", "GV-2")):
        req = {q["id"]: q for q in result.compliance[fw]["requirements"]}[rid]
        assert req["verdict"] != "na", (fw, req["evidence"])
    rows = _rows(root)
    assert rows["llama-3.1-70b-instruct"]["component_type"] == "external_provider"


def test_a_self_hosted_ollama_behind_base_url_is_a_model_server_not_a_gateway(tmp_path) -> None:
    root = _repo(tmp_path, {"app.py": (
        "from langchain_ollama import ChatOllama\n"
        'llm = ChatOllama(model="mistral:7b", base_url="http://ollama.prod.svc:11434")\n'
    )})
    rows = _rows(root)
    assert not [n for n in rows if n.startswith("AI gateway")]
    server = rows["Ollama server (ollama.prod.svc:11434)"]
    assert server["component_type"] == "self_hosted_model_server"
    assert server["license"] == "Apache-2.0"  # the one model it serves, never proprietary
    assert rows["mistral:7b"]["component_type"] == "self_hosted_model"


def test_call_site_scope_picks_the_client_the_call_is_made_on(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import os\nfrom openai import OpenAI\n"
        'proxy = OpenAI(base_url="http://litellm.internal:4000")\n'
        'other = OpenAI(base_url=os.environ["OTHER_URL"])\n'
        'a = proxy.chat.completions.create(model="gpt-4o", messages=[])\n'
        'b = other.chat.completions.create(model="gpt-4o-mini", messages=[])\n'
    )})
    assert _served(result, "gpt-4o") == ["AI gateway (litellm.internal:4000)"]
    assert _served(result, "gpt-4o-mini") == ["AI endpoint (OTHER_URL)"]


# --------------------------------------------------------------------------- M2

_TAGS = {
    "mistral:7b": ("Mistral", "Apache-2.0"),
    "mistral": ("Mistral", "Apache-2.0"),
    "mixtral:8x7b": ("Mistral", "Apache-2.0"),
    "phi3:mini": ("Microsoft", "MIT"),
    "phi4": ("Microsoft", "MIT"),
    "deepseek-r1:8b": ("DeepSeek", "MIT"),  # 8b = R1-0528-Qwen3-8B (HF mit)
    "codellama:7b": ("Meta", "LicenseRef-llama2-community"),
    # per tag (review 6063080163 R4-M1): 22b = 2409 under the MRL, 24b = 2501 Apache-2.0
    "mistral-small:22b": ("Mistral", "LicenseRef-Mistral-Research-License"),
    "mistral-small:24b": ("Mistral", "Apache-2.0"),
    "deepseek-r1:70b": ("DeepSeek", "MIT AND LicenseRef-llama3.3-community"),
    "llama2:7b": ("Meta", "LicenseRef-llama2-community"),
    "llava:13b": ("LLaVA", None),
    "nomic-embed-text": ("Nomic", "Apache-2.0"),
    "mxbai-embed-large": ("mixedbread", "Apache-2.0"),
    "gpt-oss:20b": ("OpenAI", "Apache-2.0"),
    "command-r": ("Cohere", "CC-BY-NC-4.0"),
    "qwen2.5:7b": ("Alibaba", "Apache-2.0"),  # 7b Apache; only 3b / 72b are Qwen licences
    "gemma2:9b": ("Google", "LicenseRef-Gemma-Terms-of-Use"),
    "llama3.1:8b": ("Meta", "LicenseRef-llama3.1-community"),
    "llama3.2": ("Meta", "LicenseRef-llama3.2-community"),
    "tinyllama": (None, None),
}


def test_ollama_library_tags_are_open_weights_models_of_their_family(tmp_path) -> None:
    body = "import ollama\n" + "".join(
        f'r{i} = ollama.chat(model="{tag}", messages=[])\n' for i, tag in enumerate(_TAGS)
    )
    root = _repo(tmp_path, {"app.py": body})
    result = scan_repo(root, level=4)
    models = _models(result)
    assert set(models) == set(_TAGS)
    for tag, (vendor, licence) in _TAGS.items():
        assert models[tag].publisher == vendor, tag
        assert _licence(models[tag]) == licence, tag
        assert _served(result, tag) == ["Ollama (local)"], tag
    # no hosted product, no vendor node: the prompts never leave the host
    assert not [c for c in result.components if c.kind == "service"]
    rows = _rows(root)
    assert rows["gpt-oss:20b"]["component_type"] == "self_hosted_model"
    assert rows["command-r"]["license"] == "CC-BY-NC-4.0"
    assert rows["llava:13b"]["license"] == "NOASSERTION"


def test_cloud_tags_and_the_ollama_com_host_are_ollama_cloud(tmp_path) -> None:
    result = _scan(tmp_path, {
        "a.py": 'import ollama\nr = ollama.chat(model="gpt-oss:120b-cloud", messages=[])\n',
        "b.py": "from ollama import Client\n"
        'c = Client(host="https://ollama.com", headers={"Authorization": "Bearer FAKE"})\n'
        'r = c.chat(model="qwen3-coder:480b", messages=[])\n',
    })
    cloud = _services(result)["Ollama Cloud"]
    assert cloud.properties["service:endpoint"] == "https://ollama.com"
    assert cloud.properties["service:trust_zone"] == "external"
    assert _served(result, "gpt-oss:120b-cloud") == ["Ollama Cloud"]
    assert _served(result, "qwen3-coder:480b") == ["Ollama Cloud"]  # the client's host


# --------------------------------------------------------------------------- M3


def test_malformed_notebooks_never_abort_the_scan(tmp_path) -> None:
    good = {"cells": [{"cell_type": "code", "source": ["from transformers import pipeline\n",
                                                        'p = pipeline("asr", model="openai/whisper-large-v3")\n']}]}
    files = {
        "a.ipynb": json.dumps({"cells": {"a": 1}}),
        "b.ipynb": json.dumps([1, 2, 3]),
        "c.ipynb": json.dumps({"cells": [{"cell_type": "code", "source": [1, 2]}, "x", None]}),
        "d.ipynb": '{"cells": [ {"cell_type": "code", "source": ["from openai import OpenAI\\n", "c = OpenAI()\\n"',
        "nb3.ipynb": json.dumps({"worksheets": [{"cells": [{"cell_type": "code", "input": [
            'from sentence_transformers import SentenceTransformer\n', 'm = SentenceTransformer("all-MiniLM-L6-v2")\n']}]}]}),
        "good.ipynb": json.dumps(good),
    }
    result = _scan(tmp_path, files)
    assert "aibom:scanner_errors" not in result.properties
    # not notebooks (cells not a list, a top-level list) or invalid JSON: warned, read as text
    assert result.properties["aibom:notebooks_unreadable"] == "a.ipynb, b.ipynb, d.ipynb"
    models = _models(result)
    assert "openai/whisper-large-v3" in models and "all-MiniLM-L6-v2" in models
    # the truncated notebook is read as raw text: its client is still a service
    assert "OpenAI API" in _services(result)
    assert read_notebook(files["a.ipynb"]) is None and read_notebook(files["b.ipynb"]) is None
    assert read_notebook(files["c.ipynb"]) == ""


def test_a_failing_scanner_is_recorded_not_raised(tmp_path, monkeypatch) -> None:
    from aibom.scan.scanners import model_ref_scan

    def boom(self, ctx):
        raise RuntimeError("probe")

    monkeypatch.setattr(model_ref_scan.ModelRefScanner, "scan", boom)
    result = _scan(tmp_path, {"requirements.txt": "openai==1.50.0\n"})
    # an engine bug (not bad input): logged with its traceback, counted, marked unexpected
    assert result.properties["aibom:scanner_errors"] == "model-ref: RuntimeError (unexpected)"
    assert result.properties["aibom:scan_completeness"] == "partial"
    assert [c.name for c in result.components if c.kind == "framework"] == ["openai"]


# --------------------------------------------------------------------------- M4


def test_a_model_from_configuration_is_an_unidentified_model(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import os\nfrom langchain_openai import ChatOpenAI\n"
        'llm = ChatOpenAI(model=os.environ["M"])\n'
    )})
    (model,) = _models(result).values()
    assert model.name == "unidentified model (ChatOpenAI)"
    assert model.properties["model:unidentified_reason"] == "model from configuration"
    assert model.properties["model:config_keys"] == "M"
    assert model.properties["discovery:snippet"] == 'ChatOpenAI(model=os.environ["M"]) in app.py'
    run_all(result)
    for fw in ("cert_in_aibom", "rbi_free_ai", "sebi_cscrf_aibom", "eu_ai_act_annexIV"):
        assert result.compliance[fw]["out_of_scope"] == 0, fw  # never "no AI models detected"
    name = {q["id"]: q for q in result.compliance["cert_in_aibom"]["requirements"]}["T10-Model-Name"]
    assert name["verdict"] == "not_bom_evidenceable"
    assert name["evidence"].startswith("AI model use detected; model not identified (model from configuration)")


def test_an_sdk_call_with_a_configured_model_is_unidentified_and_known_ones_are_not(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import os\nfrom openai import OpenAI\nclient = OpenAI()\n"
        'MODEL = "gpt-4o-mini"\n'
        "a = client.chat.completions.create(model=settings.CHAT_MODEL, messages=[])\n"
        "b = client.chat.completions.create(model=MODEL, messages=[])\n"
        'c = client.chat.completions.create(model=os.getenv("X", "gpt-4o"), messages=[])\n'
    )})
    models = _models(result)
    assert set(models) == {"unidentified model (OpenAI)", "gpt-4o-mini", "gpt-4o"}
    assert models["unidentified model (OpenAI)"].properties["model:config_keys"] == "CHAT_MODEL"
    assert _served(result, "unidentified model (OpenAI)") == ["OpenAI API"]


# --------------------------------------------------------------------------- minors


def test_m1_one_unidentified_model_per_class_with_every_call_site(tmp_path) -> None:
    from aibom.emit.cyclonedx import emit_and_validate

    result = _scan(tmp_path, {
        "a.py": "from langchain_openai import ChatOpenAI\nllm = ChatOpenAI()\n",
        "b.py": "from langchain_openai import ChatOpenAI\nllm = ChatOpenAI()\n",
    })
    (model,) = [m for m in _models(result).values() if m.properties.get("model:identified") == "false"]
    assert model.properties["discovery:sources"] == "a.py,b.py"
    bom = emit_and_validate(result)
    (comp,) = [c for c in bom["components"] if c["name"] == "unidentified model (ChatOpenAI)"]
    assert comp["evidence"]["occurrences"] == [{"location": "a.py"}, {"location": "b.py"}]
    rows = _rows(tmp_path)
    assert rows["unidentified model (ChatOpenAI)"]["model_identified"] is False


def test_m2_manifests_dedupe_by_pep503_name(tmp_path) -> None:
    result = _scan(tmp_path, {
        "requirements.txt": "pyannote.audio==3.1.1\nfaster_whisper==1.0.3\n",
        "pyproject.toml": '[project]\nname = "x"\ndependencies = ["pyannote-audio>=3.1", "faster-whisper"]\n',
    })
    libs = [c.name for c in result.components if c.kind == "framework"]
    assert sorted(libs) == ["faster_whisper", "pyannote.audio"]


def test_m3_licences_from_pypi() -> None:
    assert resolve_license("whisperx") == "BSD-2-Clause"
    for pkg in ("langchain-openai", "langchain-anthropic", "langchain-community", "langchain-core",
                "langchain-ollama", "langchain-aws", "langgraph"):
        assert resolve_license(pkg) == "MIT", pkg


def test_m4_notebook_clients_and_strong_context_orgless_hub_ids(tmp_path) -> None:
    nb = {"cells": [{"cell_type": "code", "source": [
        "from langchain_openai import ChatOpenAI\n", "llm = ChatOpenAI()\n",
        "from transformers import AutoModel, pipeline\n",
        'm = AutoModel.from_pretrained("bert-base-uncased")\n',
        'p = pipeline("text-generation", model="gpt2")\n',
        'local = AutoModel.from_pretrained("output")\n',
        'label = "gpt2-like prose"\n',
    ]}]}
    result = _scan(tmp_path, {"nb.ipynb": json.dumps(nb)})
    assert "OpenAI API" in _services(result)
    models = _models(result)
    assert "unidentified model (ChatOpenAI)" in models
    assert models["bert-base-uncased"].purl == "pkg:huggingface/bert-base-uncased"
    assert models["gpt2"].purl == "pkg:huggingface/gpt2"
    assert "output" not in models


def test_m6_an_unidentified_chatollama_is_no_model_file(tmp_path) -> None:
    root = _repo(tmp_path, {"app.py": "from langchain_ollama import ChatOllama\nllm = ChatOllama()\n"})
    rows = _rows(root)
    row = rows["unidentified model (ChatOllama)"]
    assert row["component_type"] == "self_hosted_model"
    assert row["license"] == "NOASSERTION"
