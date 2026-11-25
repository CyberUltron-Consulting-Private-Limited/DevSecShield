# ruff: noqa: E501 - the reviewer's probe sources are kept verbatim (long lines)
"""Review 6063080163 of #498 (D5 AI BOM, round 5): the reviewer's probes as tests.

R4-M1 Ollama tag licences per tag / size, not per family;
R4-M2 a scanner that did not finish is visible and withholds the grade;
R4-M3 a model named in one file and used in another: no invented hosted provider,
      no double count, one-hop wrappers resolved;
R4-M4 OLLAMA_HOST from Kubernetes / Helm and from code; getenv fallbacks and example
      files are defaults, never the endpoint;
minors and nits. Every credential below is a fake placeholder.
"""

from __future__ import annotations

import json
import logging
import pathlib
import re

from aibom.compliance import run_all
from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.model.result import REL_SERVED_BY
from aibom.scan.parsers.code_imports import read_notebook
from aibom.scan.parsers.ollama_tags import ollama_family
from aibom.scan.pipeline import scan_repo

_REPO = pathlib.Path(__file__).resolve().parents[2]


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


def _services(result) -> dict:
    return {c.name: c for c in result.components if c.kind in ("cloud_service", "endpoint", "service", "container")}


def _served(result, name: str) -> list[str]:
    model = _models(result)[name]
    by_ref = {c.bom_ref: c for c in result.components}
    return [by_ref[e.dst].name for e in result.edges if e.src == model.bom_ref and e.rel == REL_SERVED_BY]


def _rows(root) -> dict:
    return {r["component_name"]: r for r in scan_to_devsecshield(root, level=4)["results"]}


_OLLAMA_CALL = 'import ollama\nr = ollama.chat(model="llama3.1:8b", messages=[])\n'


# --------------------------------------------------------------------------- R4-M1


def test_tag_licences_resolve_per_size_and_version() -> None:
    expected = {
        "mistral-small:22b": "LicenseRef-Mistral-Research-License",  # 22b-instruct-2409, HF license_name mrl
        "mistral-small:22b-instruct-2409-q4_K_M": "LicenseRef-Mistral-Research-License",
        "mistral-small:24b": "Apache-2.0",  # 24b-instruct-2501, HF apache-2.0
        "mistral-small3.1": "Apache-2.0",
        "mistral-small": None,  # the bare alias moves
        "mistral-small:latest": None,
        "deepseek-r1:671b": "MIT",
        "deepseek-r1:8b": "MIT",  # 8b-0528-qwen3, HF mit
        "deepseek-r1:7b": "MIT AND Apache-2.0",  # Qwen-2.5 distill (Ollama page)
        "deepseek-r1:70b": "MIT AND LicenseRef-llama3.3-community",  # Llama 3.3 distill
        "deepseek-r1": None,
        "llama2:7b": "LicenseRef-llama2-community",
        "llama3:8b": "LicenseRef-llama3-community",
        "llama3.3:70b": "LicenseRef-llama3.3-community",
        "qwen2.5:3b": "LicenseRef-Qwen-Research-License",
        "qwen2.5:72b": "LicenseRef-Qwen-License",
        "qwen2.5:14b": "Apache-2.0",
        "qwen3:8b": "Apache-2.0",
        "granite3.1-dense:8b": "Apache-2.0",
        "smollm2:1.7b": "Apache-2.0",
        "tinyllama": None,
    }
    for tag, licence in expected.items():
        assert ollama_family(tag)[1] == licence, tag


def test_an_expression_licence_is_a_cyclonedx_expression_and_spdx_valid(tmp_path) -> None:
    from aibom.emit.cyclonedx import emit_and_validate
    from aibom.emit.spdx import emit_spdx

    result = _scan(tmp_path, {"app.py": 'import ollama\nr = ollama.chat(model="deepseek-r1:70b", messages=[])\n'})
    bom = emit_and_validate(result)
    (comp,) = [c for c in bom["components"] if c["name"] == "deepseek-r1:70b"]
    assert comp["licenses"] == [{"expression": "MIT AND LicenseRef-llama3.3-community"}]
    doc = emit_spdx(result) if not isinstance(emit_spdx(result), str) else json.loads(emit_spdx(result))
    exprs = [e.get("simplelicensing_licenseExpression") for e in doc["@graph"]
             if e.get("type") == "simplelicensing_LicenseExpression"]
    assert "MIT AND LicenseRef-llama3.3-community" in exprs
    rows = _rows(tmp_path)
    assert rows["deepseek-r1:70b"]["license"] == "MIT AND LicenseRef-llama3.3-community"


# --------------------------------------------------------------------------- R4-M2


def test_a_scanner_failure_is_logged_counted_and_withholds_the_grade(tmp_path, monkeypatch, caplog) -> None:
    from aibom.scan.scanners import model_ref_scan

    def boom(self, ctx):
        raise KeyError("engine bug")

    monkeypatch.setattr(model_ref_scan.ModelRefScanner, "scan", boom)
    with caplog.at_level(logging.ERROR, logger="aibom.scan"):
        result = _scan(tmp_path, {"requirements.txt": "openai==1.50.0\n"})
    # an unexpected exception: logged at error level WITH its traceback
    (record,) = [r for r in caplog.records if r.name == "aibom.scan"]
    assert record.levelno == logging.ERROR and record.exc_info is not None
    assert result.properties["aibom:scanner_errors"] == "model-ref: KeyError (unexpected)"
    assert result.properties["aibom:scan_completeness"] == "partial"
    assert result.scores["completeness"] == "partial"
    assert result.scores["risk_grade"] == "—"  # withheld, never a clean A
    assert result.scores["risk_label"] == "Grade withheld: scan incomplete"


def test_a_parse_error_is_a_warning_not_an_unexpected_failure(tmp_path, monkeypatch, caplog) -> None:
    from aibom.scan.scanners import model_ref_scan

    def bad_input(self, ctx):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(model_ref_scan.ModelRefScanner, "scan", bad_input)
    with caplog.at_level(logging.WARNING, logger="aibom.scan"):
        result = _scan(tmp_path, {"requirements.txt": "openai==1.50.0\n"})
    assert result.properties["aibom:scanner_errors"] == "model-ref: UnicodeDecodeError"
    assert [r.levelno for r in caplog.records if r.name == "aibom.scan"] == [logging.WARNING]


# --------------------------------------------------------------------------- R4-M3


def test_a_tag_named_in_settings_is_self_hosted_never_meta(tmp_path) -> None:
    root = _repo(tmp_path, {"settings.py": 'PROD_MODEL = "llama3.1:70b"\n', "dev.py": _OLLAMA_CALL})
    result = scan_repo(root, level=4)
    model = _models(result)["llama3.1:70b"]
    assert model.properties["model:served_via"] == "ollama"
    assert model.properties["discovery:confidence"] == "low"
    assert _served(result, "llama3.1:70b") == ["Ollama (local)"]
    assert "Meta" not in _services(result)
    rows = _rows(root)
    assert rows["llama3.1:70b"]["component_type"] == "self_hosted_model"
    run_all(result)
    req = {q["id"]: q for q in result.compliance["rbi_free_ai"]["requirements"]}["FREEAI-19-1"]
    assert "DPA" not in req["evidence"]  # no third party to ask a contract of


def test_a_tag_never_used_with_a_client_has_no_provider(tmp_path) -> None:
    result = _scan(tmp_path, {"settings.py": 'PROD_MODEL = "llama3.1:70b"\n'})
    assert _served(result, "llama3.1:70b") == []
    assert not [c for c in result.components if c.kind == "service"]


def test_an_imported_constant_is_one_named_model_not_two(tmp_path) -> None:
    result = _scan(tmp_path, {
        "cfg.py": 'MODEL = "qwen2.5:7b"\n',
        "app.py": "import ollama\nfrom cfg import MODEL\nr = ollama.chat(model=MODEL, messages=[])\n",
    })
    assert set(_models(result)) == {"qwen2.5:7b"}
    assert "aibom:model_unnamed_calls" not in result.properties
    assert "Alibaba" not in _services(result)


def test_a_one_hop_wrapper_resolves_its_literal(tmp_path) -> None:
    result = _scan(tmp_path, {
        "llm.py": 'import ollama\ndef ask(m, q):\n    return ollama.chat(model=m, messages=[{"role": "user", "content": q}])\n',
        "app.py": 'from llm import ask\nprint(ask("mistral:7b", "hi"))\n',
    })
    assert set(_models(result)) == {"mistral:7b"}
    assert _served(result, "mistral:7b") == ["Ollama (local)"]


def test_a_wrapper_never_called_with_a_literal_stays_unidentified(tmp_path) -> None:
    result = _scan(tmp_path, {
        "llm.py": "import ollama\ndef ask(m, q):\n    return ollama.chat(model=m, messages=[])\n",
        "app.py": "import os\nfrom llm import ask\nprint(ask(os.environ['M'], 'hi'))\n",
    })
    assert set(_models(result)) == {"unidentified model (Ollama)"}


# --------------------------------------------------------------------------- R4-M4


def test_ollama_host_from_a_kubernetes_manifest(tmp_path) -> None:
    result = _scan(tmp_path, {
        "app.py": _OLLAMA_CALL,
        "deploy/app.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n"
        "        - name: app\n          env:\n            - name: OLLAMA_HOST\n              value: http://ollama.ml.svc:11434\n",
    })
    assert "Ollama (local)" not in _services(result)
    assert _served(result, "llama3.1:8b") == ["Ollama server (ollama.ml.svc:11434)"]


def test_ollama_host_from_helm_values(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": _OLLAMA_CALL, "chart/values.yaml": "env:\n  OLLAMA_HOST: http://10.2.2.2:11434\n"})
    assert _served(result, "llama3.1:8b") == ["Ollama server (10.2.2.2:11434)"]


def test_ollama_host_set_in_code(tmp_path) -> None:
    result = _scan(tmp_path, {
        "boot.py": 'import os\nos.environ["OLLAMA_HOST"] = "http://10.1.1.1:11434"\n',
        "app.py": _OLLAMA_CALL,
    })
    assert "Ollama (local)" not in _services(result)
    assert _served(result, "llama3.1:8b") == ["Ollama server (10.1.1.1:11434)"]


def test_a_getenv_fallback_is_a_default_not_a_second_local_server(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import os\nfrom ollama import Client\n"
        'c = Client(host=os.getenv("OLLAMA_HOST", "http://localhost:11434"))\n'
        'r = c.chat(model="llama3.1:8b", messages=[])\n'
    )})
    services = _services(result)
    assert "Ollama (local)" not in services
    server = services["Ollama server (endpoint unknown)"]
    assert server.properties["service:endpoint_env"] == "OLLAMA_HOST"
    assert server.properties["service:endpoint_default"] == "http://localhost:11434"
    assert _served(result, "llama3.1:8b") == ["Ollama server (endpoint unknown)"]


def test_an_example_env_file_is_a_default_not_the_endpoint(tmp_path) -> None:
    result = _scan(tmp_path, {".env.example": "OLLAMA_HOST=http://10.0.0.5:11434\n", "app.py": _OLLAMA_CALL})
    services = _services(result)
    assert "Ollama server (10.0.0.5:11434)" not in services
    server = services["Ollama server (endpoint unknown)"]
    assert server.properties["service:endpoint_basis"] == "example"
    assert server.properties["service:endpoint_default"] == "http://10.0.0.5:11434"


# --------------------------------------------------------------------------- minors


def test_m3_a_self_hosted_server_needs_hosting_evidence_not_a_vendor_dpa(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": 'from ollama import Client\nc = Client("http://gpu-box:11434")\nr = c.chat(model="llama3.1:8b", messages=[])\n'})
    run_all(result)
    for fw, rid in (("rbi_free_ai", "FREEAI-19-1"), ("nist_rmf", "GV-2")):
        req = {q["id"]: q for q in result.compliance[fw]["requirements"]}[rid]
        assert req["verdict"] == "not_bom_evidenceable"
        assert "self-hosted model server: no vendor; attest who operates the host" in req["evidence"]
        assert "DPA" not in req["evidence"]


def test_m4_a_remote_ollama_rest_url_and_the_bind_address_are_servers(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        'URL = "http://gpu-box:11434/api/generate"\n'
        "def ask(q, http):\n    return http.post(URL, json={\"model\": \"mistral:7b\", \"prompt\": q})\n"
    ), "b.py": 'B = "http://0.0.0.0:11434"\n'})
    services = _services(result)
    assert "Ollama server (gpu-box:11434)" in services
    assert services["Ollama (local)"].properties["service:endpoint"] == "http://0.0.0.0:11434"
    assert _served(result, "mistral:7b") == ["Ollama server (gpu-box:11434)"]


def test_m5_unnamed_call_libraries_are_the_sdk_used(tmp_path) -> None:
    result = _scan(tmp_path, {
        "requirements.txt": "openai==1.50.0\nollama==0.4.4\n",
        "a.py": "import os\nfrom openai import OpenAI\nc = OpenAI()\nr = c.chat.completions.create(model=os.environ['M'], messages=[])\n",
        "b.py": "import os, ollama\nr = ollama.chat(model=os.environ['N'], messages=[])\n",
    })
    assert result.properties["aibom:model_unnamed_library"] == "ollama 0.4.4; openai 1.50.0"
    models = _models(result)
    assert models["unidentified model (OpenAI)"].properties["model:default_from_library"] == "openai 1.50.0"


def test_m6_a_comma_import_is_the_sdk(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import os, openai\nimport sys, anthropic\n"
        'c = openai.OpenAI()\nr = c.chat.completions.create(model="gpt-4o", messages=[])\n'
        'a = anthropic.Anthropic()\nm = a.messages.create(model="claude-3-5-sonnet-20241022", max_tokens=1, messages=[])\n'
    )})
    assert _served(result, "gpt-4o") == ["OpenAI API"]
    assert _served(result, "claude-3-5-sonnet-20241022") == ["Anthropic API"]


def test_m7_the_legacy_worker_maps_the_new_types() -> None:
    text = (_REPO / "RabbitMQ/worker/helpers/tools/ai_bom_agent/parser.py").read_text()
    for member, cdx in (("LOCAL_MODEL_SERVER", "platform"), ("SELF_HOSTED_MODEL_SERVER", "platform"),
                        ("SELF_HOSTED_MODEL", "machine-learning-model")):
        assert re.search(rf"AIComponentType\.{member}\.value:\s*\"{cdx}\"", text), member


def test_m8_a_compose_ollama_container_is_a_self_hosted_server(tmp_path) -> None:
    root = _repo(tmp_path, {"docker-compose.yml": "services:\n  ollama:\n    image: ollama/ollama:latest\n"})
    row = _rows(root)["Ollama"]
    assert row["component_type"] == "self_hosted_model_server"
    assert row["license"] == "MIT"


# --------------------------------------------------------------------------- nits


def test_a_notebook_with_a_byte_order_mark_is_read(tmp_path) -> None:
    nb = {"cells": [{"cell_type": "code", "source": ['from transformers import pipeline\n',
                                                    'p = pipeline("asr", model="openai/whisper-large-v3")\n']}]}
    text = "﻿" + json.dumps(nb)
    assert read_notebook(text) is not None
    result = _scan(tmp_path, {"n.ipynb": text})
    assert "aibom:notebooks_unreadable" not in result.properties
    assert "openai/whisper-large-v3" in _models(result)


def test_an_f_string_model_is_an_unidentified_model_with_its_template(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "from langchain_openai import ChatOpenAI\n"
        'v = "4o"\nllm = ChatOpenAI(model=f"gpt-{v}")\n'
    )})
    (model,) = _models(result).values()
    assert model.name == "unidentified model (ChatOpenAI)"
    assert model.properties["discovery:snippet"] == 'ChatOpenAI(model=f"gpt-{v}") in app.py'
