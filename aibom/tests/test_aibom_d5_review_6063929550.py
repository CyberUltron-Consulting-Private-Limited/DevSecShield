# ruff: noqa: E501 - the reviewer's probe sources are kept verbatim (long lines)
"""Review 6063929550 of #498 (D5 AI BOM, round 6): the reviewer's probes as tests.

R5-M1 a loose ``family:tag`` literal is an Ollama model in use only when the
      repository has Ollama evidence and the tag is a real size / variant tag;
      lists, dict keys, picker options, docstrings and cache / log keys are
      catalogue mentions or nothing;
R5-M2 a partial scan withholds grade AND band everywhere: SARIF says the run did
      not succeed, compliance verdicts say they rest on an incomplete scan;
minors: OLLAMA_HOST only from the application's workloads, conflicting hosts are
unknown; per-tag licences (gemma3n, phi4-reasoning, qwen2.5-coder:7b); one licence
per model version whatever the source path; LiteLLM ``ollama/<tag>``.
The Docker / host:port / time negatives stay as regression tests.
"""

from __future__ import annotations

import pathlib

import pytest

from aibom.compliance import run_all
from aibom.emit.sarif import emit_sarif
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


def _catalog(result) -> set[str]:
    return {n for n, c in _models(result).items() if (c.properties or {}).get("model:reference_type") == "catalog"}


def _ollama_services(result) -> dict:
    return {c.name: c for c in result.components if (c.properties or {}).get("service:platform") == "ollama"}


def _served(result, name: str) -> list[str]:
    model = _models(result)[name]
    by_ref = {c.bom_ref: c for c in result.components}
    return [by_ref[e.dst].name for e in result.edges if e.src == model.bom_ref and e.rel == REL_SERVED_BY]


_OLLAMA_CALL = 'import ollama\nr = ollama.chat(model="llama3.1:8b", messages=[])\n'


# --------------------------------------------------------------------------- R5-M1


def test_a_model_picker_list_without_ollama_is_a_catalogue_not_six_models(tmp_path) -> None:
    result = _scan(tmp_path, {"ui.py": (
        "import streamlit as st\n"
        'choice = st.selectbox("Model", ["llama3:8b", "mistral:7b", "gemma2:9b", "phi3:mini", "qwen2:7b", "codellama:13b"])\n'
    )})
    assert _in_use(result) == set()


def test_a_benchmark_dict_and_a_log_line_are_not_models_in_use(tmp_path) -> None:
    result = _scan(tmp_path, {
        "client.py": _OLLAMA_CALL,
        "bench.py": 'SCORES = {"llama3:8b": 0.71, "mistral:7b": 0.65}\nlabel = "mistral:7b"\nprint(label)\n',
    })
    assert "mistral:7b" not in _in_use(result)
    assert "llama3:8b" not in _in_use(result)


def test_a_tag_that_is_not_a_size_or_variant_is_never_a_model(tmp_path) -> None:
    from aibom.scan.parsers.ollama_tags import valid_tag

    result = _scan(tmp_path, {"client.py": _OLLAMA_CALL, "stats.py": 'KEY = "llama3:hits"\nm = "llama3:hits"\n'})
    assert not any(n.startswith("llama3:hits") for n in _models(result))
    assert not valid_tag("llama3:hits")
    assert valid_tag("llama3:8b") and valid_tag("qwen2.5:7b-instruct-q4_K_M") and valid_tag("llava:latest")


def test_cache_keys_and_docstrings_are_never_models(tmp_path) -> None:
    result = _scan(tmp_path, {
        "client.py": _OLLAMA_CALL,
        "cache.py": 'import redis\nr = redis.Redis()\nr.set("mistral:7b", 1)\nr.get("gemma2:9b")\n',
        "doc.py": 'def f():\n    """Use a model such as "phi3:mini" here."""\n    return 1\n',
    })
    in_use = _in_use(result)
    assert not {"mistral:7b", "gemma2:9b", "phi3:mini"} & in_use


def test_the_literal_finder_classifies_usage_and_catalogue() -> None:
    from aibom.scan.parsers.ollama_tags import find_ollama_tag_literals

    found = dict(find_ollama_tag_literals('opts = ["llama3:8b", "mistral:7b"]\nmodel = "qwen2:7b"\n', "py"))
    assert found["llama3:8b"] == "catalog" and found["mistral:7b"] == "catalog"
    assert found["qwen2:7b"] == "usage"


def test_a_tag_in_config_json_is_a_model_not_a_weight_file_typed_as_in_yaml(tmp_path) -> None:
    json_res = _scan(tmp_path / "j", {"client.py": "import ollama\n", "config.json": '{"model": "llama3.1:8b"}\n'})
    yaml_res = _scan(tmp_path / "y", {"client.py": "import ollama\n", "config.yaml": "model: llama3.1:8b\n"})
    for result in (json_res, yaml_res):
        model = _models(result)["llama3.1:8b"]
        assert (model.properties or {}).get("model:served_via") == "ollama"
        assert (model.properties or {}).get("model:kind") != "weights"
    j, y = _models(json_res)["llama3.1:8b"], _models(yaml_res)["llama3.1:8b"]
    assert (j.kind, j.licenses) == (y.kind, y.licenses)
    assert {k: v for k, v in (j.properties or {}).items() if k != "discovery:source"} == \
        {k: v for k, v in (y.properties or {}).items() if k != "discovery:source"}


def test_a_litellm_ollama_route_is_an_ollama_model(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": 'import litellm\nlitellm.completion(model="ollama/llama3:8b", messages=[])\n'})
    model = _models(result)["llama3:8b"]
    assert (model.properties or {}).get("model:served_via") == "ollama"


# --------------------------------------------------------------------------- per-tag licences (m2-m4)


@pytest.mark.parametrize(("tag", "licence"), [
    ("gemma3n:e4b", "LicenseRef-Gemma-Terms-of-Use"),
    ("phi4-reasoning:14b", "MIT"),
    ("qwen2.5-coder:7b", "Apache-2.0"),
    ("qwen2.5-coder:3b", "LicenseRef-qwen-research"),
])
def test_ollama_tag_licences_with_cited_sources(tmp_path, tag, licence) -> None:
    result = _scan(tmp_path, {"client.py": f'import ollama\nollama.chat(model="{tag}", messages=[])\n'})
    model = _models(result)[tag]
    assert licence.lower() in str(model.licenses).lower(), model.licenses


def test_one_licence_per_model_version_whatever_the_source_path(tmp_path) -> None:
    ollama = _scan(tmp_path / "o", {"client.py": 'import ollama\nollama.chat(model="llama3.1:8b", messages=[])\n'})
    bedrock = _scan(tmp_path / "b", {"client.py": (
        "import boto3\nc = boto3.client('bedrock-runtime')\n"
        "c.invoke_model(modelId='meta.llama3-1-8b-instruct-v1:0', body='{}')\n"
    )})

    def lic(result):
        return {str(model.licenses) for model in _models(result).values()}

    assert any("llama3.1" in s for s in lic(ollama)), lic(ollama)
    assert any("llama3.1" in s for s in lic(bedrock)), lic(bedrock)


# --------------------------------------------------------------------------- m1


_K8S_TOOL = (
    "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n"
    "        - name: open-webui\n          image: ghcr.io/open-webui/open-webui:main\n          env:\n"
    "            - name: OLLAMA_HOST\n              value: http://10.9.9.9:11434\n"
)


def test_an_unrelated_tools_kubernetes_env_does_not_configure_the_app(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": _OLLAMA_CALL, "deploy/webui.yaml": _K8S_TOOL})
    assert "Ollama server (10.9.9.9:11434)" not in _ollama_services(result)


def test_the_apps_own_kubernetes_container_configures_it(tmp_path) -> None:
    root = tmp_path / "chatbot"
    manifest = _K8S_TOOL.replace("name: open-webui", "name: chatbot").replace(
        "ghcr.io/open-webui/open-webui:main", "registry.example/chatbot:1.0")
    result = scan_repo(_repo(root, {"app.py": _OLLAMA_CALL, "deploy/app.yaml": manifest}), level=4)
    assert _served(result, "llama3.1:8b") == ["Ollama server (10.9.9.9:11434)"]


def test_a_compose_tool_service_is_skipped_and_the_built_app_is_read(tmp_path) -> None:
    compose = (
        "services:\n  app:\n    build: .\n    environment:\n      - OLLAMA_HOST=http://ollama:11434\n"
        "  webui:\n    image: ghcr.io/open-webui/open-webui:main\n    environment:\n      OLLAMA_HOST: http://other:11434\n"
    )
    result = _scan(tmp_path, {"app.py": _OLLAMA_CALL, "docker-compose.yml": compose})
    assert _served(result, "llama3.1:8b") == ["Ollama server (ollama:11434)"]


def test_conflicting_hosts_are_unknown_never_silently_local(tmp_path) -> None:
    manifest = _K8S_TOOL.replace("name: open-webui", "name: app").replace("ghcr.io/open-webui/open-webui:main", "app:1")
    result = _scan(tmp_path, {
        "app.py": _OLLAMA_CALL,
        ".env": "OLLAMA_HOST=http://10.1.1.1:11434\n",
        "deploy/app.yaml": manifest,
    })
    services = _ollama_services(result)
    assert "Ollama (local)" not in services
    unknown = services["Ollama server (endpoint unknown)"]
    assert unknown.properties["service:endpoint_candidates"] == "http://10.1.1.1:11434, http://10.9.9.9:11434"
    assert unknown.properties["service:endpoint_basis"] == "conflicting"


# --------------------------------------------------------------------------- R5-M2


# a repository whose checks reach pass and fail verdicts
_DECIDED = {
    "requirements.txt": "openai==1.50.0\nlangchain==0.2.0\n",
    "app.py": 'from openai import OpenAI\nc = OpenAI()\nc.chat.completions.create(model="gpt-4o", messages=[])\n',
}


def _partial(tmp_path, monkeypatch, files=None):
    from aibom.scan.scanners import net_env_scan

    def boom(self, ctx):
        raise RuntimeError("engine bug")

    monkeypatch.setattr(net_env_scan.NetEnvScanner, "scan", boom)
    return _scan(tmp_path, files or _DECIDED)


def test_a_partial_scan_withholds_the_band_too(tmp_path, monkeypatch) -> None:
    result = _partial(tmp_path, monkeypatch)
    assert result.scores["risk_grade"] == "—"
    assert result.scores["risk_band"] == "withheld"  # never "low"


def test_sarif_says_the_run_did_not_succeed_and_names_the_scanner(tmp_path, monkeypatch) -> None:
    result = _partial(tmp_path, monkeypatch)
    (inv,) = emit_sarif(result)["runs"][0]["invocations"]
    assert inv["executionSuccessful"] is False
    (note,) = inv["toolExecutionNotifications"]
    assert note["level"] == "error" and note["descriptor"]["id"] == "net-env"
    assert "net-env" in note["message"]["text"]


def test_a_complete_scan_stays_successful_in_sarif(tmp_path) -> None:
    result = _scan(tmp_path, {"requirements.txt": "openai==1.50.0\n"})
    (inv,) = emit_sarif(result)["runs"][0]["invocations"]
    assert inv["executionSuccessful"] is True and "toolExecutionNotifications" not in inv


def test_compliance_verdicts_on_a_partial_scan_say_so(tmp_path, monkeypatch) -> None:
    result = _partial(tmp_path, monkeypatch)
    report = run_all(result)
    frameworks = [v for k, v in report.items() if isinstance(v, dict) and "requirements" in v]
    assert frameworks and all(fw["basis"] == "incomplete_scan" for fw in frameworks)
    decided = [r for fw in frameworks for r in fw["requirements"] if r["verdict"] in ("pass", "fail")]
    assert decided and all("based on an incomplete scan: net-env did not finish" in r["evidence"] for r in decided)


def test_compliance_on_a_complete_scan_is_unqualified(tmp_path) -> None:
    report = run_all(_scan(tmp_path, _DECIDED))
    for key, fw in report.items():
        if isinstance(fw, dict) and "requirements" in fw:
            assert "basis" not in fw, key  # a complete scan's report is unchanged
            assert not any("incomplete scan" in r["evidence"] for r in fw["requirements"])


# --------------------------------------------------------------------------- regressions (kept)


@pytest.mark.parametrize("literal", [
    "redis:7", "postgres:15", "python:3.12", "node:20", "nginx:1.25", "busybox:1.36",
    "db:5432", "api:8080", "10:30", "numpy:1.26", "user:42",
])
def test_docker_host_port_and_time_literals_are_never_models(tmp_path, literal) -> None:
    result = _scan(tmp_path, {"client.py": _OLLAMA_CALL, "conf.py": f'X = "{literal}"\nmodel = "{literal}"\n'})
    assert literal not in _models(result)


def test_compose_ports_and_k8s_times_are_never_models(tmp_path) -> None:
    result = _scan(tmp_path, {
        "client.py": _OLLAMA_CALL,
        "docker-compose.yml": "services:\n  web:\n    image: nginx:1.25\n    ports:\n      - 8080:80\n",
        "deploy/cron.yaml": "spec:\n  containers:\n    - name: app\n      env:\n        - name: AT\n          value: '10:30'\n",
    })
    assert set(_models(result)) <= {"llama3.1:8b"}
