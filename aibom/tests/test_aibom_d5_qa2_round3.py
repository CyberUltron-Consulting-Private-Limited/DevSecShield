# ruff: noqa: E501 - fixture sources are kept verbatim (long lines)
"""#498 round 3 (D5 AI BOM): what the engine got wrong on two public AI repositories
and the industry conventions (OWASP AIBOM / CycloneDX purl / Hugging Face ids).

* alejandro-ao/ask-multiple-pdfs @ dc0155b: a commented-out
  ``HuggingFaceInstructEmbeddings(model_name="hkunlp/instructor-xl")`` was a model in
  use, served by an endpoint-less "HKUNLP" service; ``ChatOpenAI()`` /
  ``OpenAIEmbeddings()`` (LangChain) gave no OpenAI API service; faiss-cpu's licence
  was unknown.
* Vaibhavs10/insanely-fast-whisper @ 0fed9a4: ``openai/whisper-large-v3`` and
  ``pyannote/speaker-diarization-3.1`` (argparse defaults fed to ``pipeline`` /
  ``Pipeline.from_pretrained``) gave a BOM with no model at all.
* Mistral open weights behind a self-hosted gateway read LicenseRef-proprietary.
* An ``import`` line above a reference was read as its gateway.

Every credential below is a fake placeholder.
"""

from __future__ import annotations

import pathlib

from aibom.model.result import REL_DEPENDS_ON, REL_SERVED_BY
from aibom.scan.parsers.model_refs import find_hf_repo_ids, find_model_refs_ctx
from aibom.scan.pipeline import scan_repo


def _scan(tmp_path: pathlib.Path, files: dict[str, str]):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return scan_repo(tmp_path, level=4)  # the worker's level


def _models(result) -> dict:
    return {c.name: c for c in result.components if c.kind == "model"}


def _served(result, name: str) -> list[str]:
    model = _models(result)[name]
    by_ref = {c.bom_ref: c for c in result.components}
    return [by_ref[e.dst].name for e in result.edges if e.src == model.bom_ref and e.rel == REL_SERVED_BY]


def _licence(comp) -> str | None:
    if not comp.licenses:
        return None
    lic = comp.licenses[0]["license"]
    return lic.get("id") or lic.get("name")


_ASK_PDFS = '''from langchain.embeddings import OpenAIEmbeddings, HuggingFaceInstructEmbeddings
from langchain.chat_models import ChatOpenAI
from langchain.llms import HuggingFaceHub

def get_vectorstore(text_chunks):
    embeddings = OpenAIEmbeddings()
    # embeddings = HuggingFaceInstructEmbeddings(model_name="hkunlp/instructor-xl")
    return embeddings

def get_conversation_chain(vectorstore):
    llm = ChatOpenAI()
    # llm = HuggingFaceHub(repo_id="google/flan-t5-xxl", model_kwargs={"temperature":0.5})
    return llm
'''

_WHISPER = '''import argparse
from transformers import pipeline
from pyannote.audio import Pipeline

parser = argparse.ArgumentParser()
parser.add_argument(
    "--model-name",
    required=False,
    default="openai/whisper-large-v3",
    type=str,
)
parser.add_argument(
    "--diarization_model",
    default="pyannote/speaker-diarization-3.1",
)
args = parser.parse_args()
pipe = pipeline("automatic-speech-recognition", model=args.model_name)
diarizer = Pipeline.from_pretrained(args.diarization_model)
'''


# ------------------------------------------------------------- comments are not usage


def test_a_commented_out_model_is_a_mention_not_a_model_in_use() -> None:
    refs = find_model_refs_ctx(_ASK_PDFS + 'x = 1  # or model="gpt-4-turbo"\n', "py")
    assert refs["hkunlp/instructor-xl"] == ("HKUNLP", "catalog")
    assert refs["gpt-4-turbo"] == ("OpenAI", "catalog")
    # the same text read as prose (no language) keeps the old line rules
    assert find_model_refs_ctx('model="gpt-4o"\n')["gpt-4o"][1] == "usage"


def test_ask_multiple_pdfs_has_no_commented_model_and_an_openai_service(tmp_path) -> None:
    result = _scan(tmp_path, {
        "app.py": _ASK_PDFS,
        "requirements.txt": "langchain==0.0.184\nopenai==0.27.6\nfaiss-cpu==1.7.4\ntiktoken==0.4.0\n",
    })
    models = _models(result)
    assert models["hkunlp/instructor-xl"].properties["model:reference_type"] == "catalog"
    assert not [c for c in result.components if c.name == "HKUNLP"]  # no invented service
    services = {c.name: c for c in result.components if c.kind == "cloud_service"}
    assert services["OpenAI API"].properties["service:endpoint_basis"] == "sdk-default"
    assert result.properties["aibom:licence_coverage"] == "4/4"  # faiss-cpu is MIT
    assert "google/flan-t5-xxl" not in models  # commented out


# ------------------------------------------------------------------ LangChain clients


def test_langchain_clients_are_their_vendor_apis(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "from langchain_openai import ChatOpenAI, OpenAIEmbeddings\n"
        "from langchain_anthropic import ChatAnthropic\n"
        'llm = ChatOpenAI(model="gpt-4o-mini")\n'
        'emb = OpenAIEmbeddings(model="text-embedding-3-small")\n'
        'claude = ChatAnthropic(model="claude-3-5-sonnet-20241022")\n'
    )})
    assert _served(result, "gpt-4o-mini") == ["OpenAI API"]
    assert _served(result, "text-embedding-3-small") == ["OpenAI API"]
    assert _served(result, "claude-3-5-sonnet-20241022") == ["Anthropic API"]


def test_langchain_js_client_is_the_openai_api(tmp_path) -> None:
    result = _scan(tmp_path, {"app/route.ts": (
        'import { ChatOpenAI } from "@langchain/openai";\n'
        '// const old = new ChatOpenAI({ configuration: { baseURL: "http://x" } });\n'
        'export const llm = new ChatOpenAI({ model: "gpt-4o-mini", temperature: 0 });\n'
    )})
    assert _served(result, "gpt-4o-mini") == ["OpenAI API"]


def test_langchain_proxy_azure_and_bedrock_in_one_file(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "from langchain_openai import ChatOpenAI, AzureChatOpenAI\n"
        "from langchain_aws import ChatBedrock\n"
        'proxy = ChatOpenAI(model="gpt-4o", openai_api_base="http://litellm.internal:4000")\n'
        'az = AzureChatOpenAI(azure_endpoint="https://bank-ai.openai.azure.com/", model="gpt-4o-mini")\n'
        'br = ChatBedrock(model_id="anthropic.claude-3-haiku-20240307-v1:0", region_name="ap-south-1")\n'
    )})
    names = {c.name for c in result.components if c.kind == "cloud_service"}
    assert "OpenAI API" not in names  # every OpenAI client here points elsewhere
    # the import of ChatBedrock above is no Bedrock hint for gpt-4o
    assert _served(result, "gpt-4o") == ["AI gateway (litellm.internal:4000)"]
    assert _served(result, "gpt-4o-mini") == ["Azure OpenAI"]
    assert _served(result, "anthropic.claude-3-haiku-20240307-v1:0") == ["Amazon Bedrock Runtime"]


# ------------------------------------------------------------------ Hugging Face Hub ids


def test_hub_ids_are_found_only_where_the_code_loads_them() -> None:
    assert find_hf_repo_ids(_WHISPER, "py") == {
        "openai/whisper-large-v3": "OpenAI",
        "pyannote/speaker-diarization-3.1": "pyannote",
    }
    for text in (
        'r = litellm.completion(model="openai/gpt-4o")\n',  # a provider route
        'm = AutoModel.from_pretrained("./models/x")\n',
        'm = AutoModel.from_pretrained("checkpoints/ft-run")\n',  # a local dir
        '# m = AutoModel.from_pretrained("org/name")\n',
        's = "AutoModel.from_pretrained(\'org/name\')"\n',
    ):
        assert find_hf_repo_ids(text, "py") == {}, text


def test_insanely_fast_whisper_inventories_its_hub_models(tmp_path) -> None:
    result = _scan(tmp_path, {
        "src/insanely_fast_whisper/cli.py": _WHISPER,
        "pyproject.toml": '[project]\nname = "x"\ndependencies = ["transformers", "pyannote-audio>=3.1.0"]\n',
    })
    models = _models(result)
    whisper = models["openai/whisper-large-v3"]
    assert whisper.properties["model:reference_type"] == "usage"
    assert whisper.purl == "pkg:huggingface/openai/whisper-large-v3"
    assert _licence(whisper) == "Apache-2.0"  # the Hub card, never OpenAI's API terms
    assert whisper.model_card.task == "automatic-speech-recognition"
    diar = models["pyannote/speaker-diarization-3.1"]
    assert diar.publisher == "pyannote" and _licence(diar) is None
    assert any(f.code == "MODEL_LICENSE_UNKNOWN" and f.target == diar.bom_ref for f in result.flags)
    # run locally: no service, never "served by OpenAI"
    assert _served(result, "openai/whisper-large-v3") == []
    deps = {e.dst for e in result.edges if e.src == whisper.bom_ref and e.rel == REL_DEPENDS_ON}
    assert deps == {"lib-transformers"}


def test_a_hub_model_is_not_served_by_its_makers_api(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "from openai import OpenAI\nfrom transformers import pipeline\n"
        "client = OpenAI()\n"
        'asr = pipeline("automatic-speech-recognition", model="openai/whisper-large-v3")\n'
        'r = client.chat.completions.create(model="gpt-4o", messages=[])\n'
    )})
    assert _served(result, "gpt-4o") == ["OpenAI API"]
    assert _served(result, "openai/whisper-large-v3") == []


def test_a_known_family_keeps_its_name_and_gains_the_hub_purl(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "from transformers import AutoModelForCausalLM\n"
        'm = AutoModelForCausalLM.from_pretrained("mistralai/Mistral-7B-Instruct-v0.2")\n'
    )})
    model = _models(result)["Mistral-7B-Instruct-v0.2"]
    assert model.purl == "pkg:huggingface/mistralai/Mistral-7B-Instruct-v0.2"
    assert _licence(model) == "Apache-2.0"
    assert _served(result, "Mistral-7B-Instruct-v0.2") == []


def test_the_whisper_api_model_keeps_openai_terms() -> None:
    from aibom.scan.parsers.model_kb import lookup

    assert lookup("whisper-1") is None  # the API model: vendor terms apply
    assert lookup("openai/whisper-large-v3")["license"] == "Apache-2.0"


# ------------------------------------------------------------ Mistral behind a gateway


def test_open_weights_behind_a_self_hosted_gateway_keep_their_licence(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "from openai import OpenAI\n"
        'client = OpenAI(base_url="http://vllm.internal:8000/v1", api_key="none")\n'
        'r = client.chat.completions.create(model="mistral-7b-instruct", messages=[])\n'
    )})
    model = _models(result)["mistral-7b-instruct"]
    assert _served(result, "mistral-7b-instruct") == ["AI gateway (vllm.internal:8000)"]
    assert _licence(model) == "Apache-2.0"


def test_a_mistral_api_model_still_reads_provider_terms(tmp_path) -> None:
    result = _scan(tmp_path, {
        "requirements.txt": "mistralai==1.2.0\n",
        "app.py": "from mistralai import Mistral\nclient = Mistral(api_key='x')\n"
        'r = client.chat.complete(model="codestral-latest", messages=[])\n',
    })
    assert _licence(_models(result)["codestral-latest"]) == "LicenseRef-proprietary"


# ------------------------------------------------------------- the formats agree


def test_spdx_and_the_rows_carry_the_hub_identity_and_unknown_licence(tmp_path) -> None:
    import json

    from aibom.integrations.devsecshield import scan_to_devsecshield

    root = tmp_path / "repo"
    root.mkdir()
    (root / "cli.py").write_text(_WHISPER)
    (root / "requirements.txt").write_text("transformers==4.44.0\n")
    run = scan_to_devsecshield(root, level=4)
    spdx = run["ai_bom_spdx"]
    spdx = json.loads(spdx) if isinstance(spdx, str) else spdx
    purls = {e["name"]: e.get("software_packageUrl") for e in spdx["@graph"] if e.get("type") == "ai_AIPackage"}
    assert purls["openai/whisper-large-v3"] == "pkg:huggingface/openai/whisper-large-v3"
    cdx = {c["name"]: c.get("purl") for c in run["ai_bom_json"]["components"]}
    assert cdx["openai/whisper-large-v3"] == purls["openai/whisper-large-v3"]
    rows = {r["component_name"]: r for r in run["results"]}
    # a referenced model with no known licence is unknown, not "not declared"
    assert rows["pyannote/speaker-diarization-3.1"]["license"] == "NOASSERTION"
    assert rows["pyannote/speaker-diarization-3.1"]["license_status"] == "unknown"
    assert rows["openai/whisper-large-v3"]["license"] == "Apache-2.0"


# ===================================================== round 3 follow-up (coordinator)

_OLLAMA_APP = '''import ollama

def chat(q):
    return ollama.chat(model="llama3.1:8b", messages=[{"role": "user", "content": q}])

def code(q):
    return ollama.generate(model="gemma2:9b", prompt=q)
'''


def _rows(tmp_path, files: dict[str, str]) -> dict:
    from aibom.integrations.devsecshield import scan_to_devsecshield

    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return {r["component_name"]: r for r in scan_to_devsecshield(tmp_path, level=4)["results"]}


def test_ollama_sdk_with_no_host_is_the_local_server(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": _OLLAMA_APP, "requirements.txt": "ollama==0.4.4\n"})
    (server,) = [c for c in result.components if c.name == "Ollama (local)"]
    assert server.properties["service:endpoint"] == "http://127.0.0.1:11434"
    assert server.properties["service:trust_zone"] == "local"
    # open weights run on the local server, never on an endpoint-less "Meta" / "Google" vendor node
    assert _served(result, "llama3.1:8b") == ["Ollama (local)"]
    assert _served(result, "gemma2:9b") == ["Ollama (local)"]
    assert not [c for c in result.components if c.name in ("Meta", "Google")]


def test_ollama_rows_are_local_serving_with_open_weights_licences(tmp_path) -> None:
    rows = _rows(tmp_path, {"app.py": _OLLAMA_APP, "requirements.txt": "ollama==0.4.4\n"})
    server = rows["Ollama (local)"]
    assert server["component_type"] == "local_model_server"
    # two different model licences behind it: not asserted as one, never proprietary
    assert server["license"] == "NOASSERTION"
    # an Ollama tag is the model's id; run by the server, no file (round 4, m6)
    assert rows["llama3.1:8b"]["component_type"] == "self_hosted_model"
    assert rows["llama3.1:8b"]["license"] == "LicenseRef-llama-community"
    assert rows["gemma2:9b"]["license"] == "LicenseRef-Gemma-Terms-of-Use"
    assert rows["ollama"]["license"] == "MIT"  # the client library (PyPI)


def test_an_ollama_server_with_one_model_carries_that_licence(tmp_path) -> None:
    rows = _rows(tmp_path, {"app.py": (
        'URL = "http://localhost:11434/api/generate"\n'
        'def ask(q, http):\n    return http.post(URL, json={"model": "mistral:7b", "prompt": q})\n'
    )})
    assert rows["Ollama (local)"]["component_type"] == "local_model_server"
    assert rows["Ollama (local)"]["license"] == "Apache-2.0"
    assert rows["mistral:7b"]["license"] == "Apache-2.0"


def test_a_hosted_model_is_never_served_by_ollama(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import ollama\nfrom openai import OpenAI\nclient = OpenAI()\n"
        'local = ollama.chat(model="llama3.1:8b", messages=[])\n'
        'r = client.chat.completions.create(model="gpt-4o", messages=[])\n'
    )})
    assert _served(result, "gpt-4o") == ["OpenAI API"]
    assert _served(result, "llama3.1:8b") == ["Ollama (local)"]


def test_an_ollama_client_given_a_variable_host_claims_no_default(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "import os, ollama\nc = ollama.Client(host=os.environ['OLLAMA_HOST'])\n"
        'r = c.chat(model="llama3.1:8b", messages=[])\n'
    )})
    assert not [c for c in result.components if c.name == "Ollama (local)"]


def test_speech_libraries_are_ai_libraries_with_licences(tmp_path) -> None:
    from aibom.scan.parsers.ai_libraries import classify
    from aibom.scan.parsers.license_resolver import resolve_license

    expected = {
        "pyannote.audio": "MIT", "openai-whisper": "MIT", "faster-whisper": "MIT",
        "ctranslate2": "MIT", "vllm": "Apache-2.0", "llama-cpp-python": "MIT",
        "ollama": "MIT", "sentence-transformers": "Apache-2.0",
        "diffusers": "Apache-2.0", "peft": "Apache-2.0", "accelerate": "Apache-2.0",
        "bitsandbytes": "MIT", "onnxruntime": "MIT", "tensorrt": "LicenseRef-proprietary",
        "ultralytics": "AGPL-3.0-or-later", "timm": "Apache-2.0", "spacy": "MIT",
        "gensim": "LGPL-2.1-only",
    }
    for package, spdx in expected.items():
        assert classify(package) == "ai", package
        assert resolve_license(package) == spdx, package
    result = _scan(tmp_path, {
        "cli.py": _WHISPER,
        "requirements.txt": "transformers==4.44.0\npyannote.audio==3.1.1\nfaster-whisper==1.0.3\n",
    })
    libs = {c.name: c for c in result.components if c.kind == "framework"}
    assert _licence(libs["pyannote.audio"]) == "MIT"
    assert _licence(libs["faster-whisper"]) == "MIT"
    # the diarization pipeline is loaded by pyannote.audio, Whisper by transformers
    diar = _models(result)["pyannote/speaker-diarization-3.1"]
    by_ref = {c.bom_ref: c.name for c in result.components}
    deps = {by_ref[e.dst] for e in result.edges if e.src == diar.bom_ref and e.rel == REL_DEPENDS_ON}
    assert deps == {"pyannote.audio"}


def test_hub_ids_in_notebook_code_cells_are_read(tmp_path) -> None:
    import json

    nb = {
        "cells": [
            {"cell_type": "markdown", "source": ["Uses `AutoModel.from_pretrained(\"md/only\")` in prose."]},
            {"cell_type": "code", "source": [
                "from transformers import pipeline\n",
                "pipe = pipeline(\"automatic-speech-recognition\", model=\"openai/whisper-large-v3\")\n",
                "# old = pipeline(model=\"distil-whisper/distil-large-v2\")\n",
            ]},
        ],
        "metadata": {}, "nbformat": 4, "nbformat_minor": 5,
    }
    result = _scan(tmp_path, {"transcribe.ipynb": json.dumps(nb, indent=1)})
    models = _models(result)
    assert models["openai/whisper-large-v3"].properties["model:reference_type"] == "usage"
    assert models["openai/whisper-large-v3"].purl == "pkg:huggingface/openai/whisper-large-v3"
    assert "distil-whisper/distil-large-v2" not in models  # commented out in the cell
    assert "md/only" not in models  # a markdown cell is not code


def test_langchain_calls_with_no_model_are_unidentified_models_with_evidence(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": _ASK_PDFS, "requirements.txt": "langchain==0.0.184\nopenai==0.27.6\n"})
    assert result.properties["aibom:model_unnamed_calls"] == "2"
    assert result.properties["aibom:model_unnamed_detail"] == "OpenAIEmbeddings() in app.py; ChatOpenAI() in app.py"
    assert result.properties["aibom:model_unnamed_library"] == "langchain 0.0.184"
    unknown = {
        c.name: c for c in result.components
        if c.kind == "model" and c.properties.get("model:identified") == "false"
    }
    assert set(unknown) == {"unidentified model (ChatOpenAI)", "unidentified model (OpenAIEmbeddings)"}
    chat = unknown["unidentified model (ChatOpenAI)"]
    assert chat.properties["model:reference_type"] == "usage"  # counted: the app uses a model
    assert chat.properties["discovery:confidence"] == "low"
    assert chat.properties["model:default_from_library"] == "langchain 0.0.184"
    assert chat.model_card.task == "chat/completion"
    assert unknown["unidentified model (OpenAIEmbeddings)"].model_card.task == "text-embedding"
    assert _served(result, "unidentified model (ChatOpenAI)") == ["OpenAI API"]


def test_the_cyclonedx_entry_carries_low_confidence_identity_evidence(tmp_path) -> None:
    from aibom.emit.cyclonedx import emit_and_validate

    result = _scan(tmp_path, {"app.py": _ASK_PDFS, "requirements.txt": "langchain==0.0.184\nopenai==0.27.6\n"})
    bom = emit_and_validate(result)  # schema-valid CycloneDX 1.6
    (chat,) = [c for c in bom["components"] if c["name"] == "unidentified model (ChatOpenAI)"]
    assert chat["type"] == "machine-learning-model"
    (identity,) = chat["evidence"]["identity"]
    assert identity["field"] == "name" and identity["confidence"] == 0.1
    assert identity["methods"][0]["technique"] == "source-code-analysis"
    assert identity["methods"][0]["value"] == (
        "ChatOpenAI() in app.py: library default model applies (langchain 0.0.184)")
    assert chat["evidence"]["occurrences"] == [{"location": "app.py"}]


def test_checks_read_unidentified_model_use_as_needs_information(tmp_path) -> None:
    from aibom.compliance import run_all

    result = _scan(tmp_path, {"app.py": _ASK_PDFS, "requirements.txt": "langchain==0.0.184\nopenai==0.27.6\n"})
    run_all(result)
    for fw in ("cert_in_aibom", "sebi_cscrf_aibom", "rbi_free_ai", "eu_ai_act_annexIV", "nist_rmf"):
        report = result.compliance[fw]
        assert report["out_of_scope"] == 0, fw  # never "no AI models detected"
        assert report["pass"] == 0 and report["fail"] == 0, fw  # nothing vouched for an unknown model
    name = {q["id"]: q for q in result.compliance["cert_in_aibom"]["requirements"]}["T10-Model-Name"]
    assert name["verdict"] == "not_bom_evidenceable" and name["attestable"]
    assert name["evidence"].startswith(
        "AI model use detected; model not identified (library default applies): ChatOpenAI() in app.py")


def test_a_real_failure_on_a_named_model_stays_a_failure(tmp_path) -> None:
    from aibom.compliance import run_all

    result = _scan(tmp_path, {"app.py": (
        "from langchain_openai import ChatOpenAI\n"
        "default = ChatOpenAI()\n"
        'named = ChatOpenAI(model="gpt-4o-mini")\n'
    )})
    run_all(result)
    version = {q["id"]: q for q in result.compliance["cert_in_aibom"]["requirements"]}["T10-Model-Version"]
    # gpt-4o-mini has no version either: a real gap on a named model is still a FAIL
    assert version["verdict"] == "fail"


def test_a_langchain_call_that_names_its_model_is_not_unnamed(tmp_path) -> None:
    result = _scan(tmp_path, {"app.py": (
        "from langchain_openai import ChatOpenAI\nfrom openai import OpenAI\n"
        'llm = ChatOpenAI(model="gpt-4o-mini")\nraw = OpenAI()\ncfg = ChatOpenAI(**KW)\n'
    )})
    assert "aibom:model_unnamed_calls" not in result.properties
