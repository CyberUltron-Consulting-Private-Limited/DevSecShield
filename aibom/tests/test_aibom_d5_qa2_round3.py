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
