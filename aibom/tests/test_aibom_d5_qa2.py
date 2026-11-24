"""Staging QA round 2 (lane Q2) on D5, the AI BOM: Q2-05, Q2-06, Q2-07 and G-D5-5.

Each test reproduces a finding on a small repository written to ``tmp_path``. The two
repositories mirror the lines of the public repos the QA lane scanned that caused the
finding: ``tom-doerr/zsh_codex@6ede649`` (one client class per provider, Claude only
through Amazon Bedrock, Llama only through Groq) and ``PurCL/RepoAudit@160f5bc``
(Bedrock model ids with and without a cross-region prefix, the Anthropic and Gemini
SDKs, DeepSeek through the OpenAI SDK). Every credential below is a fake placeholder.
"""

from __future__ import annotations

import pathlib

import pytest

from aibom.compliance import run_all
from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.model.result import REL_SERVED_BY
from aibom.scan.parsers.license_resolver import resolve_license
from aibom.scan.parsers.model_kb import lookup
from aibom.scan.parsers.model_refs import find_model_refs, find_model_refs_ctx
from aibom.scan.pipeline import scan_repo

_ZSH_CODEX = {
    "requirements.txt": "openai\n",
    "services/services.py": '''import os
from abc import ABC, abstractmethod


class BaseClient(ABC):
    @abstractmethod
    def get_completion(self, full_command: str) -> str:
        pass


class OpenAIClient(BaseClient):
    """- model (optional): defaults to "gpt-4o-mini" """
    api_type = "openai"
    default_model = os.getenv("OPENAI_DEFAULT_MODEL", "gpt-4o-mini")

    def __init__(self, config: dict):
        from openai import OpenAI
        self.client = OpenAI(api_key=config["api_key"])

    def get_completion(self, full_command: str) -> str:
        chat = self.client.chat.completions
        return chat.create(model=self.default_model, messages=[])


class GoogleGenAIClient(BaseClient):
    api_type = "gemini"
    default_model = os.getenv("GOOGLE_GENAI_DEFAULT_MODEL", "gemini-1.5-pro-latest")

    def __init__(self, config: dict):
        import google.generativeai as genai
        genai.configure(api_key=config["api_key"])
        self.model = genai.GenerativeModel(self.default_model)


class GroqClient(BaseClient):
    """- api_type="groq"
    - model (optional): defaults to "llama-3.2-11b-text-preview"
    """
    api_type = "groq"
    default_model = os.getenv("GROQ_DEFAULT_MODEL", "llama-3.2-11b-text-preview")

    def __init__(self, config: dict):
        from groq import Groq
        self.client = Groq(api_key=config["api_key"])


class MistralClient(BaseClient):
    api_type = "mistral"
    default_model = os.getenv("MISTRAL_DEFAULT_MODEL", "codestral-latest")

    def __init__(self, config: dict):
        from mistralai import Mistral
        self.client = Mistral(api_key=config["api_key"])


class AmazonBedrock(BaseClient):
    """- model (optional): defaults to "anthropic.claude-3-5-sonnet-20240620-v1:0" """
    api_type = "bedrock"
    default_model = os.getenv(
        "BEDROCK_DEFAULT_MODEL", "anthropic.claude-3-5-sonnet-20240620-v1:0"
    )

    def __init__(self, config: dict):
        import boto3
        self.client = boto3.client("bedrock-runtime")

    def get_completion(self, full_command: str) -> str:
        body = {"anthropic_version": "bedrock-2023-05-31"}
        return self.client.invoke_model(modelId=self.default_model, body=body)
''',
}

_REPO_AUDIT = {
    "requirements.txt": "openai\ngoogle-generativeai\nboto3\nanthropic\nreplicate\n",
    "src/llmtool/LLM_utils.py": """from openai import *
import google.generativeai as genai
import anthropic
import boto3
import os


class LLM:
    def infer_with_gemini(self, message):
        gemini_model = genai.GenerativeModel("gemini-pro")
        return gemini_model.generate_content(message)

    def infer_with_deepseek_model(self, message):
        client = OpenAI(api_key=os.environ["DEEPSEEK_KEY"], base_url="https://api.deepseek.com")
        return client.chat.completions.create(model=self.name, messages=[])

    def infer_with_claude_aws_bedrock(self, message):
        if "3.5" in self.name:
            model_id = "anthropic.claude-3-5-sonnet-20241022-v2:0"
        else:
            model_id = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
        client = boto3.client("bedrock-runtime", region_name="us-west-2")
        return client.invoke_model(modelId=model_id, body="{}")

    def infer_with_claude_key(self, message):
        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_KEY"])
        model_name = "claude-3-7-sonnet-20250219"
        return client.messages.create(model=model_name, max_tokens=10, messages=[])
""",
}


def _write(root: pathlib.Path, files: dict[str, str]) -> pathlib.Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


@pytest.fixture(name="zsh")
def _zsh(tmp_path: pathlib.Path):
    return scan_repo(_write(tmp_path / "zsh_codex", _ZSH_CODEX), level=4)


@pytest.fixture(name="audit")
def _audit(tmp_path: pathlib.Path):
    return scan_repo(_write(tmp_path / "RepoAudit", _REPO_AUDIT), level=4)


def _model(result, name: str):
    found = [c for c in result.components if c.kind == "model" and c.name == name]
    assert found, (
        f"{name!r} not in {[c.name for c in result.components if c.kind == 'model']}"
    )
    return found[0]


def _served_by(result, model) -> list[str]:
    return sorted(c.name for c in result.neighbors(model.bom_ref, REL_SERVED_BY))


def _services(result) -> dict[str, dict[str, str]]:
    return {
        c.name: dict(c.properties or {})
        for c in result.components
        if c.kind in ("service", "cloud_service", "endpoint")
    }


# --------------------------------------------------------------------------- #
# Q2-05: Bedrock model ids are recognised whole
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "model_id", "vendor"),
    [
        (
            '"anthropic.claude-3-5-sonnet-20240620-v1:0"',
            "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "Anthropic",
        ),
        (
            '"us.anthropic.claude-3-7-sonnet-20250219-v1:0"',
            "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
            "Anthropic",
        ),
        (
            '"eu.anthropic.claude-3-5-sonnet-20240620-v1:0"',
            "eu.anthropic.claude-3-5-sonnet-20240620-v1:0",
            "Anthropic",
        ),
        (
            '"apac.anthropic.claude-3-haiku-20240307-v1:0"',
            "apac.anthropic.claude-3-haiku-20240307-v1:0",
            "Anthropic",
        ),
        ('"anthropic.claude-v2:1"', "anthropic.claude-v2:1", "Anthropic"),
        ('"anthropic.claude-instant-v1"', "anthropic.claude-instant-v1", "Anthropic"),
        ('"meta.llama3-70b-instruct-v1:0"', "meta.llama3-70b-instruct-v1:0", "Meta"),
        (
            '"us.meta.llama3-2-11b-instruct-v1:0"',
            "us.meta.llama3-2-11b-instruct-v1:0",
            "Meta",
        ),
        ('"amazon.titan-text-express-v1"', "amazon.titan-text-express-v1", "Amazon"),
        ('"amazon.nova-pro-v1:0"', "amazon.nova-pro-v1:0", "Amazon"),
        (
            '"mistral.mistral-large-2402-v1:0"',
            "mistral.mistral-large-2402-v1:0",
            "Mistral",
        ),
        (
            '"mistral.mixtral-8x7b-instruct-v0:1"',
            "mistral.mixtral-8x7b-instruct-v0:1",
            "Mistral",
        ),
        ('"cohere.command-r-plus-v1:0"', "cohere.command-r-plus-v1:0", "Cohere"),
        ('"cohere.embed-english-v3"', "cohere.embed-english-v3", "Cohere"),
        ('"ai21.jamba-1-5-large-v1:0"', "ai21.jamba-1-5-large-v1:0", "AI21 Labs"),
        # provisioned-throughput suffix
        (
            '"anthropic.claude-3-sonnet-20240229-v1:0:200k"',
            "anthropic.claude-3-sonnet-20240229-v1:0:200k",
            "Anthropic",
        ),
        # an ARN names the id after "foundation-model/"
        (
            '"arn:aws:bedrock:us-east-1::foundation-model/meta.llama3-8b-instruct-v1:0"',
            "meta.llama3-8b-instruct-v1:0",
            "Meta",
        ),
    ],
)
def test_q2_05_a_bedrock_id_is_kept_whole(
    text: str, model_id: str, vendor: str
) -> None:
    refs = find_model_refs(f"model_id = {text}\n")
    assert refs == {model_id: vendor}, (
        refs
    )  # and no truncated sibling ("claude-...-v1")


@pytest.mark.parametrize(
    "text",
    [
        "see https://www.amazon.com/x",
        "open meta.json",
        "https://api.mistral.ai/v1",
        "https://api.cohere.ai/v1",
        "docs.anthropic.com",
        "ai21.com/studio",
    ],
)
def test_q2_05_provider_domains_are_not_bedrock_ids(text: str) -> None:
    assert find_model_refs(text) == {}


def test_q2_05_a_bedrock_id_in_a_getenv_default_is_usage() -> None:
    model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    text = f'm = os.getenv("BEDROCK_DEFAULT_MODEL", "{model_id}")\n'
    assert find_model_refs_ctx(text) == {
        "anthropic.claude-3-5-sonnet-20240620-v1:0": ("Anthropic", "usage")
    }


def test_q2_05_zsh_codex_keeps_the_full_bedrock_id(zsh) -> None:
    names = {c.name for c in zsh.components if c.kind == "model"}
    assert "anthropic.claude-3-5-sonnet-20240620-v1:0" in names
    assert "claude-3-5-sonnet-20240620-v1" not in names
    m = _model(zsh, "anthropic.claude-3-5-sonnet-20240620-v1:0")
    assert m.publisher == "Anthropic"  # the model vendor
    assert m.properties["model:provider"] == "bedrock"  # where it is served
    assert m.properties["model:reference_type"] == "usage"
    assert m.model_card.model_architecture == "Claude (proprietary)"


def test_q2_05_repoaudit_keeps_both_bedrock_ids_with_the_profile(audit) -> None:
    names = {c.name for c in audit.components if c.kind == "model"}
    assert {
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
    } <= names
    assert (
        not {"claude-3-5-sonnet-20241022-v2", "claude-3-7-sonnet-20250219-v1"} & names
    )
    prof = _model(audit, "us.anthropic.claude-3-7-sonnet-20250219-v1:0")
    assert prof.properties["model:provider"] == "bedrock"
    assert prof.properties["model:bedrock_inference_profile"] == "us"
    plain = _model(audit, "anthropic.claude-3-5-sonnet-20241022-v2:0")
    assert "model:bedrock_inference_profile" not in plain.properties


# --------------------------------------------------------------------------- #
# Q2-06: a service per called SDK; every model served by its gateway
# --------------------------------------------------------------------------- #


def test_q2_06_zsh_codex_every_called_sdk_is_a_service(zsh) -> None:
    services = _services(zsh)
    assert {
        "OpenAI API",
        "Google Gemini API",
        "Groq API",
        "Mistral API",
        "Amazon Bedrock Runtime",
    } <= set(services), sorted(services)
    # no vendor "service" for a vendor reached through another gateway
    assert "Anthropic" not in services and "Meta" not in services, sorted(services)
    assert services["Groq API"]["service:endpoint"] == "https://api.groq.com"
    assert services["Groq API"]["discovery:method"] == "sdk-client"
    assert services["Groq API"]["discovery:source"] == "services/services.py"


def test_q2_06_zsh_codex_models_are_served_by_their_gateway(zsh) -> None:
    expect = {
        "anthropic.claude-3-5-sonnet-20240620-v1:0": ["Amazon Bedrock Runtime"],
        "llama-3.2-11b-text-preview": ["Groq API"],
        "codestral-latest": ["Mistral API"],
        "gemini-1.5-pro-latest": ["Google Gemini API"],
        "gpt-4o-mini": ["OpenAI API"],
    }
    for name, services in expect.items():
        assert _served_by(zsh, _model(zsh, name)) == services, name
    llama = _model(zsh, "llama-3.2-11b-text-preview")
    assert llama.publisher == "Meta" and llama.properties["model:provider"] == "groq"


def test_q2_06_repoaudit_links_every_model_to_its_service(audit) -> None:
    services = _services(audit)
    assert {
        "Anthropic API",
        "Google Gemini API",
        "DeepSeek API",
        "Amazon Bedrock Runtime",
    } <= set(services), sorted(services)
    # OpenAI(...) here always points at another base_url: not the OpenAI API
    assert "OpenAI API" not in services
    expect = {
        "anthropic.claude-3-5-sonnet-20241022-v2:0": ["Amazon Bedrock Runtime"],
        "us.anthropic.claude-3-7-sonnet-20250219-v1:0": ["Amazon Bedrock Runtime"],
        "claude-3-7-sonnet-20250219": ["Anthropic API"],
        "gemini-pro": ["Google Gemini API"],
    }
    for name, svc in expect.items():
        assert _served_by(audit, _model(audit, name)) == svc, name


def test_q2_06_an_sdk_imported_but_never_called_is_not_a_service(
    tmp_path: pathlib.Path,
) -> None:
    _write(tmp_path, {"app.py": "import groq\nfrom mistralai import Mistral\nX = 1\n"})
    assert not {"Groq API", "Mistral API"} & set(
        _services(scan_repo(tmp_path, level=4))
    )


def test_q2_06_an_sdk_client_in_test_code_is_not_a_service(
    tmp_path: pathlib.Path,
) -> None:
    _write(
        tmp_path, {"tests/test_x.py": "from groq import Groq\nc = Groq(api_key='x')\n"}
    )
    assert "Groq API" not in _services(scan_repo(tmp_path, level=4))


def test_q2_06_anthropic_bedrock_client_is_bedrock(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "app.py": "from anthropic import AnthropicBedrock\n"
            "c = AnthropicBedrock(aws_region='us-east-1')\n"
            'c.messages.create(model="claude-3-5-sonnet-20241022")\n'
        },
    )
    services = _services(scan_repo(tmp_path, level=4))
    assert "Amazon Bedrock Runtime" in services and "Anthropic API" not in services


def test_q2_06_run_object_types_api_models_as_external(tmp_path: pathlib.Path) -> None:
    root = _write(tmp_path / "r", {**_ZSH_CODEX, "models/w.safetensors": "x" * 64})
    out = scan_to_devsecshield(str(root), level=4)
    rows = {r["component_name"]: r for r in out["results"]}
    claude = rows["anthropic.claude-3-5-sonnet-20240620-v1:0"]
    assert claude["component_type"] == "external_provider"
    assert claude["component_kind"] == "model"  # still a model for the model counts
    assert claude["source"] == "bedrock"
    assert rows["llama-3.2-11b-text-preview"]["source"] == "groq"
    weights = rows["w.safetensors"]
    assert weights["component_type"] == "local_model_file"
    assert weights["component_kind"] == "model_file"
    nodes = {n["label"]: n for n in out["ai_bom_graph"]["nodes"]}
    assert nodes["gpt-4o-mini"]["type"] == "external_provider"
    assert nodes["w.safetensors"]["type"] == "local_model_file"


def test_q2_06_freeai_19_1_and_gv_2_assess_the_external_models(audit) -> None:
    run_all(audit)
    for fw, rid in (("rbi_free_ai", "FREEAI-19-1"), ("nist_rmf", "GV-2")):
        req = next(q for q in audit.compliance[fw]["requirements"] if q["id"] == rid)
        assert req["verdict"] == "not_bom_evidenceable", (rid, req)
        assert "Not applicable" not in req["evidence"]
        assert set(req["refs"]) == {
            "modelref-gemini-pro",
            "modelref-claude-3-7-sonnet-20250219",
            "modelref-anthropic-claude-3-5-sonnet-20241022-v2-0",
            "modelref-us-anthropic-claude-3-7-sonnet-20250219-v1-0",
        }, req["refs"]


# --------------------------------------------------------------------------- #
# Q2-07: licences
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("pkg", ["boto3", "botocore", "groq", "replicate"])
def test_q2_07_sdk_licences_are_apache(pkg: str) -> None:
    assert resolve_license(pkg) == "Apache-2.0"


def test_q2_07_codestral_is_mnpl_not_apache() -> None:
    # Q2-07, refined by review 6037909737 of #498 (M6): MNPL / MRL are the licences
    # of the OPEN WEIGHTS; an API name carries no weights licence (the API is used
    # under the provider's terms, see test_q2_07_zsh_codex_codestral_licence)
    assert lookup("Codestral-22B-v0.1")["license"] == (
        "LicenseRef-Mistral-AI-Non-Production-License"
    )
    assert lookup("Mistral-Large-Instruct-2407")["license"] == (
        "LicenseRef-Mistral-Research-License"
    )
    for api_name in ("codestral-latest", "mistral-large-2407", "mistral-small-latest"):
        assert "license" not in lookup(api_name), api_name
    assert lookup("Mixtral-8x7B-v0.1")["license"] == "Apache-2.0"
    assert lookup("codestral-mamba-latest")["license"] == "Apache-2.0"


def test_q2_07_zsh_codex_codestral_licence(zsh) -> None:
    # codestral-latest through the Mistral API: provider terms, never Apache-2.0
    # and never the open-weights Non-Production licence
    lic = _model(zsh, "codestral-latest").licenses
    assert lic in (
        [{"license": {"name": "LicenseRef-proprietary"}}],
        [{"license": {"id": "LicenseRef-proprietary"}}],
    ), lic


def test_q2_07_an_unresolved_licence_is_unknown_not_no_licence(
    tmp_path: pathlib.Path,
) -> None:
    _write(tmp_path, {"requirements.txt": "openai\ninternal-llm-sdk==0.1.0\n"})
    out = scan_to_devsecshield(str(tmp_path), level=4)
    assert "FRAMEWORK_NO_LICENSE" not in out["ai_bom_scores"]["by_flag"]
    row = next(r for r in out["results"] if r["component_name"] == "internal-llm-sdk")
    assert row["license"] == "NOASSERTION"
    assert row["license_status"] == "unknown"
    assert "unknown / partial" in row["description"]
    assert "No concluded license" not in row["description"]
    # the score is not driven by an unresolved licence
    assert row["impact"] == "Low"
    assert out["ai_bom_scores"]["severity_counts"]["medium"] == 0


def test_q2_07_scores_are_not_driven_by_licences(zsh, audit) -> None:
    for result in (zsh, audit):
        assert "FRAMEWORK_NO_LICENSE" not in result.scores["by_flag"]
        assert not [f for f in result.flags if f.code == "FRAMEWORK_NO_LICENSE"]


# --------------------------------------------------------------------------- #
# G-D5-5: model-card considerations from known facts only
# --------------------------------------------------------------------------- #


def test_g_d5_5_considerations_state_known_facts(zsh, audit) -> None:
    claude = _model(zsh, "anthropic.claude-3-5-sonnet-20240620-v1:0").model_card
    cons = claude.considerations
    assert cons is not None
    assert cons.use_cases == [
        "chat/completion through Amazon Bedrock Runtime, "
        "called from services/services.py"
    ]
    assert any("provider-hosted" in t for t in cons.technical_limitations)
    codestral = _model(zsh, "codestral-latest").model_card.considerations
    assert any(
        "codestral-latest" in t and "alias" in t
        for t in codestral.technical_limitations
    )
    assert not codestral.out_of_scope  # API-served: no open-weights exclusion
    prof = _model(audit, "us.anthropic.claude-3-7-sonnet-20250219-v1:0").model_card
    assert any(
        "cross-Region inference profile" in t
        for t in prof.considerations.technical_limitations
    )
    # nothing is invented: no fairness or ethics claims without a source
    assert not cons.fairness_assessments and not cons.ethical_considerations


def test_g_d5_5_cyclonedx_carries_the_considerations(tmp_path: pathlib.Path) -> None:
    out = scan_to_devsecshield(str(_write(tmp_path, _ZSH_CODEX)), level=4)
    comps = {c["name"]: c for c in out["ai_bom_json"]["components"]}
    cons = comps["codestral-latest"]["modelCard"]["considerations"]
    assert cons["useCases"] == [
        "code completion and generation (fill-in-the-middle) through Mistral API, "
        "called from services/services.py"
    ]
    assert not any(t.startswith("Out of scope:") for t in cons["technicalLimitations"])
    assert "environmentalConsiderations" not in cons  # not known: omitted


def test_g_d5_5_a_mention_gets_no_considerations(tmp_path: pathlib.Path) -> None:
    _write(tmp_path, {"README.md": "Supported: gpt-4o, claude-3-opus\n"})
    result = scan_repo(tmp_path, level=4)
    for c in result.components:
        if c.kind == "model":
            assert c.model_card.considerations is None, c.name


# --------------------------------------------------------------------------- #
# Design note (coordinator, QA round 2 live): an inventory with no finding above
# Low is "A / Low risk", not "29 / B Moderate risk"
# --------------------------------------------------------------------------- #


def test_low_only_posture_is_grade_a() -> None:
    from aibom.score.posture import posture_risk

    assert posture_risk(0, 0, 0, 7) == (14, "A", "Low risk")
    assert posture_risk(0, 0, 0, 500) == (14, "A", "Low risk")
    assert posture_risk(0, 0, 0, 2) == (8, "A", "Low risk")
    assert posture_risk(0, 0, 3, 0)[1] == "B"  # mediums still read above Low


def test_a_repo_with_no_flags_reads_low_risk(zsh) -> None:
    scores = zsh.scores
    assert scores["flag_count"] == 0
    assert (scores["risk_grade"], scores["risk_label"]) == ("A", "Low risk")
    assert scores["risk_normalized"] <= 14
