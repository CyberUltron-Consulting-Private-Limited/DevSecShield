# ruff: noqa: E501 - the reviewer's fixture sources are kept verbatim (long lines)
"""Review 6037909737 of #498 (D5 AI BOM): the engine-side majors M1, M2, M6, M7 and the
minors m1-m5. The repositories are the reviewer's fixtures (``qa/498/fixtures``),
written to ``tmp_path``. Every credential below is a fake placeholder.
"""

from __future__ import annotations

import pathlib

import pytest

from aibom.compliance import run_all
from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.model.result import REL_SERVED_BY
from aibom.scan.parsers.code_text import call_arguments, mask
from aibom.scan.parsers.model_kb import lookup
from aibom.scan.parsers.model_refs import find_model_refs
from aibom.scan.pipeline import scan_repo
from aibom.score.posture import posture_risk

_F3_PROXY = """import os
from openai import OpenAI
from anthropic import Anthropic

# LiteLLM proxy in front of every vendor
client = OpenAI(base_url="http://litellm.internal:4000", api_key=os.getenv("LITELLM_KEY"))
claude = Anthropic(base_url=os.environ["LITELLM_URL"])

def ask(q):
    return client.chat.completions.create(model="gpt-4o", messages=[])

def ask2(q):
    return claude.messages.create(model="claude-3-5-sonnet-20241022", max_tokens=10,
                                  messages=[])
"""
_F3B_NESTED = """import os
from openai import OpenAI
client = OpenAI(api_key=os.getenv("K"), base_url=str(os.getenv("PROXY_URL", "http://litellm:4000")))
def ask(q):
    return client.chat.completions.create(model="gpt-4o", messages=[])
"""
_F3C_LITELLM = """import litellm
def ask(q):
    return litellm.completion(model="gpt-4o", api_base="http://litellm.internal:4000",
                              messages=[])
"""
_F3D_KWARGS = """import os
from openai import OpenAI
CFG = {"base_url": "http://litellm.internal:4000", "api_key": os.getenv("K")}
client = OpenAI(**CFG)
def ask(q):
    return client.chat.completions.create(model="gpt-4o", messages=[])
"""
_F3E_COMMENT = """from openai import OpenAI  # noqa: F401  kept for type hints
# client = OpenAI()   # old direct call, now goes through the gateway
def ask(q):
    return None
"""
_F4_AZURE = """import os
from openai import AzureOpenAI
client = AzureOpenAI(azure_endpoint="https://contoso-ai.openai.azure.com/", api_version="2024-06-01", api_key=os.getenv("AZURE_OPENAI_KEY"))
def ask(q):
    return client.chat.completions.create(model="gpt-4o", messages=[])
"""
_F4B_AZURE_ENV = """import os
from openai import AzureOpenAI, AsyncAzureOpenAI
client = AzureOpenAI(azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"], api_version="2024-06-01")
aclient = AsyncAzureOpenAI(azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"], api_version="2024-06-01")
def ask(q):
    return client.chat.completions.create(model="gpt-4o-mini", messages=[])
"""
_F4C_OPENAI = """from openai import OpenAI
client = OpenAI()
def ask(q):
    return client.chat.completions.create(model="gpt-4o", messages=[])
"""
_F5_BOTO3 = """import boto3, json
br = boto3.client("bedrock-runtime", region_name="eu-central-1")
def ask(q):
    return br.invoke_model(modelId="eu.anthropic.claude-3-7-sonnet-20250219-v1:0", body=json.dumps({}))
"""
_F5B_ANTHROPIC_BEDROCK = """from anthropic import AnthropicBedrock
client = AnthropicBedrock(aws_region="us-west-2")
def ask(q):
    return client.messages.create(model="anthropic.claude-3-5-sonnet-20241022-v2:0", max_tokens=10, messages=[])
"""
_F5C_CTRL = """import boto3
ctrl = boto3.client("bedrock")
def models():
    return ctrl.list_foundation_models()
"""
_F5D_ANTHROPIC = """from anthropic import Anthropic
client = Anthropic()
def ask(q):
    return client.messages.create(model="claude-3-5-sonnet-20241022", max_tokens=10, messages=[])
"""


def _repo(tmp_path: pathlib.Path, files: dict[str, str]) -> pathlib.Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def _scan(tmp_path: pathlib.Path, files: dict[str, str]):
    return scan_repo(_repo(tmp_path, files), level=4)


def _services(result) -> dict[str, dict[str, str]]:
    return {
        c.name: dict(c.properties or {})
        for c in result.components
        if c.kind in ("cloud_service", "endpoint")
    }


def _served(result, name: str) -> list[str]:
    model = next(c for c in result.components if c.kind == "model" and c.name == name)
    return sorted(c.name for c in result.neighbors(model.bom_ref, REL_SERVED_BY))


def _model(result, name: str):
    return next(c for c in result.components if c.kind == "model" and c.name == name)


# --------------------------------------------------------------------------- M1


def test_mask_blanks_comments_and_string_contents_keeping_offsets() -> None:
    text = 'x = OpenAI()  # client = OpenAI()\ny = "OpenAI(" \n'
    code, bare = mask(text, "py")
    assert len(code) == len(bare) == len(text)
    assert code.count("OpenAI(") == 2 and bare.count("OpenAI(") == 1
    js_code, _ = mask("import OpenAI from 'openai' // new OpenAI()\n", "js")
    assert "'openai'" in js_code and "new OpenAI" not in js_code


def test_call_arguments_read_to_the_balanced_parenthesis() -> None:
    _code, bare = mask(_F3B_NESTED, "py")
    start = bare.index("OpenAI(") + len("OpenAI")
    args = call_arguments(bare, start)
    assert (
        args is not None and "base_url" in args and args.count("(") == args.count(")")
    )


@pytest.mark.parametrize(
    "source",
    [_F3B_NESTED, _F3D_KWARGS, _F3E_COMMENT],
    ids=["nested", "kwargs", "comment"],
)
def test_no_default_openai_endpoint_is_claimed(tmp_path, source) -> None:
    result = _scan(tmp_path, {"app/main.py": source})
    assert "OpenAI API" not in _services(result), _services(result)


def test_the_already_correct_cases_stay_correct(tmp_path) -> None:
    cases = {
        "f1": (
            {
                "app/main.py": "from openai import OpenAI\nimport anthropic\n"
                "def f(c: OpenAI): return c\n"
            },
            set(),
        ),
        "f2": (
            {
                "tests/test_llm.py": _F4C_OPENAI,
                "examples/demo.py": _F5D_ANTHROPIC,
                "app/main.py": "def hello():\n    return 'hi'\n",
            },
            set(),
        ),
        "f4c": ({"app/main.py": _F4C_OPENAI}, {"OpenAI API"}),
        "f5b": ({"app/main.py": _F5B_ANTHROPIC_BEDROCK}, {"Amazon Bedrock Runtime"}),
        "f5c": ({"app/main.py": _F5C_CTRL}, set()),
        "f5d": ({"app/main.py": _F5D_ANTHROPIC}, {"Anthropic API"}),
    }
    for name, (files, expected) in cases.items():
        result = _scan(tmp_path / name, files)
        assert set(_services(result)) == expected, (name, _services(result))


# --------------------------------------------------------------------------- M2


def test_azure_openai_serves_gpt_4o_and_is_assessed(tmp_path) -> None:
    root = _repo(
        tmp_path, {"requirements.txt": "openai==1.50.0\n", "app/main.py": _F4_AZURE}
    )
    result = scan_repo(root, level=4)
    services = _services(result)
    assert "OpenAI API" not in services
    assert (
        services["Azure OpenAI"]["service:endpoint"]
        == "https://contoso-ai.openai.azure.com"
    )
    assert _served(result, "gpt-4o") == ["Azure OpenAI"]
    assert _model(result, "gpt-4o").properties["model:provider"] == "azure"
    run_all(result)
    req = next(
        q
        for q in result.compliance["rbi_free_ai"]["requirements"]
        if q["id"] == "FREEAI-19-1"
    )
    assert req["verdict"] == "not_bom_evidenceable" and "modelref-gpt-4o" in req["refs"]
    out = scan_to_devsecshield(str(root), level=4)
    row = next(r for r in out["results"] if r["component_name"] == "gpt-4o")
    assert (row["component_type"], row["source"]) == ("external_provider", "azure")


def test_azure_openai_with_its_endpoint_in_the_environment(tmp_path) -> None:
    result = _scan(tmp_path, {"app/main.py": _F4B_AZURE_ENV})
    azure = _services(result)["Azure OpenAI"]
    assert "service:endpoint" not in azure
    assert azure["service:endpoint_env"] == "AZURE_OPENAI_ENDPOINT"
    assert _served(result, "gpt-4o-mini") == ["Azure OpenAI"]


def test_boto3_invoke_model_id_is_usage_served_by_bedrock(tmp_path) -> None:
    result = _scan(
        tmp_path, {"requirements.txt": "boto3==1.35.0\n", "app/main.py": _F5_BOTO3}
    )
    name = "eu.anthropic.claude-3-7-sonnet-20250219-v1:0"
    model = _model(result, name)
    assert model.properties["model:reference_type"] == "usage"
    assert _served(result, name) == ["Amazon Bedrock Runtime"]
    assert (
        _services(result)["Amazon Bedrock Runtime"]["service:endpoint"]
        == "https://bedrock-runtime.eu-central-1.amazonaws.com"
    )


def test_a_same_file_service_wins_over_a_repo_wide_vendor_api(tmp_path) -> None:
    result = _scan(
        tmp_path,
        {
            "app/azure.py": _F4_AZURE,
            "app/direct.py": _F4C_OPENAI.replace('"gpt-4o"', '"gpt-4o-mini"'),
        },
    )
    assert _served(result, "gpt-4o") == ["Azure OpenAI"]
    assert _served(result, "gpt-4o-mini") == ["OpenAI API"]


# --------------------------------------------------------------------------- m4


def test_a_literal_proxy_base_url_is_the_serving_gateway(tmp_path) -> None:
    result = _scan(
        tmp_path, {"requirements.txt": "openai\nanthropic\n", "app/main.py": _F3_PROXY}
    )
    services = _services(result)
    gateway = services["AI gateway (litellm.internal:4000)"]
    assert gateway["service:endpoint"] == "http://litellm.internal:4000"
    assert "OpenAI API" not in services and "Anthropic API" not in services
    assert _served(result, "gpt-4o") == ["AI gateway (litellm.internal:4000)"]
    out = scan_to_devsecshield(str(tmp_path), level=4)
    row = next(r for r in out["results"] if r["component_name"] == "gpt-4o")
    assert row["component_type"] == "external_provider"  # not local


def test_litellm_api_base_and_kwargs_config_name_the_gateway(tmp_path) -> None:
    for name, source in (("f3c", _F3C_LITELLM), ("f3d", _F3D_KWARGS)):
        result = _scan(tmp_path / name, {"app/main.py": source})
        assert _served(result, "gpt-4o") == ["AI gateway (litellm.internal:4000)"], name


# --------------------------------------------------------------------------- m5


def test_sdk_clients_in_tsx_and_mjs_files_are_services(tmp_path) -> None:
    result = _scan(
        tmp_path,
        {
            "app/api/chat/route.tsx": 'import OpenAI from "openai";\nconst client = new OpenAI();\n'
            "export async function POST() { return client.chat.completions.create("
            '{ model: "gpt-4o", messages: [] }); }\n',
            "lib/ai.mjs": 'import Anthropic from "@anthropic-ai/sdk";\n'
            "// const old = new Anthropic({ baseURL: 'x' })\nconst a = new Anthropic();\n",
        },
    )
    assert {"OpenAI API", "Anthropic API"} <= set(_services(result))


# --------------------------------------------------------------------------- m3


@pytest.mark.parametrize(
    ("model_id", "vendor"),
    [
        ("deepseek.r1-v1:0", "DeepSeek"),
        ("us.deepseek.r1-v1:0", "DeepSeek"),
        ("openai.gpt-oss-120b-1:0", "OpenAI"),
        ("writer.palmyra-x5-v1:0", "Writer"),
        ("qwen.qwen3-32b-v1:0", "Alibaba"),
    ],
)
def test_newer_bedrock_providers_are_recognised(model_id: str, vendor: str) -> None:
    assert find_model_refs(f'modelId="{model_id}"') == {model_id: vendor}


def test_lookalike_prose_is_no_bedrock_id() -> None:
    text = 'URL = "https://mistral.ai/news"\nCFG = "meta.json"\nSITE = "amazon.com"\n' \
        'NOTE = "see cohere.command docs"\n'
    assert find_model_refs(text) == {}


# --------------------------------------------------------------------------- M6


def test_open_weights_carry_their_licence_and_api_names_do_not() -> None:
    mnpl = "LicenseRef-Mistral-AI-Non-Production-License"
    assert lookup("Codestral-22B-v0.1")["license"] == mnpl
    assert lookup("Mistral-Large-Instruct-2407")["license"] == (
        "LicenseRef-Mistral-Research-License"
    )
    for name in (
        "codestral-latest",
        "codestral-2508",
        "mistral-saba-latest",
        "mistral-large-2407",
        "mistral-small-latest",
    ):
        assert "license" not in lookup(name), name
    for name in (
        "Mistral-7B-v0.1",
        "Mixtral-8x7B-v0.1",
        "Mistral-Nemo-Instruct-2407",
        "codestral-mamba-latest",
    ):
        assert lookup(name)["license"] == "Apache-2.0", name


def test_api_served_mistral_models_are_provider_terms(tmp_path) -> None:
    result = _scan(
        tmp_path,
        {
            "app/main.py": (
                "import os\nfrom mistralai import Mistral\n"
                "client = Mistral(api_key=os.environ['MISTRAL_API_KEY'])\n"
                'def a():\n    return client.chat.complete(model="codestral-latest", messages=[])\n'
                'def b():\n    return client.chat.complete(model="mistral-saba-latest", messages=[])\n'
            )
        },
    )
    for name in ("codestral-latest", "mistral-saba-latest"):
        model = _model(result, name)
        assert model.licenses == [{"license": {"name": "LicenseRef-proprietary"}}] or (
            model.licenses == [{"license": {"id": "LicenseRef-proprietary"}}]
        ), name
        cons = model.model_card.considerations
        assert cons is None or not cons.out_of_scope, name
        assert not [
            f
            for f in result.flags
            if f.target == model.bom_ref and f.code == "MODEL_LICENSE_UNKNOWN"
        ]


def test_local_codestral_weights_keep_the_non_production_licence(tmp_path) -> None:
    result = _scan(
        tmp_path,
        {
            "requirements.txt": "transformers==4.44.0\n",
            "app/main.py": "from transformers import AutoModelForCausalLM\n"
            'm = AutoModelForCausalLM.from_pretrained("mistralai/Codestral-22B-v0.1")\n',
        },
    )
    model = _model(result, "Codestral-22B-v0.1")
    assert (
        model.licenses[0]["license"].get("name", model.licenses[0]["license"].get("id"))
        == "LicenseRef-Mistral-AI-Non-Production-License"
    )
    assert any(
        "Non-Production" in u for u in model.model_card.considerations.out_of_scope
    )
    assert _served(result, "Codestral-22B-v0.1") == []  # loaded locally, not API-served


# --------------------------------------------------------------------------- M7


def test_unknown_library_licences_are_stated_in_aggregate(tmp_path) -> None:
    root = _repo(
        tmp_path,
        {
            "requirements.txt": "instructor==1.0\nlitellm==1.50\n"
            # mlx-lm: not in the offline manifest (vllm was, until #498 round 3)
            "dspy-ai==2.5\nguidance==0.1\noutlines==0.1\nmlx-lm==0.6\n"
        },
    )
    result = scan_repo(root, level=4)
    assert result.properties["aibom:licence_coverage"] == "2/6"
    assert result.properties["aibom:licence_unknown"] == "4"
    out = scan_to_devsecshield(str(root), level=4)
    props = {
        p["name"]: p["value"] for p in out["ai_bom_json"]["metadata"]["properties"]
    }
    assert (props["aibom:licence_coverage"], props["aibom:licence_unknown"]) == (
        "2/6",
        "4",
    )


def test_every_licence_resolved_states_full_coverage(tmp_path) -> None:
    result = _scan(tmp_path, {"requirements.txt": "openai==1.50.0\n"})
    assert result.properties["aibom:licence_coverage"] == "1/1"
    assert "aibom:licence_unknown" not in result.properties


# --------------------------------------------------------------------------- m2


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        ((0, 0, 0, 7), (14, "A", "Low risk")),
        ((0, 0, 1, 0), (15, "B", "Moderate risk")),
        ((0, 1, 0, 0), (30, "C", "Elevated risk")),
        ((1, 0, 0, 0), (50, "D", "High risk")),
        ((0, 0, 10, 32), (49, "C", "Elevated risk")),
        ((0, 0, 0, 0), (0, "A", "Low risk")),
    ],
)
def test_grade_a_means_the_worst_finding_is_low(counts: tuple, expected: tuple) -> None:
    assert posture_risk(*counts) == expected
