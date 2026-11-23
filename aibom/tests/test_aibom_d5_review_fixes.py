"""Review of #487 (D5 AI BOM): the blocker, the majors and the engine-side minors.

Each test reproduces a finding of review 6027766175 on a small repository written
to ``tmp_path`` (the reviewer's fixtures ``qa/487/fx/model-fn`` and
``fx/model-env``). Every credential below is a fake placeholder.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.scan.pipeline import scan_repo
from aibom.score.scorer import score_result

_TESTS = pathlib.Path(__file__).resolve().parent
_BANK = _TESTS / "fixtures" / "aibom-bank-router"
_CLINICAL = _TESTS.parent / "examples" / "clinical-imaging"
_FAKE_KEY = "AIzaFAKE-not-a-real-key-000"

_MODEL_FN = {
    "requirements.txt": "openai>=1.40\nrequests==2.32.3\n",
    ".env.example": "OPENAI_MODEL=gpt-4o\n",
    "config/llm.yaml": "llm:\n  provider: anthropic\n"
    "  model: claude-3-5-sonnet-20241022\n  temperature: 0\n",
    "app/chat.py": f"""import os, requests
from openai import OpenAI
client = OpenAI()

def a():
    return client.chat.completions.create(model="gpt-4o-mini", messages=[])

def b():
    # raw HTTP body, very common
    return requests.post("https://api.openai.com/v1/chat/completions",
                         json={{"model": "gpt-4.1", "messages": []}})

def c():
    return client.chat.completions.create(model=os.getenv("OPENAI_MODEL", "o3-mini"),
                                          messages=[])

def d():
    payload = {{
        "model": "claude-3-5-haiku-20241022",
        "max_tokens": 10,
    }}
    return requests.post("https://api.anthropic.com/v1/messages", json=payload)

def e():
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={_FAKE_KEY}"
    return requests.post(url, json={{}})
""",
    "app/hf.py": "from transformers import AutoModelForCausalLM\n"
    'MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"\n'
    "model = AutoModelForCausalLM.from_pretrained(MODEL_NAME)\n",
    "web/client.ts": "const DEFAULT_MODEL = 'claude-sonnet-4-20250514';\n"
    "export async function ask(q: string) {\n"
    "  return anthropic.messages.create({ model: DEFAULT_MODEL, max_tokens: 100,"
    ' messages: [{ role: "user", content: q }] });\n}\n',
    # prose: a doc that "uses" a model is a mention, never usage (m11, M1)
    "docs/DEEPDIVE.md": 'The judge calls `model="gpt-4o-mini"` and '
    '`model="gpt-4-turbo"`.\n',
}


def _write(root: pathlib.Path, files: dict[str, str]) -> pathlib.Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _models(bom: dict) -> dict[str, dict[str, str]]:
    return {
        c["name"]: {p["name"]: p["value"] for p in c.get("properties", [])}
        for c in bom["components"]
        if c["type"] == "machine-learning-model"
    }


@pytest.fixture(scope="module")
def model_fn(tmp_path_factory) -> dict:
    root = _write(tmp_path_factory.mktemp("model-fn"), _MODEL_FN)
    return scan_to_devsecshield(root, level=4)


# --------------------------------------------------------------------------- B1
def test_no_api_key_reaches_the_bom_or_the_scan_data(model_fn: dict) -> None:
    assert _FAKE_KEY not in json.dumps(model_fn, default=str)
    services = {
        s["name"]: s.get("endpoints") for s in model_fn["ai_bom_json"]["services"]
    }
    assert services["Google Gemini API"] == [
        "https://generativelanguage.googleapis.com/v1beta"
    ]
    assert services["OpenAI API"] == ["https://api.openai.com/v1"]
    assert services["Anthropic API"] == ["https://api.anthropic.com/v1"]


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # userinfo, query and fragment never survive
        (
            'URL = "https://svc:FAKEPASS@api.openai.com/v1/chat/completions#frag"',
            "https://api.openai.com/v1",
        ),
        (
            'URL = "https://acme.openai.azure.com/openai/deployments/gpt4/chat?api-version=2024-02-01&api-key=FAKEKEY"',
            "https://acme.openai.azure.com",
        ),
        (
            'BASE = "http://admin:FAKEPASS@localhost:11434/api/generate?token=FAKETOKEN"',
            "http://localhost:11434",
        ),
        # a token in a later path segment is not kept either
        ('U = "https://api.groq.com/openai/FAKETOKEN/v1/chat"', "https://api.groq.com"),
    ],
)
def test_endpoint_is_the_base_url_only(
    tmp_path: pathlib.Path, line: str, expected: str
) -> None:
    _write(tmp_path, {"app/client.py": line + "\n"})
    out = scan_to_devsecshield(tmp_path, level=4)
    blob = json.dumps(out, default=str)
    for secret in ("FAKEPASS", "FAKEKEY", "FAKETOKEN", "frag", "api-version"):
        assert secret not in blob, secret
    (service,) = out["ai_bom_json"]["services"]
    assert service["endpoints"] == [expected]


# --------------------------------------------------------------------------- M1
def test_reviewer_fixture_finds_every_model_with_its_classification(
    model_fn: dict,
) -> None:
    models = _models(model_fn["ai_bom_json"])
    in_use = {
        "Llama-3.1-8B-Instruct",
        "claude-3-5-haiku-20241022",  # payload dict "model": "…"
        "claude-3-5-sonnet-20241022",  # unquoted YAML model: …
        "claude-sonnet-4-20250514",
        "gemini-1.5-flash",  # REST path /models/<id>
        "gpt-4.1",  # json={"model": "…"}
        "gpt-4o",  # OPENAI_MODEL= in the env template
        "gpt-4o-mini",
        "o3-mini",  # os.getenv("…", "o3-mini")
    }
    assert {
        n for n, p in models.items() if p["model:reference_type"] == "usage"
    } == in_use
    # the doc-only name stays in the BOM as a catalog reference, not dropped
    assert models["gpt-4-turbo"]["model:reference_type"] == "catalog"
    # the strongest evidence is code, never the doc that also names it (m11)
    assert models["gpt-4o-mini"]["discovery:source"] == "app/chat.py"
    assert models["gpt-4o"]["discovery:source"] == ".env.example"


def test_catalog_references_are_kept_but_not_counted(model_fn: dict) -> None:
    rows = {r["component_name"] for r in model_fn["results"]}
    assert "gpt-4-turbo" not in rows  # no finding, no dashboard asset
    assert "gpt-4o-mini" in rows
    scores = model_fn["ai_bom_scores"]
    assert sum(scores["severity_counts"].values()) == len(model_fn["results"])
    refs = {
        r
        for fw in model_fn["ai_bom_compliance"].values()
        if isinstance(fw, dict)
        for req in fw.get("requirements") or []
        for r in req.get("refs") or []
    }
    assert "modelref-gpt-4-turbo" not in refs
    props = {
        p["name"]: p["value"] for p in model_fn["ai_bom_json"]["metadata"]["properties"]
    }
    assert props["aibom:model_mentions_catalog"] == "1"


def test_bank_router_keeps_its_catalog_models_tagged() -> None:
    out = scan_to_devsecshield(_BANK, level=4)
    models = _models(out["ai_bom_json"])
    usage = sorted(n for n, p in models.items() if p["model:reference_type"] == "usage")
    assert usage == ["Qwen2.5-1.5B-Instruct", "gpt-4o"]
    assert models["Qwen2-0.5B"]["model:reference_type"] == "catalog"
    assert models["gpt-4-turbo"]["model:reference_type"] == "catalog"  # docs/models.md
    assert models["claude-3-opus"]["model:reference_type"] == "test"
    assert {r["component_name"] for r in out["results"]} >= {
        "gpt-4o",
        "Qwen2.5-1.5B-Instruct",
    }
    assert not {"Qwen2-0.5B", "claude-3-opus"} & {
        r["component_name"] for r in out["results"]
    }


def test_a_docstring_argument_is_not_usage(tmp_path: pathlib.Path) -> None:
    """SmarterRouter router/backends/external.py: an ``Args:`` docstring line looks
    like unquoted YAML but the model is an example, not the key's value."""
    _write(
        tmp_path,
        {
            "router/external.py": 'def split(model_name):\n    """\n    Args:\n'
            '        model_name: Model name (e.g., "openai/gpt-4" or just "gpt-4")\n'
            '    """\n'
        },
    )
    models = _models(scan_to_devsecshield(tmp_path, level=4)["ai_bom_json"])
    assert models["gpt-4"]["model:reference_type"] == "catalog"


# --------------------------------------------------------------------------- m1
def test_model_settings_in_real_env_files_count(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            ".env": "OPENAI_MODEL=gpt-4o\n"
            'ROUTER_JUDGE_MODEL="claude-3-5-haiku-20241022"\n',
            "app.py": "import openai\n",
        },
    )
    models = _models(scan_to_devsecshield(tmp_path, level=4)["ai_bom_json"])
    assert {n: p["model:reference_type"] for n, p in models.items()} == {
        "gpt-4o": "usage",
        "claude-3-5-haiku-20241022": "usage",
    }


# --------------------------------------------------------------------------- M2
_HEALTHCARE_WORDS = re.compile(r"\b(?:BAA|MDR|PHI|HIPAA|FDA)\b")
_SOW = (
    "cert_in_aibom",
    "rbi_free_ai",
    "sebi_cscrf_aibom",
    "nist_rmf",
    "eu_ai_act_annexIV",
)


def test_a_bank_ai_bom_names_no_healthcare_requirement() -> None:
    out = scan_to_devsecshield(_BANK, level=4)
    for key in ("ai_bom_json", "ai_bom_spdx", "ai_bom_sarif"):
        assert not _HEALTHCARE_WORDS.findall(json.dumps(out[key])), key
    comp = out["ai_bom_compliance"]
    for key in _SOW:
        assert not _HEALTHCARE_WORDS.findall(json.dumps(comp[key])), key
    reqs = {(k, r["id"]): r for k in _SOW for r in comp[k]["requirements"]}
    # vendor accountability and the EU risk tier are contracts / determinations the
    # code cannot show: evidence to attach, not a fail
    for key in (
        ("nist_rmf", "GV-2"),
        ("rbi_free_ai", "FREEAI-19-1"),
        ("eu_ai_act_annexIV", "EUAIACT-11"),
    ):
        assert reqs[key]["verdict"] in ("not_bom_evidenceable", "na", "pass"), key
    assert reqs[("nist_rmf", "GV-2")]["title"].endswith("(contract / DPA)")
    assert reqs[("eu_ai_act_annexIV", "EUAIACT-11")]["source"] == "Art 6 / Annex III"


def test_healthcare_profile_keeps_the_healthcare_wording() -> None:
    out = scan_to_devsecshield(_CLINICAL, level=4)
    comp = out["ai_bom_compliance"]
    reqs = {(k, r["id"]): r for k in _SOW for r in comp[k]["requirements"]}
    assert "BAA" in reqs[("nist_rmf", "GV-2")]["title"]
    assert (
        reqs[("eu_ai_act_annexIV", "EUAIACT-11")]["title"]
        == "High-risk classification asserted"
    )
    assert reqs[("eu_ai_act_annexIV", "EUAIACT-11")]["source"] == "Art 6 / Annex I"


# --------------------------------------------------------------------------- m2 / m3
@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        ((0, 0, 0, 7), (28, "B", "Moderate risk")),
        ((0, 0, 10, 32), (49, "C", "Elevated risk")),
        ((0, 3, 50, 0), (69, "D", "High risk")),
        ((2, 0, 0, 0), (80, "F", "Critical risk")),
        ((0, 0, 0, 0), (0, "A", "Low risk")),
    ],
)
def test_one_grade_table(counts: tuple, expected: tuple) -> None:
    from aibom.score.posture import posture_risk

    assert posture_risk(*counts) == expected


def test_the_engine_band_is_the_pdf_grade_word() -> None:
    from aibom.score.posture import posture_grade, posture_label

    scores = scan_to_devsecshield(_BANK, level=4)["ai_bom_scores"]
    grade, band = posture_grade(scores["risk_normalized"])
    assert (scores["risk_grade"], scores["risk_band"]) == (grade, band)
    assert scores["risk_label"] == posture_label(band)


def test_cbom_scores_keep_the_cbom_scale() -> None:
    """The AI BOM posture score does not change CBOM scores (m3): the CBOM keeps its
    flag-weight scale, so synthetic-crypto-misuse stays 42.9 / medium as on dev."""
    from aibom.cbom.pipeline import scan_crypto

    result = scan_crypto(_TESTS / "fixtures" / "synthetic-crypto-misuse")
    assert result.scores["risk_normalized"] == 42.9
    assert result.scores["risk_band"] == "medium"
    assert "severity_counts" not in result.scores
    # and the AI BOM path still uses the posture score
    ai = score_result(scan_repo(_BANK, level=4))
    assert "severity_counts" in ai.scores


# --------------------------------------------------------------------------- m5 / m6
def test_bedrock_endpoint_is_regional_or_absent(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "a/regional.py": 'import boto3\nc = boto3.client("bedrock-runtime", '
            'region_name="eu-west-1")\n'
        },
    )
    (svc,) = scan_to_devsecshield(tmp_path, level=4)["ai_bom_json"]["services"]
    assert svc["endpoints"] == ["https://bedrock-runtime.eu-west-1.amazonaws.com"]
    other = tmp_path / "b"
    _write(other, {"b.py": 'import boto3\nc = boto3.client("bedrock-runtime")\n'})
    (svc,) = scan_to_devsecshield(other, level=4)["ai_bom_json"]["services"]
    assert "endpoints" not in svc
    assert "bedrock-runtime.amazonaws.com" not in json.dumps(svc)


def test_services_only_in_tests_or_examples_are_left_out(
    tmp_path: pathlib.Path,
) -> None:
    _write(
        tmp_path,
        {
            "tests/test_backend_contract.py": 'URL = "http://localhost:8000/v1"\n',
            "artificial_analysis_models.example.yaml": "url: http://localhost:11434\n",
            "app/main.py": 'BASE = "https://api.openai.com/v1"\n',
        },
    )
    bom = scan_to_devsecshield(tmp_path, level=4)["ai_bom_json"]
    assert [s["name"] for s in bom["services"]] == ["OpenAI API"]
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["aibom:services_excluded_test_example"] == "2"


def test_a_bare_dev_server_port_is_low_confidence(tmp_path: pathlib.Path) -> None:
    _write(tmp_path, {"app/main.py": 'URL = "http://localhost:8000/v1"\n'})
    (svc,) = scan_to_devsecshield(tmp_path, level=4)["ai_bom_json"]["services"]
    assert {"name": "discovery:confidence", "value": "low"} in svc["properties"]


# --------------------------------------------------------------------------- m7
def test_saas_providers_are_not_local(model_fn: dict) -> None:
    rows = {r["component_name"]: r["source"] for r in model_fn["results"]}
    assert rows["Google Gemini API"] == "google"
    assert rows["gemini-1.5-flash"] == "google"
    assert rows["OpenAI API"] == "openai"
