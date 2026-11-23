"""SOW D5 AI BOM deliverable: the defects the staging audit found on
peva3/SmarterRouter (audit-C G-D5-1..4, G-X-4).

The fixture ``fixtures/aibom-bank-router`` reproduces SmarterRouter's shape: a
model-routing service with a pricing
catalog of model names, a Hugging Face model loaded by id, OpenAI / Ollama / Bedrock
endpoints, test code that names
models, and a requirements.txt mixing AI libraries, web/database dependencies and test
tools.

Every format is checked against the official schemas bundled under ``aibom/schemas``
(CycloneDX 1.6, SARIF 2.1.0
OASIS errata01, SPDX 3.0.1 JSON schema) and the SPDX document against the official SPDX
3.0.1 SHACL model
(``fixtures/spdx-3.0.1-shacl/spdx-model.ttl``,
https://spdx.org/rdf/3.0.1/spdx-model.ttl) with pyshacl.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from aibom.emit.cyclonedx import emit_and_validate
from aibom.emit.sarif import emit_and_validate_sarif
from aibom.emit.spdx import emit_and_validate_spdx
from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.scan.parsers.ai_libraries import classify
from aibom.scan.parsers.model_refs import find_model_refs_ctx
from aibom.scan.pipeline import scan_repo
from aibom.score.scorer import posture_score

_TESTS = pathlib.Path(__file__).resolve().parent
_FIXTURE = _TESTS / "fixtures" / "aibom-bank-router"
_CLINICAL = _TESTS.parent / "examples" / "clinical-imaging"
_SHACL = (
    _TESTS / "fixtures" / "spdx-3.0.1-shacl"
)  # official model + context, unmodified


def _shacl_conforms(doc: dict) -> tuple[bool, str]:
    rdflib = pytest.importorskip("rdflib")
    pyshacl = pytest.importorskip("pyshacl")
    context = json.loads((_SHACL / "spdx-context.jsonld").read_text(encoding="utf-8"))
    data = dict(
        doc, **{"@context": context["@context"]}
    )  # offline: the official context, inlined
    graph = rdflib.Graph().parse(data=json.dumps(data), format="json-ld")
    shapes = rdflib.Graph().parse(str(_SHACL / "spdx-model.ttl"), format="turtle")
    conforms, _report, text = pyshacl.validate(
        graph,
        shacl_graph=shapes,
        ont_graph=shapes,
        inference="none",
        advanced=True,
        allow_warnings=True,
    )
    return bool(conforms), text


@pytest.fixture(scope="module")
def run() -> dict:
    return scan_to_devsecshield(_FIXTURE, level=4)


# --------------------------------------------------------------------------- SPDX 3.0.1
# (G-D5-1)
@pytest.mark.parametrize(
    "target", [_FIXTURE, _CLINICAL], ids=["bank-router", "clinical-imaging"]
)
def test_spdx_passes_the_official_shacl_model(target: pathlib.Path) -> None:
    doc = emit_and_validate_spdx(
        scan_repo(target, level=4)
    )  # JSON schema first (raises when invalid)
    conforms, text = _shacl_conforms(doc)
    assert conforms, text


def test_spdx_created_by_an_organization_using_the_tool(run: dict) -> None:
    graph = run["ai_bom_spdx"]["@graph"]
    by_id = {e.get("spdxId"): e for e in graph if e.get("spdxId")}
    info = next(e for e in graph if e.get("type") == "CreationInfo")
    assert [by_id[i]["type"] for i in info["createdBy"]] == ["Organization"]
    assert [by_id[i]["type"] for i in info["createdUsing"]] == ["Tool"]
    assert by_id[info["createdUsing"][0]]["name"].startswith("DevSecShield AI BOM ")
    assert all(not i.startswith("https://devsecshield.example") for i in by_id)


# --------------------------------------------------------------------------- services
# (G-D5-2)
def test_ai_endpoints_are_cyclonedx_services(run: dict) -> None:
    bom = run["ai_bom_json"]
    services = {s["bom-ref"]: s for s in bom["services"]}
    openai = services["cloud_service-api-openai-com"]
    assert openai["endpoints"] == ["https://api.openai.com/v1"]
    assert openai["provider"] == {"name": "OpenAI"}
    assert openai["authenticated"] is True and openai["x-trust-boundary"] is True
    assert openai["trustZone"] == "external"
    assert openai["data"][0]["flow"] == "bi-directional"
    ollama = services["endpoint-localhost-11434"]
    assert ollama["endpoints"] == ["http://localhost:11434"]
    assert ollama["x-trust-boundary"] is False and ollama["authenticated"] is False
    bedrock = next(
        s for s in services.values() if s["name"] == "Amazon Bedrock Runtime"
    )
    assert bedrock["authenticated"] is True and bedrock["trustZone"] == "external"
    # no endpoint or provider is left as an application component
    assert not [c for c in bom["components"] if c["type"] == "application"]
    # the model the code uses depends on the service that serves it
    deps = {d["ref"]: d.get("dependsOn", []) for d in bom["dependencies"]}
    assert deps["modelref-gpt-4o"] == ["cloud_service-api-openai-com", "lib-openai"]


# --------------------------------------------------------------------------- models
# (G-D5-3)
def test_model_names_are_not_truncated() -> None:
    names = set(
        find_model_refs_ctx(
            'm = AutoModel.from_pretrained("Qwen/Qwen2.5-1.5B-Instruct")\n'
            'x = ["Qwen2-0.5B", "Mistral-7B-v0.1", "llama-3.2-1b"]\n'
        )
    )
    assert {
        "Qwen2.5-1.5B-Instruct",
        "Qwen2-0.5B",
        "Mistral-7B-v0.1",
        "llama-3.2-1b",
    } <= names
    assert not {"Qwen2-0", "Qwen2.5-1"} & names


def test_only_models_the_application_uses_are_inventoried(run: dict) -> None:
    bom = run["ai_bom_json"]
    models = {
        c["name"]: {p["name"]: p["value"] for p in c.get("properties", [])}
        for c in bom["components"]
        if c["type"] == "machine-learning-model"
    }
    # gpt-4o: the judge model's default; Qwen2.5-1.5B-Instruct: loaded with
    # from_pretrained. The supported-models table (Qwen2-0.5B …), the pricing doc
    # (gpt-4-turbo) and the test (claude-3-opus) stay in the BOM as tagged
    # references (review of #487 M1), never as models in use.
    in_use = sorted(
        n for n, p in models.items() if p["model:reference_type"] == "usage"
    )
    assert in_use == ["Qwen2.5-1.5B-Instruct", "gpt-4o"]
    assert models["claude-3-opus"]["model:reference_type"] == "test"
    assert models["gpt-4-turbo"]["model:reference_type"] == "catalog"
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert int(props["aibom:model_mentions_catalog"]) >= 6
    assert props["aibom:model_mentions_test"] == "1"
    assert models["gpt-4o"]["discovery:source"] == "router/config.py"
    # only models in use are findings
    rows = {r["component_name"] for r in run["results"]}
    assert {"gpt-4o", "Qwen2.5-1.5B-Instruct"} <= rows
    assert not {"Qwen2-0.5B", "gpt-4-turbo", "claude-3-opus"} & rows


# --------------------------------------------------------------------------- AI
# libraries
def test_only_ai_libraries_are_ai_components(run: dict) -> None:
    libs = {
        c["name"] for c in run["ai_bom_json"]["components"] if c["type"] == "library"
    }
    # boto3 is imported to reach Bedrock (code-import scanner: an AI provider SDK here)
    assert libs == {"openai", "transformers", "pandas", "boto3"}
    rows = {r["component_name"]: r for r in run["results"]}
    for tool in (
        "pytest",
        "pytest-asyncio",
        "mypy",
        "ruff",
        "fastapi",
        "sqlalchemy",
        "redis",
    ):
        assert tool not in rows
    assert rows["openai"]["component_type"] == "ml_framework"
    props = {
        p["name"]: p["value"] for p in run["ai_bom_json"]["metadata"]["properties"]
    }
    assert props["aibom:dependencies_excluded_dev_tools"] == "4"
    assert props["aibom:dependencies_excluded_non_ai"] == "3"
    openai = next(c for c in run["ai_bom_json"]["components"] if c["name"] == "openai")
    assert {"name": "aibom:version_constraint", "value": ">=1.30.0"} in openai[
        "properties"
    ]


@pytest.mark.parametrize(
    ("name", "role"),
    [
        ("pytest", "dev"),
        ("pytest-cov", "dev"),
        ("types-requests", "dev"),
        ("ruff", "dev"),
        ("mypy", "dev"),
        ("sqlalchemy", "other"),
        ("fastapi", "other"),
        ("prometheus-client", "other"),
        ("torch", "ai"),
        ("langchain-openai", "ai"),
        ("sentence_transformers", "ai"),
        ("qdrant-client", "ai"),
        ("acme-llm-client", "ai"),
    ],
)
def test_library_classification(name: str, role: str) -> None:
    assert classify(name) == role


# --------------------------------------------------------------------------- risk
# (G-D5-4)
def test_risk_score_is_bounded_by_the_findings(run: dict) -> None:
    scores = run["ai_bom_scores"]
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in run["results"]:
        sev[row["impact"].lower()] += 1
    assert (
        scores["severity_counts"] == sev
    )  # the engine counts the rows the dashboard and PDF count
    assert scores["risk_normalized"] == posture_score(**sev)
    if not sev["critical"] and not sev["high"]:
        assert scores["risk_normalized"] <= 49
        assert scores["risk_band"] not in ("critical", "high")


@pytest.mark.parametrize(
    ("counts", "cap"),
    [
        (
            (0, 0, 10, 32),
            49,
        ),  # SmarterRouter on staging: 100 / F with zero critical or high
        ((0, 0, 0, 500), 29),
        ((0, 3, 50, 0), 69),
        ((1, 0, 0, 0), 40),
        ((0, 0, 0, 0), 0),
    ],
)
def test_posture_score_never_exceeds_the_worst_severity(
    counts: tuple, cap: int
) -> None:
    assert posture_score(*counts) <= cap
    assert posture_score(*counts) == min(
        cap if counts[0] == 0 else 100,
        min(100, 4 * (10 * counts[0] + 5 * counts[1] + 2 * counts[2] + counts[3])),
    )


# --------------------------------------------------------------------------- identity
# (G-X-4)
def test_tool_identity_version_and_scan_time(monkeypatch) -> None:
    monkeypatch.setenv("DSS_BUILD_VERSION", "2026.11.23-rc1")
    out = scan_to_devsecshield(_FIXTURE, level=4)
    bom, spdx, sarif = out["ai_bom_json"], out["ai_bom_spdx"], out["ai_bom_sarif"]
    (tool,) = bom["metadata"]["tools"]["components"]
    assert (tool["name"], tool["version"]) == ("DevSecShield AI BOM", "2026.11.23-rc1")
    stamp = bom["metadata"]["timestamp"]
    assert stamp != "2026-06-21T00:00:00Z" and stamp.endswith("Z")
    info = next(e for e in spdx["@graph"] if e.get("type") == "CreationInfo")
    assert info["created"] == stamp
    driver = sarif["runs"][0]["tool"]["driver"]
    assert (driver["name"], driver["version"]) == (
        "DevSecShield AI BOM",
        "2026.11.23-rc1",
    )
    assert sarif["runs"][0]["invocations"][0]["endTimeUtc"] == stamp
    for doc in (bom, spdx, sarif):
        text = json.dumps(doc)
        assert "clinithread" not in text.lower()
        assert (
            "FDA" not in text and "HIPAA" not in text
        )  # a bank's AI BOM: neutral disclaimer
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert "advisory only" in props["regulatory:disclaimer"]
    assert "advisory only" in out["ai_bom_compliance"]["disclaimer"]


def test_healthcare_profile_keeps_the_healthcare_disclaimer() -> None:
    bom = emit_and_validate(scan_repo(_CLINICAL))
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert "HIPAA" in props["regulatory:disclaimer"]


def test_every_format_validates_against_the_official_schemas(run: dict) -> None:
    result = scan_repo(_FIXTURE, level=4)
    emit_and_validate(result)  # CycloneDX 1.6 (raises on any error)
    emit_and_validate_sarif(result)  # SARIF 2.1.0 (OASIS errata01)
    emit_and_validate_spdx(result)  # SPDX 3.0.1 JSON schema


# --------------------------------------------------------------------------- compliance
# (SOW AIBOM checks)
def test_sow_frameworks_are_computed_from_the_bom(run: dict) -> None:
    comp = run["ai_bom_compliance"]
    for key in (
        "cert_in_aibom",
        "rbi_free_ai",
        "sebi_cscrf_aibom",
        "nist_rmf",
        "eu_ai_act_annexIV",
    ):
        fw = comp[key]
        assert fw["requirements"], key
        assert sum(
            fw[k]
            for k in (
                "pass",
                "pass_with_evidence",
                "fail",
                "not_bom_evidenceable",
                "out_of_scope",
                "na",
            )
        ) == len(fw["requirements"])
    # computed over the models in use, not the catalog: no requirement cites a
    # catalog-only model
    refs = {
        r
        for key in comp
        if isinstance(comp[key], dict)
        for req in comp[key].get("requirements") or []
        for r in req.get("refs") or []
    }
    assert not {r for r in refs if r.startswith("modelref-qwen2-0")}
