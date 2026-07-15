"""
Regression tests for the healthcare AI-BOM compliance-mapping layer
(helpers/tools/ai_bom_agent/compliance).

Hard rule (from the research dossier): each framework requirement must resolve to
the right AI-BOM field OR a flagged gap — never a silent drop. These tests lock that
in, plus: the advisory DISCLAIMER is always present, a richer BOM scores higher than
a minimal one, HIPAA flags external LLM providers for BAA review, and the engine is
deterministic.

Run from RabbitMQ/worker:  uv run pytest tests/test_compliance_mapping.py -q
"""
import json
import os
import sys

import pytest

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKER)

ALL_FRAMEWORKS = {"fda_524b", "eu_ai_act_annexIV", "gmlp", "hipaa", "nist_rmf"}
VALID_STATUS = {"met", "partial", "gap", "not_applicable"}


# ----------------------------- fixtures -----------------------------

@pytest.fixture(scope="module")
def minimal_bom():
    """What the current emitter actually produces from real detections."""
    from helpers.tools.ai_bom_agent import parser
    detections = [
        {"component_name": "gpt-4", "component_type": "external_provider", "source": "openai",
         "location": "app.py:2", "snippet": "openai.OpenAI().chat.completions.create(model='gpt-4')"},
        {"component_name": "torch", "component_type": "ml_framework", "source": "pypi",
         "version": "2.3.1", "license": "BSD-3-Clause", "location": "requirements.txt:5"},
        {"component_name": "model.safetensors", "component_type": "local_model_file", "source": "local",
         "location": "models/model.safetensors"},
    ]
    return parser.generate_cyclonedx_aibom(detections, scan_id="cmp-1",
                                           repo_url="https://github.com/acme/ml")


@pytest.fixture(scope="module")
def rich_bom():
    """The dossier's clinical-imaging target shape: modelCard + namespaced
    clinical:/regulatory:/dataset: properties (no invented top-level fields)."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "version": 1,
        "metadata": {
            "timestamp": "2026-06-21T00:00:00Z",
            "tools": {"components": [{"type": "application", "name": "DevSecShield AI-BOM Scanner", "version": "1.0.0"}]},
            "component": {"type": "application", "name": "ChestXR-Triage-SaMD", "version": "2.1.0"},
            "properties": [
                {"name": "clinical:modality", "value": "DX (chest radiograph)"},
                {"name": "clinical:intended_use", "value": "triage of chest radiographs"},
                {"name": "regulatory:fda_product_code", "value": "QFM"},
                {"name": "regulatory:device_class", "value": "II (SaMD)"},
                {"name": "regulatory:eu_ai_act_risk", "value": "high-risk (Annex I / MDR)"},
                {"name": "clinical:data_flow", "value": "DICOM -> model -> PACS; no external egress"},
            ],
        },
        "components": [
            {
                "bom-ref": "model-chestxr-cnn", "type": "machine-learning-model",
                "name": "chestxr-nodule-detector", "version": "2.1.0", "publisher": "Acme Medical AI",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [{"alg": "SHA-256", "content": "e3b0c44298fc1c149afbf4c8996fb924"}],
                "modelCard": {
                    "modelParameters": {
                        "approach": {"type": "supervised"}, "task": "classification/detection",
                        "architectureFamily": "convolutional neural network", "modelArchitecture": "ResNet-50",
                        "datasets": [{"ref": "dataset-chestxr-train"}],
                    },
                    "quantitativeAnalysis": {"performanceMetrics": [
                        {"type": "AUROC", "value": "0.94", "slice": "overall"},
                        {"type": "sensitivity", "value": "0.91", "slice": "age>=65"},
                    ]},
                    "considerations": {
                        "users": ["board-certified radiologist (human-in-the-loop)"],
                        "useCases": ["triage/prioritization of chest radiographs"],
                        "technicalLimitations": ["not validated on pediatric or portable AP supine films"],
                        "ethicalConsiderations": [{"name": "demographic performance gap", "mitigationStrategy": "subgroup monitoring"}],
                        "fairnessAssessments": [{"groupAtRisk": "underrepresented scanners/sites"}],
                    },
                },
                "pedigree": {"ancestors": [{"type": "machine-learning-model", "name": "imagenet-resnet50", "version": "1.0"}]},
                "externalReferences": [{"type": "model-card", "url": "https://acme.example/chestxr.modelcard.json"}],
            },
            {
                "bom-ref": "dataset-chestxr-train", "type": "data", "name": "chestxr-training-cohort",
                "data": [{"type": "dataset", "name": "chestxr-training-cohort",
                          "governance": {"owners": [{"organization": {"name": "Acme Medical AI"}}]}}],
                "properties": [
                    {"name": "dataset:type", "value": "image (DICOM)"},
                    {"name": "dataset:size", "value": "412,000 studies"},
                    {"name": "dataset:provenance", "value": "3 US health systems, 2019-2024, IRB-approved, de-identified"},
                    {"name": "dataset:sensitivity", "value": "PHI removed; Safe Harbor de-identification"},
                    {"name": "dataset:anonymization", "value": "Safe Harbor"},
                    {"name": "dataset:known_bias", "value": "skews adult, 2 scanner vendors"},
                ],
                "licenses": [{"license": {"name": "internal-restricted"}}],
            },
            {"bom-ref": "lib-pytorch", "type": "library", "name": "torch", "version": "2.3.1",
             "purl": "pkg:pypi/torch@2.3.1"},
        ],
        "dependencies": [{"ref": "model-chestxr-cnn", "dependsOn": ["dataset-chestxr-train", "lib-pytorch"]}],
    }


@pytest.fixture(scope="module")
def findings():
    return [
        {"risk_category": "unpinned_model_version", "severity": "medium"},
        {"risk_category": "exposed_api_key", "severity": "high"},
    ]


# ----------------------------- the hard rule -----------------------------

def _all_requirements(report_dict):
    for fw in report_dict["frameworks"]:
        for req in fw["requirements"]:
            yield fw["framework_key"], req


@pytest.mark.parametrize("bom_fixture", ["minimal_bom", "rich_bom"])
def test_every_requirement_resolves_to_field_or_gap(bom_fixture, findings, request):
    """HARD RULE: every requirement maps to a field or is a flagged gap — no silent drops."""
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
    bom = request.getfixturevalue(bom_fixture)
    report = evaluate_compliance_dict(bom, findings)

    for fw_key, req in _all_requirements(report):
        ctx = f"{fw_key}/{req['id']}"
        assert req["status"] in VALID_STATUS, f"{ctx}: bad status {req['status']}"
        # Every requirement names the BOM field(s) it consulted.
        assert req["mapped_fields"], f"{ctx}: requirement has no mapped_fields"
        if req["status"] == "met":
            assert req.get("evidence"), f"{ctx}: 'met' without evidence"
        elif req["status"] == "gap":
            # a flagged gap must actually be flagged + actionable
            assert req.get("gap"), f"{ctx}: 'gap' without a gap description"
            assert req.get("recommendation"), f"{ctx}: 'gap' without a recommendation"
        elif req["status"] == "partial":
            assert req.get("evidence") or req.get("gap"), f"{ctx}: 'partial' with neither evidence nor gap"
        # not_applicable is allowed: an explicit, visible exclusion (never a silent drop)


def test_disclaimer_always_present(minimal_bom):
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict, DISCLAIMER
    report = evaluate_compliance_dict(minimal_bom)
    assert report["disclaimer"] == DISCLAIMER
    assert "advisory" in report["disclaimer"].lower()


def test_all_frameworks_present(minimal_bom):
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
    report = evaluate_compliance_dict(minimal_bom)
    keys = {fw["framework_key"] for fw in report["frameworks"]}
    assert keys == ALL_FRAMEWORKS, f"missing frameworks: {ALL_FRAMEWORKS - keys}"


def test_readiness_scores_in_range(minimal_bom, rich_bom, findings):
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
    for bom in (minimal_bom, rich_bom):
        report = evaluate_compliance_dict(bom, findings)
        assert 0.0 <= report["overall_readiness_score"] <= 100.0
        for fw in report["frameworks"]:
            assert 0.0 <= fw["readiness_score"] <= 100.0
            counts = fw["counts"]
            assert sum(counts.values()) == len(fw["requirements"])


def test_rich_bom_scores_higher_than_minimal(minimal_bom, rich_bom, findings):
    """The mapping must actually respond to richer evidence (clinical modelCard +
    namespaced properties) — otherwise the gaps are meaningless."""
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
    lo = evaluate_compliance_dict(minimal_bom, findings)["overall_readiness_score"]
    hi = evaluate_compliance_dict(rich_bom, findings)["overall_readiness_score"]
    assert hi > lo, f"rich BOM ({hi}) should out-score minimal BOM ({lo})"


def test_rich_bom_meets_key_clinical_requirements(rich_bom, findings):
    """Spot-check that the dossier's namespaced fields flip the right requirements to met."""
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
    report = evaluate_compliance_dict(rich_bom, findings)
    by_id = {f"{fw}/{req['id']}": req for fw, req in _all_requirements(report)}
    # Annex IV design specs satisfied by modelCard.modelParameters
    assert by_id["eu_ai_act_annexIV/AnnexIV-2(b)"]["status"] == "met"
    # SaMD/PCCP device classification satisfied by regulatory: properties
    assert by_id["fda_524b/524B-PCCP-1"]["status"] == "met"
    # NIST measure: performance metrics present
    assert by_id["nist_rmf/NIST-MEASURE-1"]["status"] == "met"
    # HIPAA de-identification satisfied by dataset:anonymization
    assert by_id["hipaa/HIPAA-164.502-deidentification"]["status"] == "met"


def test_hipaa_flags_external_provider_for_baa(minimal_bom):
    """openai usage in the minimal BOM must raise the BAA requirement, not pass silently."""
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
    report = evaluate_compliance_dict(minimal_bom)
    by_id = {f"{fw}/{req['id']}": req for fw, req in _all_requirements(report)}
    baa = by_id["hipaa/HIPAA-164.314-BAA"]
    assert baa["status"] == "partial", f"expected partial, got {baa['status']}"
    assert "openai" in (baa.get("evidence") or "").lower()
    assert "BAA" in (baa.get("gap") or "")


def test_engine_deterministic(rich_bom, findings):
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
    a = evaluate_compliance_dict(rich_bom, findings)
    b = evaluate_compliance_dict(rich_bom, findings)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_framework_subset_selection(minimal_bom):
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
    report = evaluate_compliance_dict(minimal_bom, [], frameworks=["hipaa"])
    keys = {fw["framework_key"] for fw in report["frameworks"]}
    assert keys == {"hipaa"}


def test_handles_empty_bom():
    """An empty BOM must not crash; everything becomes a gap or not_applicable."""
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
    report = evaluate_compliance_dict({}, [])
    assert report["frameworks"]
    for fw_key, req in _all_requirements(report):
        assert req["status"] in VALID_STATUS


# ----------------------------- agent wiring -----------------------------

def test_agent_get_compliance_report_wired(rich_bom):
    """The AIBOMAgent must expose get_compliance_report() and normalize mixed-shape
    vulnerability objects (object / dict) into findings the engine consumes."""
    from helpers.tools.ai_bom_agent.main import AIBOMAgent

    agent = AIBOMAgent.__new__(AIBOMAgent)  # bypass __init__ (needs a clone context)
    agent.cyclonedx_aibom = rich_bom

    class _V:
        def __init__(self):
            self.risk_category = "unpinned_model_version"
            self.severity = "medium"

    agent.vulnerabilities = [_V(), {"risk_category": "exposed_api_key", "severity": "high"}]

    findings = agent._vulnerabilities_as_findings()
    assert {f["risk_category"] for f in findings} == {"unpinned_model_version", "exposed_api_key"}

    report = agent.get_compliance_report()
    assert report is not None
    assert report["disclaimer"].startswith("ADVISORY ONLY")
    assert {fw["framework_key"] for fw in report["frameworks"]} == ALL_FRAMEWORKS


def test_agent_get_compliance_report_none_when_no_bom():
    from helpers.tools.ai_bom_agent.main import AIBOMAgent
    agent = AIBOMAgent.__new__(AIBOMAgent)
    agent.cyclonedx_aibom = None
    assert agent.get_compliance_report() is None
