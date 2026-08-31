"""DevSecShield native-scanner adapter: ScanResult -> locked result schema.

Exercises the REAL engine (scan_repo + compliance) on real fixtures and asserts
the normalized run-object matches the locked DevSecShield contract
(``devsecshield/contract/result-schema``). Nothing is mocked — the adapter is a
pure consumer of a real ScanResult. Enum value-sets mirror the worker's
``helpers/context/enums.py`` (AIComponentVulnerability target schema); the worker
package is not importable here, so the canonical sets are pinned in this test and
re-verified by the adversarial review against the live worker enums.
"""

from __future__ import annotations

import pathlib

from aibom.emit.validate import validate_auto
from aibom.integrations.devsecshield import (
    normalize,
    run_native_scan,
    scan_to_devsecshield,
)

_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"
_CLINICAL = _EX / "clinical-imaging"
_SHADOW = _EX / "shadow-demo"
_MULTISITE = _EX / "multi-site"
_ALLOW = pathlib.Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"

# Mirror of RabbitMQ/worker/helpers/context/enums.py (the normalize() target).
_IMPACT = {"Low", "Medium", "High", "Critical"}
_AI_COMPONENT_TYPE = {
    "local_model_file", "external_provider", "huggingface_model", "ml_framework",
    "ai_framework", "dataset", "prompt_asset", "embedding_model",
}
_MODEL_PROVIDER = {
    "openai", "anthropic", "bedrock", "vertex", "cohere", "mistral",
    "huggingface", "local", "pypi", "unknown",
}
_AI_RISK_CATEGORY = {
    "untrusted_model_deserialization", "unpinned_model_version",
    "deprecated_eol_model", "missing_model_card_lineage",
    "license_compliance_gap", "data_privacy_training_config",
    "model_theft_exposure",
}

# Required by AIComponentVulnerability (BaseVulnerability + AI-BOM fields).
_FINDING_FIELDS = {
    "title", "description", "impact", "owasp_top_10", "compliance_controls",
    "suggested_fix", "component_name", "component_type", "framework", "version",
    "source", "license", "location", "snippet", "risk_category",
    "owasp_top_10_llm", "model_card",
}
_LOCKED_KEYS = {"results", "ai_bom_json", "ai_bom_compliance", "duration_of_scan"}
_ADDITIVE_KEYS = {"ai_bom_spdx", "ai_bom_sarif", "ai_bom_graph", "ai_bom_scores"}


def _run(path, **kw) -> dict:
    return scan_to_devsecshield(path, **kw)


# --------------------------------------------------------------------------- #
# Run-object shape: the locked keys + the additive ones are all present.
# --------------------------------------------------------------------------- #


def test_run_object_has_locked_and_additive_keys() -> None:
    out = _run(_CLINICAL)
    assert set(out) >= _LOCKED_KEYS
    assert set(out) >= _ADDITIVE_KEYS
    assert isinstance(out["results"], list)
    assert isinstance(out["duration_of_scan"], float)


# --------------------------------------------------------------------------- #
# Findings: one per flag, each matching the AIComponentVulnerability schema.
# --------------------------------------------------------------------------- #


def test_every_finding_matches_the_locked_finding_schema() -> None:
    out = _run(_SHADOW, level=4, allowlist=_ALLOW)
    assert out["results"], "shadow-demo must yield findings"
    for f in out["results"]:
        assert set(f) == _FINDING_FIELDS, f"finding keys drift: {set(f)}"
        assert f["impact"] in _IMPACT
        assert f["component_type"] in _AI_COMPONENT_TYPE
        assert f["source"] in _MODEL_PROVIDER
        assert f["risk_category"] in _AI_RISK_CATEGORY
        assert isinstance(f["owasp_top_10"], list)
        # owasp_top_10_llm is the SERIALIZED platform shape: {ENUM_NAME: label}
        # (the worker's base_vuln dumps list[OWASPTop10LLM] -> dict, and the
        # backend dashboard reads it via .items()). A list would crash the
        # dashboard's aggregation, so the stored contract is a dict.
        assert isinstance(f["owasp_top_10_llm"], dict)
        assert isinstance(f["compliance_controls"], list)
        # str|None scalar fields must never leak a dict/object (worker schema).
        for scalar in ("framework", "version", "license", "location", "snippet"):
            assert f[scalar] is None or isinstance(f[scalar], str), scalar


def test_license_is_flattened_to_a_string() -> None:
    out = _run(_CLINICAL)
    licensed = [f for f in out["results"] if f["license"] is not None]
    assert licensed, "clinical-imaging model carries a license"
    for f in licensed:
        assert isinstance(f["license"], str)  # not a CycloneDX dict
        assert "{" not in f["license"]


def test_findings_are_the_component_inventory() -> None:
    result = run_native_scan(_SHADOW, level=4, allowlist=_ALLOW)
    out = normalize(result, duration_of_scan=0.0)
    # One finding per COMPONENT — the dashboard counts results[] as AI assets
    # (total_ai_assets = len(results)), so the inventory unit is the component.
    assert len(out["results"]) == len(result.components)
    assert len(out["results"]) > 0
    # The 5 shadow UNSANCTIONED components surface as >= Medium-impact findings
    # (UNSANCTIONED_COMPONENT=6 -> medium under the recalibrated scorer; stacking
    # with other flags may elevate further, but never below medium).
    flagged = [
        f for f in out["results"] if f["impact"] in ("Medium", "High", "Critical")
    ]
    assert len(flagged) >= 5


def test_clinical_imaging_findings_carry_component_metadata() -> None:
    out = _run(_CLINICAL)
    assert out["results"]
    # PHI / EU-AI-Act risks attach to the model component, not a blank target.
    names = {f["component_name"] for f in out["results"]}
    assert all(n for n in names)  # no empty component names


# --------------------------------------------------------------------------- #
# Edges + compliance must survive normalization (frontend needs them).
# --------------------------------------------------------------------------- #


def test_edges_preserved_in_graph() -> None:
    result = run_native_scan(_MULTISITE)
    out = normalize(result, duration_of_scan=0.0)
    graph = out["ai_bom_graph"]
    assert {n["id"] for n in graph["nodes"]} == {c.bom_ref for c in result.components}
    assert len(graph["edges"]) == len(result.edges)
    rels = {e["rel"] for e in graph["edges"]}
    assert "deployed_at" in rels  # multi-site per-site edges survive


def test_compliance_pass_fail_na_preserved() -> None:
    out = _run(_CLINICAL)
    comp = out["ai_bom_compliance"]
    frameworks = [k for k in comp if k != "disclaimer"]
    assert frameworks
    for fw in frameworks:
        assert {"pass", "fail", "na"} <= set(comp[fw])


def test_scores_carry_band_and_normalized() -> None:
    out = _run(_SHADOW, level=4, allowlist=_ALLOW)
    assert {"risk_normalized", "risk_band"} <= set(out["ai_bom_scores"])


# --------------------------------------------------------------------------- #
# Raw BOM artifacts: present, downloadable, and schema-valid.
# --------------------------------------------------------------------------- #


def test_raw_bom_artifacts_present_and_cyclonedx_valid() -> None:
    out = _run(_CLINICAL)
    assert isinstance(out["ai_bom_json"], dict) and out["ai_bom_json"]
    assert isinstance(out["ai_bom_spdx"], dict) and out["ai_bom_spdx"]
    assert isinstance(out["ai_bom_sarif"], dict) and out["ai_bom_sarif"]
    fmt, errors = validate_auto(out["ai_bom_json"])
    assert fmt == "cyclonedx" and errors == []


# --------------------------------------------------------------------------- #
# Determinism (the engine + normalizer are pure; duration is the only variable).
# --------------------------------------------------------------------------- #


def test_normalize_is_deterministic() -> None:
    r1 = run_native_scan(_SHADOW, level=4, allowlist=_ALLOW)
    r2 = run_native_scan(_SHADOW, level=4, allowlist=_ALLOW)
    assert normalize(r1, duration_of_scan=0.0) == normalize(r2, duration_of_scan=0.0)


def test_provider_matches_production_buckets() -> None:
    """Provider is vendor, then local model, then pkg:pypi/ — not kind=framework."""
    from aibom.integrations.devsecshield import _provider

    assert _provider(None, "torch", "framework", "pkg:pypi/torch@2.3") == "pypi"
    assert _provider(None, "langchain", "framework", None) == "unknown"
    assert _provider(None, "weights.bin", "model", None) == "local"
    assert _provider(None, "openai", "framework", "pkg:pypi/openai") == "openai"
    assert _provider(None, "anthropic", "service", None) == "anthropic"
    assert _provider(None, "custom-endpoint", "service", None) == "unknown"


def test_scan_to_devsecshield_persists_deterministic_source() -> None:
    """Same scanner input → same results[].source (purl-based PyPI, vendor first)."""
    synthetic = pathlib.Path(__file__).resolve().parent / "fixtures" / "synthetic"
    clinical = _CLINICAL

    syn = {r["component_name"]: r["source"] for r in scan_to_devsecshield(synthetic, level=4)["results"]}
    assert syn["torch"] == "pypi"
    assert syn["numpy"] == "pypi"
    assert syn["langchain"] == "pypi"
    assert syn["openai"] == "openai"
    assert syn["anthropic"] == "anthropic"

    clin = {r["component_name"]: r["source"] for r in scan_to_devsecshield(clinical, level=4)["results"]}
    assert clin["chestxr-nodule-detector"] == "local"
    assert clin["chestxr-training-cohort"] == "unknown"
