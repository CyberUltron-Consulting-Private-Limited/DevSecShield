"""
FDA FD&C Act §524B (cyber device SBOM mandate) + SaMD / PCCP readiness mapping.

§524B (added by the Dec 2022 Omnibus §3305; effective for submissions after
2023-03-29) requires a machine-readable SBOM of commercial/open-source/off-the-shelf
software components in premarket submissions for "cyber devices"; FDA may Refuse to
Accept a non-compliant submission. The current final guidance ("Cybersecurity in
Medical Devices...", 2025-06-27) references the NTIA Minimum Elements and FDA has
begun requesting VEX. For AI-enabled SaMD the SBOM is extended with the model/dataset
layer, and a PCCP (Predetermined Change Control Plan, final guidance 2024-12-03) may
pre-authorize model modifications.

This maps each requirement to fields the AI-BOM does (or should) carry. ADVISORY ONLY.
"""
from __future__ import annotations

from helpers.tools.ai_bom_agent.compliance import base as B
from helpers.tools.ai_bom_agent.compliance.base import (
    FrameworkReport,
    RequirementResult,
    register,
)

KEY = "fda_524b"
NAME = "FDA FD&C Act §524B (cyber-device SBOM) + SaMD/PCCP"
VERSION = "2025-06 final guidance / 2024-12 PCCP"


@register(KEY)
def evaluate(bom: dict, findings: list[dict]) -> FrameworkReport:
    comps = B.components(bom)
    libs = [c for c in comps if c.get("type") == "library"]
    reqs: list[RequirementResult] = []

    # --- §524B core: machine-readable SBOM of software components -----------
    reqs.append(RequirementResult(
        id="524B-1",
        title="Machine-readable SBOM of commercial/open-source/off-the-shelf software components",
        status="met" if libs else "partial",
        mapped_fields=["components[type=library]", "bomFormat", "specVersion"],
        evidence=(f"{len(libs)} software library component(s) inventoried in a CycloneDX 1.6 BOM"
                  if libs else "BOM emitted in CycloneDX 1.6 (machine-readable) but no library components detected"),
        gap=None if libs else "No library/dependency components inventoried — confirm the repo has dependency manifests.",
        recommendation=None if libs else "Ensure pip/npm/Maven/Go manifests are scanned so OTS components appear in the SBOM.",
    ))

    # --- NTIA minimum elements: supplier / component name / version --------
    named_versioned = [c for c in libs if c.get("version")]
    reqs.append(RequirementResult(
        id="524B-2",
        title="NTIA minimum elements: component name, version, supplier present",
        status=B.found("met", bool(libs) and len(named_versioned) == len(libs) and bool(libs),
                       present_status="met",
                       absent_status="partial" if libs else "gap"),
        mapped_fields=["components[].name", "components[].version", "components[].supplier", "components[].purl"],
        evidence=(f"{len(named_versioned)}/{len(libs)} libraries carry a version"
                  if libs else None),
        gap=(None if libs and len(named_versioned) == len(libs)
             else "Some components lack a pinned version — NTIA requires version + supplier per component."),
        recommendation="Resolve versions from lockfiles; populate supplier/purl for each OTS component.",
    ))

    # --- Component integrity: hashes ---------------------------------------
    reqs.append(RequirementResult(
        id="524B-3",
        title="Component integrity attestation (hashes) for model weights / artifacts",
        status="met" if B.any_component_has_hashes(bom) else "gap",
        mapped_fields=["components[].hashes"],
        evidence="At least one component carries a cryptographic hash" if B.any_component_has_hashes(bom) else None,
        gap=None if B.any_component_has_hashes(bom) else "No component hashes present (model-weight integrity not attested).",
        recommendation="Emit SHA-256 hashes for model weight files and pinned artifacts.",
    ))

    # --- Vulnerability / VEX referencing -----------------------------------
    reqs.append(RequirementResult(
        id="524B-4",
        title="Known-vulnerability referencing (NTIA/VEX) for inventoried components",
        status="partial" if B.has_vulnerability_data(bom, findings) else "gap",
        mapped_fields=["properties[aibom:risk-category]", "findings[].risk_category", "findings[].severity"],
        evidence=((f"{len(findings)} AI-risk finding(s) carried alongside the BOM"
                   if findings else "Per-component aibom:risk-category present")
                  if B.has_vulnerability_data(bom, findings) else None),
        gap="No VEX/VDR vulnerability document is emitted; risk is expressed as advisory finding categories only.",
        recommendation="Attach a CycloneDX VEX (vulnerabilities[]) and OSV/NVD CVE references per component.",
    ))

    # --- AI extension: model identity & provenance (SaMD) ------------------
    ml = B.models(bom)
    reqs.append(RequirementResult(
        id="524B-SaMD-1",
        title="AI model layer: each model identified with provider/version (SaMD inventory)",
        status="met" if ml else "not_applicable",
        mapped_fields=["components[type=machine-learning-model]", "properties[aibom:provider]", "version"],
        evidence=(f"{len(ml)} machine-learning-model component(s) inventoried" if ml else "No AI/ML models detected in repo"),
        gap=None,
        recommendation=None if ml else "If this is AI-enabled SaMD, ensure model files / provider SDK calls are detected.",
    ))

    # --- AI extension: model card (architecture, intended use) -------------
    has_card = B.any_model_has_modelcard(bom)
    has_considerations = B.any_model_has_considerations(bom)
    reqs.append(RequirementResult(
        id="524B-SaMD-2",
        title="Model card: architecture, intended use, limitations (SaMD device description)",
        status="partial" if has_card and not has_considerations else ("met" if has_considerations else ("gap" if ml else "not_applicable")),
        mapped_fields=["modelCard.modelParameters", "modelCard.considerations", "modelCard.quantitativeAnalysis"],
        evidence=("modelCard present on at least one model" if has_card else None),
        gap=(None if has_considerations else
             ("modelCard lacks considerations (intended users/use-cases/limitations) required for the SaMD device description."
              if ml else None)),
        recommendation=("Populate modelCard.considerations (intendedUse, users, technicalLimitations) and "
                        "quantitativeAnalysis (performance metrics) per the SaMD description."),
    ))

    # --- PCCP: predetermined change control plan reference -----------------
    has_pccp = B.bom_has_property(bom, "regulatory:pccp", "regulatory:fda_product_code", "regulatory:device_class")
    reqs.append(RequirementResult(
        id="524B-PCCP-1",
        title="PCCP / FDA product code / device class declared (predetermined change control)",
        status="met" if has_pccp else ("gap" if ml else "not_applicable"),
        mapped_fields=["metadata.properties[regulatory:fda_product_code]",
                       "metadata.properties[regulatory:device_class]",
                       "metadata.properties[regulatory:pccp]"],
        evidence="regulatory: namespaced device/PCCP property present" if has_pccp else None,
        gap=(None if has_pccp else
             ("No regulatory:fda_product_code / device_class / PCCP properties — device classification not declared."
              if ml else None)),
        recommendation=("Add metadata.properties regulatory:fda_product_code, regulatory:device_class, and a "
                        "regulatory:pccp reference (or externalReference to the authorized PCCP)."),
    ))

    return FrameworkReport(framework=NAME, framework_key=KEY, version=VERSION, requirements=reqs)
