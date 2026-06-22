"""IMDRF Good Machine Learning Practice — N88 Final (Jan 2025), 10 principles.

Each principle either anchors to a graph fact (pass/fail) or, when it requires
process evidence the AI-BOM cannot carry (multidisciplinary teams, train/test
independence, reference-dataset methodology), returns ``na`` with an advisory
note — honest per the coverage rule, never a false pass. Never reads flags.
"""

from __future__ import annotations

from aibom.compliance.base import (
    FAIL,
    NA,
    PASS,
    CheckResult,
    Requirement,
    deployed_sites,
    has_license,
    human_in_the_loop,
    models,
    register_check,
    trained_datasets,
)
from aibom.model.result import ScanResult

_FW = "gmlp"


def _req(rid: str, title: str) -> Requirement:
    return Requirement(rid, _FW, title, "IMDRF/AIML WG/N88 Final:2025")


R1 = _req("GMLP-1", "Multidisciplinary expertise across the TPLC")
R2 = _req("GMLP-2", "Good software engineering + security practices")
R3 = _req("GMLP-3", "Representative training datasets")
R4 = _req("GMLP-4", "Training/test set independence")
R5 = _req("GMLP-5", "Reference datasets use best available methods")
R6 = _req("GMLP-6", "Model design tailored to data + intended use")
R7 = _req("GMLP-7", "Focus on human-AI team performance")
R8 = _req("GMLP-8", "Clinically relevant testing")
R9 = _req("GMLP-9", "Clear, essential information to users")
R10 = _req("GMLP-10", "Deployed models monitored for performance/drift")


@register_check(R1)
def _p1(r: ScanResult, req: Requirement) -> CheckResult:
    return NA("multidisciplinary expertise is process evidence, not BOM-modelled")


@register_check(R2)
def _p2(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not (m.hashes and has_license(m))]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack integrity hash or license", bad)
    return PASS("every model has an integrity hash + license", [m.bom_ref for m in ms])


@register_check(R3)
def _p3(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    failures: list[str] = []
    for m in ms:
        ds = trained_datasets(r, m)
        if not ds or any(not (d.known_bias and d.provenance) for d in ds):
            failures.append(m.bom_ref)
    if failures:
        return FAIL(
            f"{len(failures)} model(s) lack documented dataset bias/provenance",
            failures,
        )
    return PASS("training datasets document known bias + provenance",
                [m.bom_ref for m in ms])


@register_check(R4)
def _p4(r: ScanResult, req: Requirement) -> CheckResult:
    return NA("train/test split is not modelled (no test-set component)")


@register_check(R5)
def _p5(r: ScanResult, req: Requirement) -> CheckResult:
    return NA("reference-dataset methodology is process evidence, not BOM-modelled")


@register_check(R6)
def _p6(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (m.model_card.intended_use and m.model_card.model_architecture)
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack intended-use or architecture", bad)
    return PASS("model design ties architecture to intended use",
                [m.bom_ref for m in ms])


@register_check(R7)
def _p7(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not human_in_the_loop(m)]
    if bad:
        return FAIL(f"{len(bad)} model(s) name no human-AI team", bad)
    return PASS("every model documents a human-AI team", [m.bom_ref for m in ms])


@register_check(R8)
def _p8(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not any(pm.slice for pm in m.model_card.performance_metrics)
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) report no subgroup-sliced metrics", bad)
    return PASS("clinically-relevant subgroup metrics reported",
                [m.bom_ref for m in ms])


@register_check(R9)
def _p9(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not any(
            ref.type == "model-card" for ref in (m.external_references or [])
        )
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) link no model card for users", bad)
    return PASS("every model links a model card for users", [m.bom_ref for m in ms])


@register_check(R10)
def _p10(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    deployed = [m for m in ms if deployed_sites(r, m)]
    if not deployed:
        return NA("no deployed models (deployed_at) to monitor for drift")
    bad: list[str] = []
    for m in deployed:
        if any(
            not (s.properties or {}).get("site:drift_status")
            for s in deployed_sites(r, m)
        ):
            bad.append(m.bom_ref)
    if bad:
        return FAIL(f"{len(bad)} deployed model(s) lack site drift status", bad)
    return PASS("every deployment site reports drift status",
                [m.bom_ref for m in deployed])
