"""IMDRF Good Machine Learning Practice — N88 Final (Jan 2025), 10 principles.

Seven principles anchor to graph facts (pass/fail); the three that require
process evidence (multidisciplinary teams, train/test independence, reference-
dataset methodology) return NA. Never reads flags.
"""

from __future__ import annotations

from aibom.compliance.base import (
    FAIL,
    NA,
    PASS,
    CheckResult,
    Requirement,
    clinical_models,
    deployed_sites,
    has_license,
    register_applicability,
    register_check,
    register_manual,
    trained_datasets,
)
from aibom.model.result import ScanResult

_FW = "gmlp"
_SRC = "IMDRF/AIML WG/N88 Final:2025"


def _r(rid: str, title: str) -> Requirement:
    return Requirement(rid, _FW, title, _SRC)


R2 = _r("GMLP-2", "Good software engineering + security practices")
R3 = _r("GMLP-3", "Representative training datasets")
R6 = _r("GMLP-6", "Model design tailored to data + intended use")
R7 = _r("GMLP-7", "Focus on human-AI team performance")
R8 = _r("GMLP-8", "Clinically relevant testing (subgroup metrics)")
R9 = _r("GMLP-9", "Clear, essential information to users")
R10 = _r("GMLP-10", "Deployed models monitored for performance/drift")


@register_check(R2)
def _p2(r: ScanResult, req: Requirement) -> CheckResult:
    ms = clinical_models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not (m.hashes and has_license(m))]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack integrity hash or license", bad)
    return PASS("every model has integrity hash + license", [m.bom_ref for m in ms])


@register_check(R3)
def _p3(r: ScanResult, req: Requirement) -> CheckResult:
    ms = clinical_models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not trained_datasets(r, m)
        or any(not d.provenance for d in trained_datasets(r, m))
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack provenanced training datasets", bad)
    return PASS("training datasets are provenanced", [m.bom_ref for m in ms])


@register_check(R6)
def _p6(r: ScanResult, req: Requirement) -> CheckResult:
    ms = clinical_models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (m.model_card.intended_use and m.model_card.model_architecture)
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack intended-use or architecture", bad)
    return PASS(
        "model design ties architecture to intended use", [m.bom_ref for m in ms]
    )


@register_check(R7)
def _p7(r: ScanResult, req: Requirement) -> CheckResult:
    ms = clinical_models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (m.model_card.considerations and m.model_card.considerations.users)
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) document no intended users / team", bad)
    return PASS(
        "every model documents its human-AI team / users", [m.bom_ref for m in ms]
    )


@register_check(R8)
def _p8(r: ScanResult, req: Requirement) -> CheckResult:
    ms = clinical_models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not any(pm.slice for pm in m.model_card.performance_metrics)
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) report no subgroup-sliced metrics", bad)
    return PASS(
        "clinically-relevant subgroup metrics reported", [m.bom_ref for m in ms]
    )


@register_check(R9)
def _p9(r: ScanResult, req: Requirement) -> CheckResult:
    ms = clinical_models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (
            m.version
            and any(ref.type == "model-card" for ref in (m.external_references or []))
        )
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack a versioned user-facing model card", bad)
    return PASS(
        "every model links a versioned model card for users", [m.bom_ref for m in ms]
    )


@register_check(R10)
def _p10(r: ScanResult, req: Requirement) -> CheckResult:
    ms = clinical_models(r)
    deployed = [m for m in ms if deployed_sites(r, m)]
    if not deployed:
        return NA("no deployed models (deployed_at) to monitor for drift")
    bad = [
        m.bom_ref
        for m in deployed
        if any(
            not (s.properties or {}).get("site:drift_status")
            for s in deployed_sites(r, m)
        )
    ]
    if bad:
        return FAIL(f"{len(bad)} deployed model(s) lack site drift status", bad)
    return PASS(
        "every deployment site reports drift status", [m.bom_ref for m in deployed]
    )


register_manual(
    _r("GMLP-1", "Multidisciplinary expertise across the TPLC"),
    "multidisciplinary expertise is process evidence, not BOM-modelled",
)
register_manual(
    _r("GMLP-4", "Training/test set independence"),
    "train/test independence is not modelled (no test-set component)",
)
register_manual(
    _r("GMLP-5", "Reference datasets use best available methods"),
    "reference-dataset methodology is process evidence, not BOM-modelled",
)

# GMLP is Good Machine Learning Practice for MEDICAL-DEVICE AI (SaMD). It does not
# apply to a generic AI artifact (e.g. a vector DB + embedding models); there it is
# out_of_scope, NOT fail.
register_applicability(
    _FW,
    lambda r: bool(clinical_models(r)),
    "GMLP applies to medical-device ML (SaMD); this artifact has no clinical model",
)
