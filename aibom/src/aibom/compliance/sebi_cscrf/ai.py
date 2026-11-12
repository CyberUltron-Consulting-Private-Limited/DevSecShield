"""SEBI CSCRF AIBOM lane — honest software-inventory reading of models.

Registered under ``sebi_cscrf_aibom``. Imported from
:mod:`aibom.compliance.__init__` only (never CBOM/SBOM runners).

CIR/2024/113 has **no** AI/ML/AIBOM-specific controls. This lane maps
inventoryable model software facts to ID.AM / GV.SC.S5-style reading only.
Never invents fairness, training-data, or AI red-team SEBI controls.
"""

from __future__ import annotations

from aibom.compliance.base import (
    FAIL,
    NA,
    NOT_EVIDENCEABLE,
    PASS,
    CheckResult,
    Requirement,
    depends_on_frameworks,
    has_license,
    models,
    register_applicability,
    register_check,
    register_manual,
)
from aibom.compliance.sebi_cscrf.common import SEBI_DISCLAIMER, load_ledger
from aibom.model.component import ModelComponent
from aibom.model.result import ScanResult

_FW = "sebi_cscrf_aibom"
_SRC = "SEBI CSCRF CIR/2024/113"


def _refs(comps: list[ModelComponent]) -> list[str]:
    return [c.bom_ref for c in comps if c.bom_ref]


def _has_nonempty(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


register_applicability(
    _FW,
    lambda r: bool(models(r)),
    "no AI models detected; SEBI CSCRF AIBOM software-inventory reading does not apply",
)


def _req(rid: str, title: str, source: str) -> Requirement:
    return Requirement(rid, _FW, title, source)


R_INV = _req(
    "CSCRF-ID.AM.S1-inv",
    "Model software inventory name",
    f"{_SRC} ID.AM.S1",
)
R_VER = _req(
    "CSCRF-ID.AM.S1-ver",
    "Model software inventory version",
    f"{_SRC} ID.AM.S1 / GV.SC.S5",
)
R_DEP = _req(
    "CSCRF-GV.SC.S5-dep",
    "Framework dependencies named when edged",
    f"{_SRC} GV.SC.S5",
)
R_LIC = _req(
    "CSCRF-GV.SC.S5-lic",
    "Model license declared when inventoriable",
    f"{_SRC} GV.SC.S5(a)",
)
R_HASH = _req(
    "CSCRF-GV.SC.S5-hash",
    "Model integrity hash when inventoriable",
    f"{_SRC} GV.SC.S5(e)",
)


@register_check(R_INV)
def _inv(r: ScanResult, req: Requirement) -> CheckResult:
    mods = models(r)
    if not mods:
        return PASS("no models (applicability should OOS)")
    bad = [m for m in mods if not _has_nonempty(m.name)]
    if bad:
        return FAIL(
            f"{len(bad)}/{len(mods)} model(s) lack name",
            _refs(bad),
        )
    return PASS(f"all {len(mods)} model(s) named", _refs(mods))


@register_check(R_VER)
def _ver(r: ScanResult, req: Requirement) -> CheckResult:
    mods = models(r)
    if not mods:
        return PASS("no models (applicability should OOS)")
    bad = [m for m in mods if not _has_nonempty(m.version)]
    if bad:
        return FAIL(
            f"{len(bad)}/{len(mods)} model(s) lack version",
            _refs(bad),
        )
    return PASS(f"all {len(mods)} model(s) versioned", _refs(mods))


@register_check(R_DEP)
def _dep(r: ScanResult, req: Requirement) -> CheckResult:
    mods = models(r)
    if not mods:
        return PASS("no models")
    # NA when no framework dependency edges exist — do not invent deps.
    any_deps = any(depends_on_frameworks(r, m) for m in mods)
    if not any_deps:
        return NA(
            "no framework dependency edges on models; "
            "GV.SC.S5 dependency reading not applicable"
        )
    bad: list[ModelComponent] = []
    for m in mods:
        deps = depends_on_frameworks(r, m)
        if not deps:
            continue
        for d in deps:
            if not _has_nonempty(d.name):
                bad.append(m)
                break
    if bad:
        return FAIL(
            f"{len(bad)} model(s) have unnamed framework dependencies",
            _refs(bad),
        )
    return PASS("framework dependencies carry names where edged", _refs(mods))


@register_check(R_LIC)
def _lic(r: ScanResult, req: Requirement) -> CheckResult:
    mods = models(r)
    if not mods:
        return PASS("no models")
    present = [m for m in mods if has_license(m)]
    absent = [m for m in mods if not has_license(m)]
    if not absent:
        return PASS(f"all {len(mods)} model(s) declare license", _refs(mods))
    if present and absent:
        return NOT_EVIDENCEABLE(
            f"license not BOM-evidenceable for {len(absent)}/{len(mods)} "
            f"model(s) ({SEBI_DISCLAIMER})",
            _refs(absent),
        )
    return NOT_EVIDENCEABLE(
        f"model licenses not BOM-evidenceable from AI inventory ({SEBI_DISCLAIMER})",
        _refs(mods),
    )


def _model_hash(m: ModelComponent) -> str | None:
    props = m.properties or {}
    for key in ("hash", "sha256", "digest", "integrity", "sbom:hash", "ai:hash"):
        val = props.get(key)
        if _has_nonempty(val):
            return str(val).strip()
    # CycloneDX-style hashes attribute if present on component
    hashes = getattr(m, "hashes", None)
    if hashes:
        return "yes"
    return None


@register_check(R_HASH)
def _hash(r: ScanResult, req: Requirement) -> CheckResult:
    mods = models(r)
    if not mods:
        return PASS("no models")
    present = [m for m in mods if _model_hash(m)]
    absent = [m for m in mods if not _model_hash(m)]
    if not absent:
        return PASS(f"all {len(mods)} model(s) carry integrity hash", _refs(mods))
    if present and absent:
        return NOT_EVIDENCEABLE(
            f"hash not BOM-evidenceable for {len(absent)}/{len(mods)} "
            f"model(s) ({SEBI_DISCLAIMER})",
            _refs(absent),
        )
    return NOT_EVIDENCEABLE(
        f"model integrity hashes not BOM-evidenceable from AI inventory "
        f"({SEBI_DISCLAIMER})",
        _refs(mods),
    )


def _register_manuals() -> None:
    doc = load_ledger()
    for raw in doc.get("requirements") or []:
        if raw.get("lane") != "aibom" or raw.get("mode") != "manual":
            continue
        rid = str(raw["id"])
        req = Requirement(
            id=rid,
            framework=_FW,
            title=str(raw["title"]),
            source=str(raw.get("pdf") or _SRC),
        )
        register_manual(
            req,
            f"{SEBI_DISCLAIMER} Process attestation for {rid} "
            f"(organizational evidence; CIR has no AI-specific automated control).",
        )


_register_manuals()
