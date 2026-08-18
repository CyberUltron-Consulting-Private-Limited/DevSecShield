"""CERT-In AIBOM lane checks — Table 10 auto + §9.4.1 manuals (Phase 2).

Registered under framework key ``cert_in_aibom``. Imported by
:mod:`aibom.compliance.__init__` for side-effect registration so
:func:`aibom.compliance.engine.run_all` includes it.

Checks read the GRAPH (ModelComponent / model_card / edges) only —
never ``result.flags``. Missing inventable facts → NBE (never invent).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aibom.compliance.base import (
    FAIL,
    NOT_EVIDENCEABLE,
    PASS,
    CheckResult,
    Requirement,
    depends_on_frameworks,
    deployed_sites,
    has_license,
    models,
    register_applicability,
    register_check,
    register_manual,
    trained_datasets,
)
from aibom.compliance.cert_in.common import CERTIN_DISCLAIMER, load_ledger
from aibom.compliance.cert_in.predicates import has_nonempty
from aibom.model.component import ModelComponent
from aibom.model.result import ScanResult

_FW = "cert_in_aibom"

register_applicability(
    _FW,
    lambda r: bool(models(r)),
    "no AI models detected; CERT-In AIBOM guidelines do not apply",
)


def _refs(comps: list[ModelComponent]) -> list[str]:
    return [c.bom_ref for c in comps if c.bom_ref]


def _mc(m: ModelComponent) -> Any:
    return m.model_card


def _field_value(r: ScanResult, m: ModelComponent, rid: str) -> Any:
    """Resolve a Table-10 field off a model (graph-only)."""
    mc = _mc(m)
    if rid == "T10-Model-Name":
        return m.name
    if rid == "T10-Model-Version":
        return m.version
    if rid == "T10-Model-Licensing-Information":
        return "yes" if has_license(m) else None
    if rid == "T10-Software-Dependencies":
        deps = depends_on_frameworks(r, m)
        return deps if deps else None
    if rid == "T10-Model-Type":
        return mc.task or mc.approach_type or mc.architecture_family
    if rid == "T10-Model-Developer":
        return m.publisher
    if rid == "T10-ML-Models-and-Algorithms":
        return mc.model_architecture or mc.architecture_family or mc.approach_type
    if rid == "T10-Model-Performance-Metrics":
        return mc.performance_metrics or None
    if rid == "T10-Data-Sets":
        ds = trained_datasets(r, m)
        return ds if ds else (mc.datasets or None)
    if rid == "T10-Data-Source":
        ds = trained_datasets(r, m)
        if not ds:
            return None
        for d in ds:
            # provenance / availability / name are inventable dataset facts
            if has_nonempty(getattr(d, "provenance", None)) or has_nonempty(
                getattr(d, "availability", None)
            ) or has_nonempty(d.name):
                return d.name or getattr(d, "provenance", None)
        return None
    if rid == "T10-Hardware":
        sites = deployed_sites(r, m)
        return sites if sites else None
    if rid == "T10-Security-Requirements":
        props = m.properties or {}
        for k, v in props.items():
            if "security" in k.lower() or "encrypt" in k.lower():
                if has_nonempty(v):
                    return v
        return None
    if rid == "T10-Input":
        return mc.inputs or None
    if rid == "T10-Output":
        return mc.outputs or None
    if rid == "T10-Intended-Usage":
        return mc.intended_use
    if rid == "T10-Out-of-Scope-Usage":
        cons = mc.considerations
        if cons is None:
            return None
        # Considerations may carry use_limitations / prohibited use lists
        for attr in ("use_limitations", "technical_limitations", "out_of_scope"):
            val = getattr(cons, attr, None)
            if has_nonempty(val):
                return val
        return None
    if rid == "T10-Environmental-Impact":
        props = m.properties or {}
        for k, v in props.items():
            if any(t in k.lower() for t in ("energy", "carbon", "environmental")):
                if has_nonempty(v):
                    return v
        return None
    if rid == "T10-Vulnerabilities":
        # Never invent CVE lists from flags — only explicit graph props.
        props = m.properties or {}
        for k, v in props.items():
            if "vuln" in k.lower() or "cve" in k.lower():
                if has_nonempty(v):
                    return v
        return None
    if rid == "T10-Attestations":
        props = m.properties or {}
        for k, v in props.items():
            if "attest" in k.lower() or "signature" in k.lower():
                if has_nonempty(v):
                    return v
        return None
    return None


def _make_auto_check(
    *,
    missing: str,
    rid: str,
) -> Callable[[ScanResult, Requirement], CheckResult]:
    def _check(r: ScanResult, req: Requirement) -> CheckResult:
        mods = models(r)
        # Applicability already OOS when no models; defensive vacuous PASS.
        if not mods:
            return PASS(f"no models; {rid} vacuously satisfied")

        present: list[ModelComponent] = []
        absent: list[ModelComponent] = []
        for m in mods:
            if has_nonempty(_field_value(r, m, rid)):
                present.append(m)
            else:
                absent.append(m)

        if missing == "nbe":
            if not absent:
                return PASS(
                    f"all {len(mods)} model(s) carry {rid}",
                    _refs(mods),
                )
            if present and absent:
                return NOT_EVIDENCEABLE(
                    f"{rid}: {len(absent)}/{len(mods)} model(s) lack inventable "
                    f"evidence; unknown → not BOM-evidenceable ({CERTIN_DISCLAIMER})",
                    _refs(absent),
                )
            return NOT_EVIDENCEABLE(
                f"{rid}: not BOM-evidenceable from static AI inventory "
                f"({CERTIN_DISCLAIMER})",
                _refs(mods),
            )

        # fail-missing
        if absent:
            return FAIL(
                f"{rid}: {len(absent)}/{len(mods)} model(s) lack required field",
                _refs(absent),
            )
        return PASS(f"all {len(mods)} model(s) satisfy {rid}", _refs(mods))

    _check.__name__ = f"_certin_{rid.replace('.', '_').replace('-', '_')}"
    _check.__qualname__ = _check.__name__
    return _check


def _register_from_ledger() -> None:
    doc = load_ledger()
    for raw in doc.get("requirements") or []:
        rid = str(raw.get("id") or "")
        mode = str(raw.get("mode") or "")
        missing = str(raw.get("missing") or "fail")
        title = str(raw.get("title") or rid)
        source = str(raw.get("pdf") or "CERT-In TG v2.0")

        if mode == "manual" and rid.startswith("9.4.1."):
            req = Requirement(
                id=rid,
                framework=_FW,
                title=title,
                source=source,
            )
            register_manual(
                req,
                f"{CERTIN_DISCLAIMER} Process attestation for {rid}: "
                f"{raw.get('description') or raw.get('evidence_hint') or 'organizational evidence'}.",
            )
            continue

        if mode != "auto" or not rid.startswith("T10-"):
            continue

        req = Requirement(
            id=rid,
            framework=_FW,
            title=title,
            source=source,
        )
        register_check(req)(
            _make_auto_check(missing=missing, rid=rid)
        )


_register_from_ledger()
