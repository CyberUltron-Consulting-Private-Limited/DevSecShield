"""
Healthcare AI-BOM compliance-mapping layer — shared contract.

Each framework module (fda_524b, eu_ai_act_annexIV, gmlp, hipaa, nist_rmf) maps the
AI-BOM (a CycloneDX 1.6 ML-BOM dict + the enriched finding list) to a regulatory
framework: requirement -> mapped BOM field(s) -> evidence OR a flagged gap.

ADVISORY ONLY (hard rule): this mapping supports but does not satisfy regulatory
obligations; a human/legal/regulatory reviewer must sign off. Every report carries
the DISCLAIMER.

Pure functions only — no network, no I/O. Frameworks self-register via @register.
"""
from __future__ import annotations

import dataclasses
from typing import Callable, Literal

DISCLAIMER = (
    "ADVISORY ONLY — This AI-BOM compliance mapping creates visibility, not assurance. "
    "It supports but does not by itself satisfy FDA, EU AI Act, HIPAA, GMLP or NIST "
    "obligations. A qualified regulatory/legal reviewer must validate and sign off "
    "before any submission or attestation. (CISA: 'minimum elements create visibility, "
    "not assurance.')"
)

RequirementStatus = Literal["met", "partial", "gap", "not_applicable"]


@dataclasses.dataclass
class RequirementResult:
    id: str                       # stable requirement id, e.g. "AnnexIV-2(b)"
    title: str                    # human-readable requirement
    status: RequirementStatus
    mapped_fields: list[str] = dataclasses.field(default_factory=list)  # BOM paths consulted
    evidence: str | None = None   # what was found (when met/partial)
    gap: str | None = None        # what is missing (when partial/gap)
    recommendation: str | None = None

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class FrameworkReport:
    framework: str                # e.g. "FDA FD&C Act §524B (cyber device SBOM)"
    framework_key: str            # e.g. "fda_524b"
    version: str                  # mapping/table version (e.g. "2025-06 guidance")
    requirements: list[RequirementResult] = dataclasses.field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {"met": 0, "partial": 0, "gap": 0, "not_applicable": 0}
        for r in self.requirements:
            c[r.status] = c.get(r.status, 0) + 1
        return c

    @property
    def readiness_score(self) -> float:
        """0-100. met=1.0, partial=0.5, gap=0.0; not_applicable excluded from denominator."""
        scored = [r for r in self.requirements if r.status != "not_applicable"]
        if not scored:
            return 0.0
        pts = sum(1.0 if r.status == "met" else 0.5 if r.status == "partial" else 0.0 for r in scored)
        return round(100.0 * pts / len(scored), 1)

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "framework_key": self.framework_key,
            "version": self.version,
            "counts": self.counts,
            "readiness_score": self.readiness_score,
            "requirements": [r.to_dict() for r in self.requirements],
        }


@dataclasses.dataclass
class ComplianceReport:
    generated_from: str | None              # BOM serialNumber
    frameworks: list[FrameworkReport] = dataclasses.field(default_factory=list)
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict:
        return {
            "disclaimer": self.disclaimer,
            "generated_from": self.generated_from,
            "overall_readiness_score": round(
                sum(f.readiness_score for f in self.frameworks) / len(self.frameworks), 1
            ) if self.frameworks else 0.0,
            "frameworks": [f.to_dict() for f in self.frameworks],
        }


# (bom_dict, findings) -> FrameworkReport
Evaluator = Callable[[dict, list[dict]], FrameworkReport]
_REGISTRY: dict[str, Evaluator] = {}


def register(key: str) -> Callable[[Evaluator], Evaluator]:
    def deco(fn: Evaluator) -> Evaluator:
        _REGISTRY[key] = fn
        return fn
    return deco


def registry() -> dict[str, Evaluator]:
    return dict(_REGISTRY)


# --------------------------- BOM inspection helpers ---------------------------
# These read a CycloneDX 1.6 ML-BOM dict defensively (every field may be missing).

def components(bom: dict) -> list[dict]:
    return (bom or {}).get("components", []) or []


def models(bom: dict) -> list[dict]:
    return [c for c in components(bom) if c.get("type") == "machine-learning-model"]


def datasets(bom: dict) -> list[dict]:
    return [c for c in components(bom) if c.get("type") == "data"]


def metadata_properties(bom: dict) -> dict[str, str]:
    md = (bom or {}).get("metadata", {}) or {}
    return {p.get("name"): p.get("value") for p in (md.get("properties") or []) if p.get("name")}


def component_properties(comp: dict) -> dict[str, str]:
    return {p.get("name"): p.get("value") for p in (comp.get("properties") or []) if p.get("name")}


def model_card_properties(comp: dict) -> dict[str, str]:
    mc = comp.get("modelCard") or {}
    return {p.get("name"): p.get("value") for p in (mc.get("properties") or []) if p.get("name")}


def all_properties(bom: dict) -> dict[str, str]:
    """Every property name->value found anywhere in the BOM: metadata, each
    component's properties, and each model's modelCard.properties. Used to test
    presence of namespaced keys (clinical:/regulatory:/dataset:/aibom:) regardless
    of where the emitter placed them."""
    merged: dict[str, str] = {}
    merged.update(metadata_properties(bom))
    for c in components(bom):
        merged.update(component_properties(c))
        merged.update(model_card_properties(c))
    return merged


def has_property(props: dict[str, str], *prefixes_or_keys: str) -> bool:
    for k in props:
        for token in prefixes_or_keys:
            if k == token or k.startswith(token):
                return True
    return False


def bom_has_property(bom: dict, *prefixes_or_keys: str) -> bool:
    return has_property(all_properties(bom), *prefixes_or_keys)


def any_model_has_modelcard(bom: dict) -> bool:
    return any("modelCard" in m and m.get("modelCard") for m in models(bom))


def any_model_has_considerations(bom: dict) -> bool:
    return any((m.get("modelCard") or {}).get("considerations") for m in models(bom))


def any_model_has_metrics(bom: dict) -> bool:
    return any((m.get("modelCard") or {}).get("quantitativeAnalysis") for m in models(bom))


def any_model_has_parameters(bom: dict) -> bool:
    return any((m.get("modelCard") or {}).get("modelParameters") for m in models(bom))


def any_component_has_license(bom: dict) -> bool:
    return any(c.get("licenses") for c in components(bom))


def any_component_has_hashes(bom: dict) -> bool:
    return any(c.get("hashes") for c in components(bom))


def any_component_has_version(bom: dict) -> bool:
    return any(c.get("version") for c in components(bom))


def any_component_has_evidence(bom: dict) -> bool:
    return any(c.get("evidence") for c in components(bom))


def any_external_references(bom: dict) -> bool:
    if (bom.get("metadata") or {}).get("component", {}).get("externalReferences"):
        return True
    return any(c.get("externalReferences") for c in components(bom))


def has_dependencies(bom: dict) -> bool:
    return bool((bom or {}).get("dependencies"))


def tool_info(bom: dict) -> bool:
    """G7/CISA Metadata cluster: generation tool name+version present."""
    tools = (bom.get("metadata") or {}).get("tools") or {}
    comps = tools.get("components") if isinstance(tools, dict) else None
    return bool(comps) and any(c.get("name") for c in comps)


def has_timestamp(bom: dict) -> bool:
    return bool((bom.get("metadata") or {}).get("timestamp"))


def findings_with_category(findings: list[dict], *categories: str) -> list[dict]:
    out = []
    for f in findings or []:
        cat = (f.get("risk_category") or f.get("category") or "").lower()
        for c in categories:
            if c.lower() in cat:
                out.append(f)
                break
    return out


def has_vulnerability_data(bom: dict, findings: list[dict]) -> bool:
    """Security Properties / vulnerability referencing: the AI-BOM carries risk
    categories on components, and findings carry remediation/severity."""
    if bom_has_property(bom, "aibom:risk-category"):
        return True
    return bool(findings)


def found(status_when_present: RequirementStatus, condition: bool,
          present_status: RequirementStatus = "met",
          absent_status: RequirementStatus = "gap") -> RequirementStatus:
    return present_status if condition else absent_status
