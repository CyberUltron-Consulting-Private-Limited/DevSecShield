"""Run the registered checks and assemble ``ScanResult.compliance``.

Coverage rule (``aibom/contract/coverage``): ``coverage = pass / (pass + fail)``;
**NA is excluded from the denominator** and reported as a separate count. When a
framework has zero applicable (pass+fail) checks — e.g. HIPAA on a no-PHI BOM —
coverage is ``None`` (not 0), so an inapplicable framework never reads as a
0% failure.
"""

from __future__ import annotations

from typing import Any

from aibom.compliance.base import (
    ADVISORY_DISCLAIMER,
    CheckResult,
    applicability_for,
    checks_for,
)
from aibom.model.result import ScanResult

# Canonical framework keys (must match Requirement.framework) + CLI aliases.
FRAMEWORKS = [
    "fda_524b",
    "eu_ai_act_annexIV",
    "gmlp",
    "hipaa",
    "nist_rmf",
    "rbi_free_ai",
    "cert_in_aibom",
    "sebi_cscrf_aibom",
]
ALIASES = {
    "fda524b": "fda_524b",
    "euaiact": "eu_ai_act_annexIV",
    "gmlp": "gmlp",
    "hipaa": "hipaa",
    "nist": "nist_rmf",
    "rbi": "rbi_free_ai",
    "freeai": "rbi_free_ai",
}


def resolve_framework(name: str) -> str:
    """Map a CLI alias (or canonical key) to the canonical framework key."""
    if name in FRAMEWORKS:
        return name
    if name in ALIASES:
        return ALIASES[name]
    raise KeyError(f"unknown framework {name!r}; choose: {', '.join(ALIASES)} | all")


#: The five distinct verdict states (coverage uses pass + pass_with_evidence).
_STATES = (
    "pass",
    "pass_with_evidence",
    "fail",
    "out_of_scope",
    "not_bom_evidenceable",
    "na",
)


def run_framework(
    result: ScanResult,
    framework: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one framework; return {pass, pass_with_evidence, fail, out_of_scope,
    not_bom_evidenceable, na, coverage, requirements}.

    APPLICABILITY: if the framework's predicate is False (e.g. GMLP on an artifact
    with no clinical model), EVERY requirement is ``out_of_scope`` — never fail,
    never a generic na. EVIDENCE: an uploaded attestation keyed by requirement id
    flips a ``not_bom_evidenceable`` verdict to ``pass_with_evidence``.
    """
    evidence = evidence or {}
    gate = applicability_for(framework)
    oos_reason = gate[1] if (gate is not None and not gate[0](result)) else None

    counts = dict.fromkeys(_STATES, 0)
    requirements: list[dict[str, Any]] = []
    for requirement, check in checks_for(framework):
        if oos_reason is not None:
            cr = CheckResult("out_of_scope", oos_reason)
        else:
            cr = check(result, requirement)
            if cr.verdict == "not_bom_evidenceable" and requirement.id in evidence:
                cr = CheckResult(
                    "pass_with_evidence",
                    f"attested: {evidence[requirement.id]}",
                    cr.refs,
                )
        counts[cr.verdict] = counts.get(cr.verdict, 0) + 1
        requirements.append(
            {
                "id": requirement.id,
                "title": requirement.title,
                "source": requirement.source,
                "verdict": cr.verdict,
                "evidence": cr.evidence,
                "refs": list(cr.refs),
                "attestable": cr.verdict
                in ("not_bom_evidenceable", "pass_with_evidence"),
            }
        )
    n_pass = counts["pass"] + counts["pass_with_evidence"]  # evidence counts as pass
    applicable = n_pass + counts["fail"]
    coverage = round(n_pass / applicable, 3) if applicable else None
    return {
        "pass": counts["pass"],
        "pass_with_evidence": counts["pass_with_evidence"],
        "fail": counts["fail"],
        "out_of_scope": counts["out_of_scope"],
        "not_bom_evidenceable": counts["not_bom_evidenceable"],
        "na": counts["na"],
        "coverage": coverage,  # pass/(pass+fail); None when 0 applicable
        "requirements": requirements,
    }


def run_all(
    result: ScanResult, evidence: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Run every framework, write ``result.compliance`` in place, and return it.

    ``evidence`` is an optional ``{framework: {requirement_id: attestation}}`` map
    of uploaded attestations that flip ``not_bom_evidenceable`` requirements to
    ``pass_with_evidence``. Importing :mod:`aibom.compliance` self-registers all
    five framework modules before this runs.
    """
    evidence = evidence or {}
    report: dict[str, Any] = {
        fw: run_framework(result, fw, evidence.get(fw)) for fw in FRAMEWORKS
    }
    report["disclaimer"] = ADVISORY_DISCLAIMER
    result.compliance = report
    return report


__all__ = ["FRAMEWORKS", "ALIASES", "resolve_framework", "run_framework", "run_all"]
