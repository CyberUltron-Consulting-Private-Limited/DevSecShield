"""Run the registered checks and assemble ``ScanResult.compliance``.

Coverage rule (``aibom/contract/coverage``): ``coverage = pass / (pass + fail)``;
**NA is excluded from the denominator** and reported as a separate count. When a
framework has zero applicable (pass+fail) checks — e.g. HIPAA on a no-PHI BOM —
coverage is ``None`` (not 0), so an inapplicable framework never reads as a
0% failure.
"""

from __future__ import annotations

from typing import Any

from aibom.compliance.base import ADVISORY_DISCLAIMER, checks_for
from aibom.model.result import ScanResult

# Canonical framework keys (must match Requirement.framework) + CLI aliases.
FRAMEWORKS = ["fda_524b", "eu_ai_act_annexIV", "gmlp", "hipaa", "nist_rmf"]
ALIASES = {
    "fda524b": "fda_524b",
    "euaiact": "eu_ai_act_annexIV",
    "gmlp": "gmlp",
    "hipaa": "hipaa",
    "nist": "nist_rmf",
}


def resolve_framework(name: str) -> str:
    """Map a CLI alias (or canonical key) to the canonical framework key."""
    if name in FRAMEWORKS:
        return name
    if name in ALIASES:
        return ALIASES[name]
    raise KeyError(
        f"unknown framework {name!r}; choose: {', '.join(ALIASES)} | all"
    )


def run_framework(result: ScanResult, framework: str) -> dict[str, Any]:
    """Run one framework's checks; return its {pass,fail,na,coverage,requirements}."""
    n_pass = n_fail = n_na = 0
    requirements: list[dict[str, Any]] = []
    for requirement, check in checks_for(framework):
        cr = check(result, requirement)
        if cr.verdict == "pass":
            n_pass += 1
        elif cr.verdict == "fail":
            n_fail += 1
        else:
            n_na += 1
        requirements.append(
            {
                "id": requirement.id,
                "title": requirement.title,
                "source": requirement.source,
                "verdict": cr.verdict,
                "evidence": cr.evidence,
                "refs": list(cr.refs),
            }
        )
    applicable = n_pass + n_fail
    coverage = round(n_pass / applicable, 3) if applicable else None
    return {
        "pass": n_pass,
        "fail": n_fail,
        "na": n_na,
        "coverage": coverage,  # None when 0 applicable
        "requirements": requirements,
    }


def run_all(result: ScanResult) -> dict[str, Any]:
    """Run every framework, write ``result.compliance`` in place, and return it.

    Importing :mod:`aibom.compliance` (done by the CLI) self-registers all five
    framework modules before this runs.
    """
    report: dict[str, Any] = {fw: run_framework(result, fw) for fw in FRAMEWORKS}
    report["disclaimer"] = ADVISORY_DISCLAIMER
    result.compliance = report
    return report


__all__ = ["FRAMEWORKS", "ALIASES", "resolve_framework", "run_framework", "run_all"]
