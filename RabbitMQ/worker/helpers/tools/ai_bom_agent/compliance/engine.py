"""
Compliance engine — runs every registered framework mapper against an AI-BOM
(CycloneDX 1.6 ML-BOM dict) plus its enriched finding list, and assembles a single
advisory ComplianceReport.

Pure orchestration: importing this module imports every framework module, which
self-registers via @register. No network, no I/O.
"""
from __future__ import annotations

from helpers.tools.ai_bom_agent.compliance.base import ComplianceReport, registry

# Importing the framework modules triggers their @register side-effect.
from helpers.tools.ai_bom_agent.compliance import (  # noqa: F401
    fda_524b,
    eu_ai_act_annexIV,
    gmlp,
    hipaa,
    nist_rmf,
)

# Stable display order for the assembled report.
FRAMEWORK_ORDER = [
    "fda_524b",
    "eu_ai_act_annexIV",
    "gmlp",
    "hipaa",
    "nist_rmf",
]


def available_frameworks() -> list[str]:
    return [k for k in FRAMEWORK_ORDER if k in registry()] + \
        [k for k in registry() if k not in FRAMEWORK_ORDER]


def evaluate_compliance(
    bom: dict,
    findings: list[dict] | None = None,
    frameworks: list[str] | None = None,
) -> ComplianceReport:
    """Run the selected (default: all) framework mappers over the BOM.

    Args:
        bom:        CycloneDX 1.6 ML-BOM dict (the ai_bom_json output).
        findings:   enriched AI-risk findings list (optional).
        frameworks: subset of framework keys to run; None = all registered.

    Returns:
        ComplianceReport (advisory; carries the DISCLAIMER).
    """
    bom = bom or {}
    findings = findings or []
    reg = registry()
    keys = frameworks or available_frameworks()

    reports = []
    for key in keys:
        evaluator = reg.get(key)
        if evaluator is None:
            continue
        reports.append(evaluator(bom, findings))

    serial = bom.get("serialNumber")
    return ComplianceReport(generated_from=serial, frameworks=reports)


def evaluate_compliance_dict(
    bom: dict,
    findings: list[dict] | None = None,
    frameworks: list[str] | None = None,
) -> dict:
    """Convenience wrapper returning the JSON-serializable dict."""
    return evaluate_compliance(bom, findings, frameworks).to_dict()
