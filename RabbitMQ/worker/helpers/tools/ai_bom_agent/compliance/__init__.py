"""
Healthcare AI-BOM compliance-mapping layer.

Extends the existing DevSecShield ai_bom (CycloneDX 1.6 ML-BOM) with an ADVISORY
regulatory readiness mapping: each framework requirement -> mapped BOM field(s) ->
evidence OR a flagged gap. Frameworks: FDA §524B/SaMD/PCCP, EU AI Act Annex IV,
GMLP, HIPAA, NIST AI RMF.

Public API:
    from helpers.tools.ai_bom_agent.compliance import evaluate_compliance, evaluate_compliance_dict
    report = evaluate_compliance(ai_bom_json, findings)        # ComplianceReport
    report_dict = evaluate_compliance_dict(ai_bom_json, findings)  # JSON-ready dict

Hard rule: this mapping is advisory only and every report carries base.DISCLAIMER.
No invented top-level BOM fields — healthcare data lives in namespaced properties
(clinical:/regulatory:/dataset:).
"""
from helpers.tools.ai_bom_agent.compliance.base import (
    DISCLAIMER,
    ComplianceReport,
    FrameworkReport,
    RequirementResult,
)
from helpers.tools.ai_bom_agent.compliance.engine import (
    available_frameworks,
    evaluate_compliance,
    evaluate_compliance_dict,
)

__all__ = [
    "DISCLAIMER",
    "ComplianceReport",
    "FrameworkReport",
    "RequirementResult",
    "available_frameworks",
    "evaluate_compliance",
    "evaluate_compliance_dict",
]
