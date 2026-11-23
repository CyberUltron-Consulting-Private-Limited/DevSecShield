"""SARIF 2.1.0 reporter: ``ScanResult.flags`` -> SARIF results for CI gating.

PURE function. Each semantic flag a scanner raised becomes one SARIF result so a
CI pipeline can gate (e.g. fail on ``error``-level findings). The flags are
ADVISORY governance signals — they surface review obligations, they do not
assert compliance.

HARD RULE (build-failure): the emitted document MUST validate against the
bundled SARIF 2.1.0 schema. ``emit_and_validate_sarif`` enforces it.
"""

from __future__ import annotations

from typing import Any

from aibom.emit._disclaimer import HEALTHCARE_AIBOM_DISCLAIMER, disclaimer_of
from aibom.emit.identity import SUPPLIER, SUPPLIER_URL, TOOL_NAMES, identity_for
from aibom.emit.registry import BaseReporter, register_reporter
from aibom.emit.validate import validate_sarif
from aibom.model.result import SEVERITIES, ScanResult

TOOL_NAME = TOOL_NAMES["aibom"]
INFO_URI = SUPPLIER_URL
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Static catalog of known flag codes -> SARIF rule metadata (stable ruleIndex).
# Scanners raise these codes; new codes fall back to a generated rule entry.
_RULE_CATALOG: dict[str, dict[str, str]] = {
    "DATASET_NO_DEIDENT": {
        "name": "DatasetNotDeidentified",
        "text": "Training dataset shows no evidence of de-identification; HIPAA "
        "de-identification of PHI is required.",
        "level": "error",
    },
    "MODEL_EU_AI_ACT_HIGH_RISK": {
        "name": "EuAiActHighRisk",
        "text": "EU AI Act high-risk AI system requires Annex IV technical "
        "documentation and MDR/IVDR alignment.",
        "level": "warning",
    },
    "MODEL_NO_LICENSE": {
        "name": "ConcludedLicenseMissing",
        "text": "AI model component has no declared license; a concluded license "
        "is required for SPDX/§524B.",
        "level": "error",
    },
    "MODEL_PHI_AT_INFERENCE": {
        "name": "PhiAtInference",
        "text": "Model processes sensitive personal information (PHI) at inference; "
        "HIPAA BAA and §524B security risk analysis required.",
        "level": "warning",
    },
}


def _rule_catalog(result: ScanResult) -> list[str]:
    """The flag codes raised, sorted (stable ruleIndex). The static catalog's
    clinical rules (HIPAA / §524B / EU AI Act wording) are listed only for a
    healthcare-profile scan, so a bank's SARIF never names HIPAA or FDA."""
    codes = {f.code for f in result.flags}
    if disclaimer_of(result) == HEALTHCARE_AIBOM_DISCLAIMER:
        codes |= set(_RULE_CATALOG)
    return sorted(codes)


def _rule_entry(code: str) -> dict[str, Any]:
    meta = _RULE_CATALOG.get(
        code, {"name": code.title().replace("_", ""), "text": code, "level": "warning"}
    )
    return {
        "id": code,
        "name": meta["name"],
        "shortDescription": {"text": meta["text"]},
        "defaultConfiguration": {"level": meta["level"]},
        "helpUri": f"{INFO_URI}#{code.lower()}",
    }


def emit_sarif(result: ScanResult) -> dict[str, Any]:
    """Serialize the scan's flags to a SARIF 2.1.0 dict (PURE)."""
    codes = _rule_catalog(result)
    index_of = {code: i for i, code in enumerate(codes)}
    rules = [_rule_entry(code) for code in codes]

    results: list[dict[str, Any]] = []
    for flag in result.flags:
        # Defensive: never emit a level outside the SARIF enum (would fail the
        # schema gate at emit time). Flag.__post_init__ already enforces this;
        # this guard keeps emit_sarif correct even if that invariant is bypassed.
        level = flag.severity if flag.severity in SEVERITIES else "warning"
        entry: dict[str, Any] = {
            "ruleId": flag.code,
            "ruleIndex": index_of[flag.code],
            "level": level,
            "message": {"text": flag.message or flag.code},
        }
        if flag.target:
            entry["locations"] = [
                {
                    "logicalLocations": [
                        {"name": flag.target, "fullyQualifiedName": flag.target}
                    ]
                }
            ]
        results.append(entry)

    identity = identity_for(result)
    return {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": identity.tool_name,
                        "organization": SUPPLIER,
                        "version": identity.tool_version,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {"executionSuccessful": True, "endTimeUtc": identity.timestamp}
                ],
                # advisory-only hard rule: this report carries the disclaimer.
                "properties": {"advisoryDisclaimer": disclaimer_of(result)},
                "results": results,
            }
        ],
    }


class SarifValidationError(Exception):
    """Raised when an emitted SARIF document fails schema validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        joined = "\n  - ".join(errors)
        super().__init__(
            f"Emitted SARIF 2.1.0 document failed schema validation "
            f"({len(errors)} error(s)):\n  - {joined}"
        )


def emit_and_validate_sarif(result: ScanResult) -> dict[str, Any]:
    """Emit SARIF then schema-validate. Raises ``SarifValidationError`` on error."""
    doc = emit_sarif(result)
    errors = validate_sarif(doc)
    if errors:
        raise SarifValidationError(errors)
    return doc


@register_reporter
class SarifReporter(BaseReporter):
    """SARIF 2.1.0 governance-findings reporter (renders ScanResult.flags)."""

    format = "sarif"

    def render(self, result: ScanResult) -> str:
        import json

        return json.dumps(emit_and_validate_sarif(result), indent=2) + "\n"


__all__ = [
    "SarifValidationError",
    "SarifReporter",
    "emit_sarif",
    "emit_and_validate_sarif",
]
