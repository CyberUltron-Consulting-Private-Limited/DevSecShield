"""CHART-DATA-CONTRACT — prevents the empty-results-page-chart regression.

The AI-BOM results page renders three charts the engine must feed:
  * OWASP donut          <- dashboard.owasp_top_10_llm_issues (finding.owasp_top_10_llm)
  * Compliance Controls  <- dashboard.compliance_controls (from ai_bom_compliance fails)
  * Risk Metrics radar   <- dashboard.severity_distribution    (from finding.impact)

These were empty because ``normalize()`` flattened ``owasp_top_10_llm`` to ``[]``.
This test scans a real fixture through the REAL normalizer (no mocks — only the
network/LLM would be external, and this path uses neither) and asserts the exact
arrays the backend dashboard aggregates are NON-EMPTY, mirroring the backend
aggregation in ``backend/utilities/dashboard/scan.py`` (ai_bom branch). If a
future change re-flattens any of them, this fails before it reaches the UI.

chroma (the gitignored clone, see tests/fixtures/CHROMA.md) is asserted too when
present; it skips in CI when the clone is absent.
"""
from __future__ import annotations

import os
from collections import Counter

import pytest

from aibom.integrations.devsecshield import scan_to_devsecshield

_HERE = os.path.dirname(os.path.abspath(__file__))


def _dashboard_arrays(fixture: str) -> dict:
    """Scan a fixture and reproduce the backend ai_bom dashboard aggregation."""
    path = os.path.join(_HERE, "fixtures", fixture)
    if not os.path.isdir(path):
        # multi-site lives under examples/, fixtures under tests/fixtures/.
        alt = os.path.join(os.path.dirname(_HERE), "examples", fixture)
        path = alt if os.path.isdir(alt) else path
    if not os.path.isdir(path):
        pytest.skip(f"fixture {fixture!r} not present (see tests/fixtures/CHROMA.md)")

    out = scan_to_devsecshield(path, level=4)
    findings = out["results"]

    _RISK = {"critical": 9, "high": 7, "medium": 5, "low": 2}
    owasp, severity = Counter(), Counter()
    asset_types, providers = Counter(), Counter()
    licenses, risk_categories = Counter(), Counter()
    risk_per_finding: list[int] = []
    for f in findings:
        for _key, label in (f.get("owasp_top_10_llm") or {}).items():
            owasp[label] += 1
        imp = (f.get("impact") or "Low").lower()
        severity[imp] += 1
        risk_per_finding.append(_RISK.get(imp, 2))
        if f.get("component_type"):
            asset_types[f["component_type"]] += 1
        if f.get("source"):
            providers[f["source"]] += 1
        if f.get("license"):
            licenses[f["license"]] += 1
        if f.get("risk_category"):
            risk_categories[f["risk_category"]] += 1

    compliance = Counter()
    for fw_key, fw in (out.get("ai_bom_compliance") or {}).items():
        if fw_key == "disclaimer" or not isinstance(fw, dict):
            continue
        if fw.get("fail"):
            compliance[fw.get("title") or fw_key] += int(fw["fail"])

    return {
        "findings": findings,
        "owasp": dict(owasp),
        "severity": dict(severity),
        "compliance": dict(compliance),
        "assetTypes": dict(asset_types),
        "providers": dict(providers),
        "licenses": dict(licenses),
        "riskCategories": dict(risk_categories),
        "riskPerFinding": risk_per_finding,
    }


# Every results-page chart's backing array — assert ALL non-empty so no chart can
# silently go blank again. The engineered scoring-calibration fixture spans the
# severities; chroma is the real-repo check (skips in CI when the clone is absent).
@pytest.mark.parametrize("fixture", ["scoring-calibration", "chroma"])
def test_every_chart_array_non_empty(fixture: str) -> None:
    d = _dashboard_arrays(fixture)
    assert d["findings"], f"{fixture}: no findings"
    for key in (
        "severity", "owasp", "compliance", "assetTypes",
        "providers", "licenses", "riskCategories", "riskPerFinding",
    ):
        assert d[key], f"{fixture}: {key}[] EMPTY -> its chart is blank"


def test_owasp_labels_are_real_2025_taxonomy() -> None:
    """The dashboard OWASP labels are the REAL OWASP-LLM-Top-10:2025 codes
    (LLM02 Sensitive Info, LLM03 Supply Chain, LLM08 Vector & Embedding, …) —
    consistent with ScanResult.owasp — not the legacy 2023 numbering."""
    valid = tuple(f"LLM{n:02d}:2025" for n in range(1, 11))
    d = _dashboard_arrays("scoring-calibration")
    assert d["owasp"], "no OWASP labels emitted"
    for label in d["owasp"]:
        assert label.startswith(valid), f"non-2025 OWASP label: {label!r}"
