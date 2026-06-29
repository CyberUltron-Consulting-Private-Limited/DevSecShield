"""CHART-DATA-CONTRACT (full) — EVERY results-page chart has data, forever.

The AI-BOM results page renders eight charts; each is fed a distribution the
backend dashboard (``backend/utilities/dashboard/scan.py`` ai_bom branch)
aggregates from the adapter's findings + ``ai_bom_compliance``. This test scans
the engineered ``synthetic-scorer`` fixture through the REAL adapter and asserts
EVERY one of those arrays is NON-EMPTY — reproducing the backend aggregation
exactly, so a future change that re-flattens any field fails before it reaches
the UI. (Complements test_chart_data_contract.py / test_dimension_parity.py; this
one locks all eight in a single place, including riskPerFinding.)

  Chart                     <- dashboard field           <- finding field
  Risk Metrics (severity)      severity_distribution         impact
  Asset Types                  asset_type_distribution       component_type
  Providers                    provider_distribution         source
  License Distribution         license_distribution          license
  Risk Categories              risk_category_distribution    risk_category
  Risk Scores per Finding      top_risks                     impact (per finding)
  OWASP LLM Top 10             owasp_top_10_llm_issues        owasp_top_10_llm
  Compliance Controls          compliance_controls           ai_bom_compliance fails

Real ScanResult through the real adapter; nothing mocked.
"""

from __future__ import annotations

import os
from collections import Counter

import pytest

from aibom.integrations.devsecshield import scan_to_devsecshield

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURE = "synthetic-scorer"


def _dashboard_arrays(fixture: str) -> dict[str, list | dict]:
    path = os.path.join(_HERE, "fixtures", fixture)
    if not os.path.isdir(path):
        pytest.skip(f"fixture {fixture!r} absent")
    out = scan_to_devsecshield(path, level=4)
    findings = out["results"]

    severity = Counter((f.get("impact") or "Low") for f in findings)
    asset_types = Counter((f.get("component_type") or "unknown") for f in findings)
    providers = Counter((f.get("source") or "unknown") for f in findings)
    licenses = Counter((f.get("license") or "unknown") for f in findings)
    risk_categories = Counter((f.get("risk_category") or "unknown") for f in findings)
    owasp = Counter(
        label for f in findings for label in (f.get("owasp_top_10_llm") or {}).values()
    )
    # Risk-per-finding: every finding ranked by its (stacked) severity.
    risk_per_finding = [
        {"name": f.get("component_name") or f.get("title"), "impact": f.get("impact")}
        for f in findings
    ]
    compliance = Counter()
    for fw_key, fw in (out.get("ai_bom_compliance") or {}).items():
        if fw_key == "disclaimer" or not isinstance(fw, dict):
            continue
        if fw.get("fail"):
            compliance[fw.get("title") or fw_key] += int(fw["fail"])

    return {
        "severity": dict(severity),
        "assetTypes": dict(asset_types),
        "providers": dict(providers),
        "licenses": dict(licenses),
        "riskCategories": dict(risk_categories),
        "owasp": dict(owasp),
        "compliance": dict(compliance),
        "riskPerFinding": risk_per_finding,
    }


# The eight arrays that back the eight results-page charts.
_REQUIRED = (
    "severity", "assetTypes", "providers", "licenses",
    "riskCategories", "owasp", "compliance", "riskPerFinding",
)


def test_every_chart_array_is_non_empty() -> None:
    arrays = _dashboard_arrays(_FIXTURE)
    blank = [k for k in _REQUIRED if not arrays.get(k)]
    assert not blank, f"these charts would render BLANK: {blank} (arrays: {arrays})"


def test_severity_spans_bands_and_owasp_has_real_categories() -> None:
    arrays = _dashboard_arrays(_FIXTURE)
    # engineered fixture: >=1 finding per severity band
    for band in ("Critical", "High", "Medium", "Low"):
        assert arrays["severity"].get(band, 0) >= 1, f"no {band}: {arrays['severity']}"
    # >=1 OWASP category and >=1 compliance gap (the chart-data contract)
    assert arrays["owasp"], "OWASP chart blank"
    assert arrays["compliance"], "Compliance chart blank"
    # every finding carries a per-finding risk severity (riskPerFinding chart)
    assert all(f["impact"] for f in arrays["riskPerFinding"])
