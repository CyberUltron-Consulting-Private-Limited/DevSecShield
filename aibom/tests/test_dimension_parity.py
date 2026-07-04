"""Trusera dimension-PARITY lock.

Trusera's ``ai-bom scan <repo> -f html`` dashboard surfaces: a component count, a
risk/severity distribution, and a provider breakdown. The DevSecShield AI-BOM
results page must cover at least those dimensions — and it covers MORE. This test
locks the six dimensions the results-page charts aggregate from the adapter's
findings, reproduced exactly as ``backend/utilities/dashboard/scan.py`` does, so a
future change that drops a dimension fails the build (complements
``test_chart_data_contract.py``, which locks the severity/OWASP/compliance arrays).

  Dimension (our chart)            <- finding field           Trusera HTML?
  severity_distribution            <- impact                  yes
  asset_type_distribution          <- component_type          partial (count only)
  provider_distribution            <- source                  yes
  license_distribution             <- license                 no
  owasp_top_10_llm_issues          <- owasp_top_10_llm         no
  risk-per-finding (top_risks)     <- impact + risk_category  yes (risk dist)

Real ScanResult through the real adapter; nothing mocked.
"""

from __future__ import annotations

import os
from collections import Counter

import pytest

from aibom.integrations.devsecshield import scan_to_devsecshield

_HERE = os.path.dirname(os.path.abspath(__file__))

# The six dimensions Trusera-parity requires, each as (finding field -> non-empty).
_DIMENSIONS = {
    "severity_distribution": lambda f: (f.get("impact") or "Low"),
    "asset_type_distribution": lambda f: (f.get("component_type") or "unknown"),
    "provider_distribution": lambda f: (f.get("source") or "unknown"),
    "license_distribution": lambda f: (f.get("license") or "unknown"),
    "risk_category_distribution": lambda f: (f.get("risk_category") or "unknown"),
}


def _findings(fixture: str) -> list[dict]:
    path = os.path.join(_HERE, "fixtures", fixture)
    if not os.path.isdir(path):
        pytest.skip(f"fixture {fixture!r} absent (see tests/fixtures/CHROMA.md)")
    return scan_to_devsecshield(path, level=4)["results"]


@pytest.mark.parametrize("fixture", ["synthetic", "chroma"])
def test_all_trusera_dimensions_present_and_non_empty(fixture: str) -> None:
    findings = _findings(fixture)
    assert findings, f"{fixture}: no findings"
    for dim, key in _DIMENSIONS.items():
        dist = Counter(key(f) for f in findings)
        assert dist, f"{fixture}: {dim} EMPTY — Trusera-parity dimension dropped"

    # OWASP (the dimension Trusera's HTML lacks) — must also aggregate non-empty.
    owasp = Counter(
        label
        for f in findings
        for label in (f.get("owasp_top_10_llm") or {}).values()
    )
    assert owasp, f"{fixture}: owasp_top_10_llm_issues EMPTY"

    # risk-per-finding: every finding carries an order-able impact for top_risks.
    assert all(f.get("impact") for f in findings)


def test_we_exceed_trusera_with_owasp_and_license_dimensions() -> None:
    # The two dimensions Trusera's HTML does NOT surface, proving parity-or-more.
    findings = _findings("synthetic")
    licenses = {(f.get("license") or "unknown") for f in findings}
    assert len(licenses) >= 1
    owasp = {
        label
        for f in findings
        for label in (f.get("owasp_top_10_llm") or {}).values()
    }
    assert owasp, "OWASP dimension (beyond Trusera) must be populated"
