"""CHART-DATA-CONTRACT — severity VARIETY (complements test_chart_data_contract.py).

That sibling proves the OWASP / compliance / severity arrays are non-empty on the
synthetic + chroma fixtures — but those fixtures fire no risk flags, so every
finding is ``Low`` and the severity chart, while non-empty, is a flat single bar.
This module uses the engineered ``chart-contract`` fixture (an intentionally
non-compliant model repo) to prove the Risk-Metrics chart receives a real
multi-severity breakdown carried THROUGH ``normalize()`` — not flattened.

Real ScanResult through the real adapter; nothing mocked (no network/LLM here).
"""

from __future__ import annotations

import pathlib
from collections import Counter

from aibom.integrations.devsecshield import scan_to_devsecshield

_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "chart-contract"


def _findings() -> list[dict]:
    return scan_to_devsecshield(_FIXTURE, level=4)["results"]


def test_severity_distribution_has_variety_not_all_low() -> None:
    sev = Counter((f.get("impact") or "Low") for f in _findings())
    # The engineered fixture fires DATASET_NO_DEIDENT (Critical), MODEL_NO_LICENSE
    # / MODEL_PHI_AT_INFERENCE (High), and leaves frameworks at Low.
    assert sev["Critical"] >= 1, f"no Critical finding: {dict(sev)}"
    assert sev["High"] >= 1, f"no High finding: {dict(sev)}"
    assert sev["Low"] >= 1, f"no Low finding: {dict(sev)}"
    # Genuinely multi-severity (the chart is not a single flat bar).
    assert len([k for k, v in sev.items() if v > 0]) >= 3


def test_engineered_fixture_also_carries_owasp_and_compliance() -> None:
    out = scan_to_devsecshield(_FIXTURE, level=4)
    assert any(f["owasp_top_10_llm"] for f in out["results"])
    comp = out["ai_bom_compliance"]
    gaps = [
        k for k, v in comp.items()
        if isinstance(v, dict) and (v.get("fail") or 0) > 0
    ]
    assert gaps, "engineered fixture must yield >=1 compliance gap"


def test_compliance_framework_detail_survives_normalize() -> None:
    # scan_to_devsecshield runs compliance internally; the run-object must carry
    # each framework's {pass,fail,na} + per-requirement detail verbatim (the
    # ComplianceCoverage drill-down needs it) — not flattened to a bare count.
    out = scan_to_devsecshield(_FIXTURE, level=4)
    comp = out["ai_bom_compliance"]
    assert isinstance(comp, dict) and comp
    fw = next(v for v in comp.values() if isinstance(v, dict) and "fail" in v)
    assert {"pass", "fail", "na"} <= set(fw)
    assert isinstance(fw.get("requirements"), list) and fw["requirements"]
