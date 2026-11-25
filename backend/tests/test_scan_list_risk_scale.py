"""#35: the SCA + SBOM, IaC, MCP and DAST scan lists show the risk score on the same 0-10 scale as their filters and
dashboards.

The list rows used to send the severity-weighted average on a 1-4 scale (Critical 4 ... Low 1), while the pages'
Risk score filter has 0-10 tiers (Critical 9 or more, High 7-9, Medium 5-7, Low under 5) and every dashboard scores a
finding Critical 10, High 7.5, Medium 5, Low 2.5. So the Critical and High filters never matched a scan, and one scan
read e.g. 4.0 in the table and 10.0 on the dashboard. The tier test reads the thresholds and the display rounding
from each page's own ``matchesRiskScoreFilter`` / ``getDisplayRiskScore``, so it checks what the page really does
with the number the backend sends.
"""
from __future__ import annotations

import datetime as dt
import math
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.utilities.dashboard import scan_list as scan_list_mod
from backend.utilities.dashboard.scan_list import (
    generate_dast_dashboard_data,
    generate_iac_dashboard_data,
    generate_mcp_dashboard_data,
    generate_sbom_sca_dashboard_data,
)
from backend.utilities.db.scan_list_item import (
    return_dast_list_item,
    return_iac_list_item,
    return_mcp_list_item,
    return_sbom_sca_list_item,
)

REPO = Path(__file__).resolve().parents[2]
CREATED = dt.datetime(2026, 11, 16, 9, 30, tzinfo=dt.timezone.utc)
OWNER = SimpleNamespace(email="o@example.test", first_name="O", last_name="Wner")


# ------------------------------------------------------------------------------------------------ scans of each type
def _scan(scan_type: str, results, metadata: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=35, title="t", scan_type=scan_type, scan_status="success", created_at=CREATED, last_updated=CREATED,
        credit_consumed=1.0, info=None, owner_user=OWNER, scan_metadata=dict(metadata or {}),
        scan_data={"results": results, "duration_of_scan": 2.0, "metadata": {}},
    )


def _rows(impacts: list[str]) -> list[dict]:
    return [{"title": f"finding {i}", "description": "d", "impact": imp, "category": "injection",
             "confidence": "high", "compliance_controls": {}, "owasp_top_10": {}} for i, imp in enumerate(impacts)]


def _mcp_results(impacts: list[str]) -> dict:
    return {"tools": [{"tool_risk_level": "high", "tool_category": "web", "vulnerabilities": _rows(impacts)}],
            "prompts": [], "resources": []}


def iac_scan(impacts):
    return _scan("iac", _rows(impacts), {"metadata": {}})


def sbom_scan(impacts):
    return _scan("sbom_sca", _rows(impacts))


def mcp_scan(impacts):
    return _scan("mcp", _mcp_results(impacts), {"server_url": "https://tools.example.com/mcp"})


def dast_scan(impacts):
    return _scan("dast", _rows(impacts), {"target_url": "https://shop.example.com"})


@pytest.fixture(autouse=True)
def mongo(monkeypatch: pytest.MonkeyPatch):
    """The stored findings of a scan are its result rows (create_findings.py); the DAST dashboard reads those."""
    store: dict[int, list[dict]] = {}

    def findings(scan_id, *a, **k):
        return list(store.get(scan_id, []))

    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id", findings)
    return store


def _store(store: dict, scan) -> None:
    rows = scan.scan_data["results"]
    if isinstance(rows, dict):
        rows = [v for tool in rows["tools"] for v in tool["vulnerabilities"]]
    store[scan.id] = [{"scan_id": scan.id, "finding_data": dict(r), "finding_status": "not_started",
                       "created_at": CREATED, "fixed_at": None, "ignored_at": None} for r in rows]


# ------------------------------------------------------------------------------------------------ the pages' tiers
def _page_source(page: str) -> str:
    return (REPO / "frontend" / "app" / "[team_id]" / page / "page.tsx").read_text(encoding="utf-8")


# The SBOM, DAST and IaC pages filter on the one 0-100 risk score since the cross-product score change
# (test_the_list_filters_use_the_one_score below); the 0-10 average stays on the API.
# impacts of one scan -> the tier its Risk score must fall in (one finding counts Critical 10 ... Low 2.5)
CASES = [
    (["Critical"], 10.0, "critical"),
    (["Critical", "Critical", "Critical", "High"], 9.4, "critical"),
    (["Critical", "High"], 8.8, "high"),
    (["High", "High"], 7.5, "high"),
    (["High", "Medium"], 6.2, "medium"),
    (["Medium"], 5.0, "medium"),
    (["Critical", "Low", "Low", "Low"], 4.4, "low"),
    (["Low"], 2.5, "low"),
]


def test_the_four_lists_are_on_one_0_to_10_scale():
    for build, item_of in [(sbom_scan, return_sbom_sca_list_item), (iac_scan, return_iac_list_item),
                           (mcp_scan, return_mcp_list_item), (dast_scan, return_dast_list_item)]:
        for impacts, score, _tier in CASES:
            assert item_of(build(impacts))["average_risk_score"] == score, (build.__name__, impacts)


def test_table_and_dashboard_show_the_same_number_for_a_scan(mongo):
    impacts = ["Critical", "High", "Medium"]  # (10 + 7.5 + 5) / 3 = 7.5
    iac, sbom, mcp, dast = iac_scan(impacts), sbom_scan(impacts), mcp_scan(impacts), dast_scan(impacts)
    for s in (iac, sbom, mcp, dast):
        _store(mongo, s)
    assert return_iac_list_item(iac)["average_risk_score"] == \
        generate_iac_dashboard_data([iac])["card_data"]["average_risk_score"] == 7.5
    assert return_sbom_sca_list_item(sbom)["average_risk_score"] == \
        generate_sbom_sca_dashboard_data([sbom])["card_data"]["average_risk_score"] == 7.5
    mcp_dash = generate_mcp_dashboard_data([mcp])
    assert return_mcp_list_item(mcp)["average_risk_score"] == mcp_dash["card_data"]["average_risk_score"] == \
        mcp_dash["risk_score_trend"]["example"] == 7.5
    assert return_dast_list_item(dast)["average_risk_score"] == \
        generate_dast_dashboard_data([dast])["card_data"]["average_risk_score"] == 7.5


def test_a_scan_without_findings_keeps_0_on_iac_mcp_and_dast():
    # unchanged: these lists show 0 for a scan that found nothing (the SBOM list shows no score instead, #46)
    assert return_iac_list_item(iac_scan([]))["average_risk_score"] == 0
    assert return_mcp_list_item(mcp_scan([]))["average_risk_score"] == 0
    assert return_dast_list_item(dast_scan([]))["average_risk_score"] == 0
    assert return_sbom_sca_list_item(sbom_scan([]))["average_risk_score"] is None


# the shared util's tiers (frontend/utils/riskPosture.ts matchesRiskTier), on the posture grade bands
POSTURE_CASES = [
    (["Critical", "Critical"], "critical"),  # 80 / F
    (["High"] * 15, "high"),  # 69 / D (capped: no Critical)
    (["Medium"] * 4, "medium"),  # 32 / C
    (["Low"] * 7, "medium"),  # 28 / B
    (["Low"] * 3, "low"),  # 12 / A
]


def _util_tiers() -> dict[str, tuple[float, float]]:
    src = (REPO / "frontend" / "utils" / "riskPosture.ts").read_text(encoding="utf-8")
    body = re.search(r"export function matchesRiskTier\(.*?\n\}", src, re.DOTALL)
    assert body, "riskPosture.ts: matchesRiskTier not found; update this test"
    num = r"(\d+)"
    b = body.group(0)
    crit = re.search(r'tier === "critical"\) return score >= ' + num, b)
    high = re.search(r'tier === "high"\) return score >= ' + num + " && score < " + num, b)
    med = re.search(r'tier === "medium"\) return score >= ' + num + " && score < " + num, b)
    low = re.search(r"return score < " + num + ";", b)
    assert crit and high and med and low, "matchesRiskTier changed shape; update this test"
    return {"critical": (float(crit.group(1)), math.inf), "high": (float(high.group(1)), float(high.group(2))),
            "medium": (float(med.group(1)), float(med.group(2))), "low": (-math.inf, float(low.group(1)))}


@pytest.mark.parametrize("page,build,item_of", [("sbom_sca", sbom_scan, return_sbom_sca_list_item),
                                                ("dast", dast_scan, return_dast_list_item),
                                                ("iac", iac_scan, return_iac_list_item)])
def test_the_list_filters_use_the_one_score(page, build, item_of):
    src = _page_source(page)
    # the SBOM list filters on triageScore: the shown score, or its guessed-version worst case when higher (#505 r3)
    reads = "return triageScore(c);" if page == "sbom_sca" else "return postureScore(c);"
    assert "return matchesRiskTier(score, filter);" in src and reads in src, page
    tiers = _util_tiers()
    for impacts, tier in POSTURE_CASES:
        score = item_of(build(impacts))["risk_posture"]["score"]
        kept = [t for t, (lo, hi) in tiers.items() if lo <= score < hi]
        assert kept == [tier], (page, impacts, score, kept)
