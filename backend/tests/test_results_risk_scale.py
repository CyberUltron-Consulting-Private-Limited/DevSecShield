"""#35, one level down: the IaC, MCP and DAST results pages score each finding on the 0-10 scale of their Risk score
filter, their risk badges and the dashboards, and the SBOM PDF averages on that scale too.

The results APIs sent ``risk_score`` 1-4 (Low 1 ... Critical 4, ``findings.risk_score_map``) while the results pages'
filter keeps Critical 9 or more, High 7-9, Medium 5-7, Low under 5: a Critical finding was filtered as Low and the
Critical and High filters never kept a finding. The badges coloured on 1-4 (IaC, SBOM) or on their own 7/5/3 (DAST).
The tier and badge tests read the thresholds from each results component's source, so they check what the page does
with the number the backend sends. Scores are computed when read, so stored scans need no migration.
"""
from __future__ import annotations

import datetime as dt
import math
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.utilities.dashboard import cicd as cicd_mod
from backend.utilities.dashboard import risk_scale
from backend.utilities.dashboard import scan as scan_mod
from backend.utilities.dashboard import scan_list as scan_list_mod
from backend.utilities.db import findings as findings_mod

REPO = Path(__file__).resolve().parents[2]
COMPONENTS = REPO / "frontend" / "components"
IMPACTS = ["Critical", "High", "Medium", "Low"]
RESULTS_PAGES = {"iac": "IACResults.tsx", "mcp": "MCPResults.tsx", "dast": "DASTResults.tsx"}


def _stored_finding(i: int, impact: str) -> dict:
    # every finding_data key the iac, mcp and dast serializers read (create_findings.py stores the result rows)
    return {"_id": f"finding-{i}", "scan_id": 35, "finding_status": "not_started", "finding_data": {
        "title": f"{impact} finding", "description": "d", "impact": impact, "compliance_controls": {},
        "owasp_top_10": {}, "owasp_top_10_llm": {}, "suggested_fix": "fix", "location": "main.tf", "snippet": "",
        "cves": {}, "category": "injection", "resource": "aws_s3_bucket.logs", "type": "tool",
        "url": "https://shop.example.com/search", "confidence": "high"}}


@pytest.fixture
def stored(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    docs = [_stored_finding(i, impact) for i, impact in enumerate(IMPACTS)]
    monkeypatch.setattr(findings_mod, "get_findings_for_scan_id", lambda *a, **k: list(docs))
    return docs


def _scores(scan_type: str) -> dict[str, float]:
    """impact -> risk_score of the findings the results API sends for this scan type."""
    return {f["impact"]: f["risk_score"] for f in findings_mod.get_findings_for_scan_type(scan_type, 35)}


def _source(component: str) -> str:
    return (COMPONENTS / component).read_text(encoding="utf-8")


def _filter_tiers(component: str) -> dict[str, tuple[float, float]]:
    """[low, high) per tier, as the component's matchesRiskScoreFilter tests them."""
    src, num = _source(component), r"(\d+(?:\.\d+)?)"
    found = {
        "critical": re.search(r'filter === "critical"\) return score >= ' + num + ";", src),
        "high": re.search(r'filter === "high"\) return score >= ' + num + " && score < " + num + ";", src),
        "medium": re.search(r'filter === "medium"\) return score >= ' + num + " && score < " + num + ";", src),
        "low": re.search(r'filter === "low"\) return score < ' + num + ";", src),
    }
    missing = [tier for tier, m in found.items() if m is None]
    assert not missing, f"{component}: matchesRiskScoreFilter changed shape ({missing}); update this test"
    return {
        "critical": (float(found["critical"].group(1)), math.inf),
        "high": (float(found["high"].group(1)), float(found["high"].group(2))),
        "medium": (float(found["medium"].group(1)), float(found["medium"].group(2))),
        "low": (-math.inf, float(found["low"].group(1))),
    }


# ------------------------------------------------------------------------------------------------ results APIs
@pytest.mark.parametrize("scan_type", sorted(RESULTS_PAGES))
def test_findings_score_on_the_0_to_10_scale(stored, scan_type):
    assert _scores(scan_type) == {"Critical": 10.0, "High": 7.5, "Medium": 5.0, "Low": 2.5}


@pytest.mark.parametrize("scan_type", sorted(RESULTS_PAGES))
def test_the_critical_and_high_filters_keep_their_findings(stored, scan_type):
    component = RESULTS_PAGES[scan_type]
    # the page filters the score as the API sends it: no rescaling between the backend and the tiers
    assert re.search(r"matchesRiskScoreFilter\(f\.risk_score \?\? (?:null|undefined), filterRiskScore\)",
                     _source(component)), component
    tiers = _filter_tiers(component)
    assert {tier: lo for tier, (lo, _hi) in tiers.items() if tier != "low"} == {
        band: floor for band, floor in risk_scale.RISK_BANDS if band != "low"}
    for impact, score in _scores(scan_type).items():
        kept = [tier for tier, (lo, hi) in tiers.items() if lo <= score < hi]
        assert kept == [impact.lower()] == [risk_scale.risk_band(score)], (scan_type, impact, score, kept)


# the colour thresholds of each results table's risk badge: red, orange, amber (below: green)
BADGES = {
    "IACResults.tsx": r'riskScoreNum >= {n} \? "bg-{colour}-100',
    "DASTResults.tsx": r'riskScore >= {n} \? "bg-{colour}-100',
    "SbomResults.tsx": r'if \(s >= {n}\) return "bg-{colour}-100',
}


@pytest.mark.parametrize("component", sorted(BADGES))
def test_risk_badges_colour_by_the_filter_tiers(component):
    src = _source(component)
    floors = {}
    for colour in ("red", "orange", "amber"):
        m = re.search(BADGES[component].format(n=r"(\d+(?:\.\d+)?)", colour=colour), src)
        assert m, f"{component}: the {colour} risk badge changed shape; update this test"
        floors[colour] = float(m.group(1))
    bands = dict(risk_scale.RISK_BANDS)
    # a Critical finding is red, High orange, Medium amber, Low green: the badge agrees with the filter tier
    assert floors == {"red": bands["critical"], "orange": bands["high"], "amber": bands["medium"]}


# ------------------------------------------------------------------------------------------------ one contract
def test_the_dashboards_score_on_the_same_scale():
    as_float = lambda scale: {impact: float(score) for impact, score in scale.items()}  # noqa: E731
    assert as_float(scan_mod.risk_score_for_impact) == risk_scale.IMPACT_RISK
    assert as_float(scan_list_mod.DAST_RISK_SCORE_FOR_IMPACT) == risk_scale.IMPACT_RISK
    assert as_float(cicd_mod.RISK_SCORE_FOR_IMPACT) == risk_scale.IMPACT_RISK
    assert risk_scale.impact_risk("informational") == risk_scale.impact_risk(None) == 2.5  # unknown counts as Low


def test_the_sbom_pdf_average_is_the_dashboards_number(monkeypatch: pytest.MonkeyPatch, tmp_path):
    from backend.utilities.dashboard.scan import generate_scan_dashboard
    from backend.utilities.dashboard.scan_list import generate_sbom_sca_dashboard_data
    from backend.utilities.db.scan_list_item import return_sbom_sca_list_item
    from backend.utilities.pdf import sbom_sca_pdf

    impacts = ["Critical", "High", "Medium", "Low", "Low"]  # (10 + 7.5 + 5 + 2.5 + 2.5) / 5 = 5.5
    rows = [{"title": f"{impact} vulnerability", "dependency": f"pkg{i}@1.0.{i}", "impact": impact,
             "cves": {f"CVE-2026-100{i}": "x"}, "reachability": "reachable", "license_type": "permissive",
             "compliance_controls": {}, "owasp_top_10": {}, "suggested_fix": "upgrade"} for i, impact in enumerate(impacts)]
    created = dt.datetime(2026, 11, 16, 9, 30, tzinfo=dt.timezone.utc)
    scan = SimpleNamespace(id=35, title="t", scan_type="sbom_sca", scan_status="success", created_at=created,
                           last_updated=created, credit_consumed=1.0, info=None, scan_metadata={},
                           owner_user=SimpleNamespace(email="o@example.test", first_name="O", last_name="Wner"),
                           scan_data={"results": rows, "duration_of_scan": 1.0})
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id", lambda *a, **k: [])
    seen: dict = {}
    summary = sbom_sca_pdf.append_executive_summary

    def spy_summary(story, **kw):
        seen.update(dict(kw["overview_rows"]))
        return summary(story, **kw)

    monkeypatch.setattr(sbom_sca_pdf, "append_executive_summary", spy_summary)
    sbom_sca_pdf.generate_pdf({"results": rows, "duration_of_scan": 1.0}, str(tmp_path / "sbom.pdf"))

    table = return_sbom_sca_list_item(scan)["average_risk_score"]
    list_card = generate_sbom_sca_dashboard_data([scan])["card_data"]["average_risk_score"]
    results_card = generate_scan_dashboard("sbom_sca", scan_object=scan)["card_data"]["average_risk_score"]
    assert table == list_card == results_card == 5.5
    # the export shows the list row's one 0-100 score (risk_scale.posture; the 0-10 average stays on the API only)
    assert seen["Risk score"] == "{score} / 100 · grade {grade} · {label}".format(
        **return_sbom_sca_list_item(scan)["risk_posture"])
