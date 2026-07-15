"""CHART-DATA-CONTRACT (backend / API-response side).

Drives the REAL ``generate_scan_dashboard`` ai_bom branch — the code that builds
the results-page dashboard payload — and asserts the three chart arrays come out
NON-EMPTY:

  * ``severity_distribution``   -> Risk-Metrics radar
  * ``owasp_top_10_llm_issues`` -> OWASP donut
  * ``compliance_controls``     -> Compliance-Controls panel

Two inputs:
  1. A captured run of the engineered ``chart-contract`` fixture (real adapter
     output: Critical+High+Low findings, OWASP labels, compliance gaps). Mirrors
     the aibom-side ``test_chart_contract_severity.py``.
     Regenerate from the aibom package:
       uv run python -c "import json; from aibom.scan.pipeline import scan_repo; \
         from aibom.integrations.devsecshield import normalize; \
         import aibom.compliance as C; r=scan_repo('tests/fixtures/chart-contract',level=4); \
         C.run_all(r); sd=normalize(r,duration_of_scan=0.0); \
         json.dump({'results':sd['results'],'ai_bom_compliance':sd['ai_bom_compliance']}, \
         open('../backend/tests/fixtures/ai_bom_chart_contract_scandata.json','w'),indent=1,sort_keys=True)"
  2. A crafted payload with ONE finding per severity — covers the Medium bucket
     that a single-model real scan cannot produce (Medium warning-flags collide
     with the model's High), proving the aggregator buckets all four levels.

Only true externals are stubbed: the DB-backed remediation/status helpers. The
aggregation itself runs for real (skill-testing-anti-patterns).
"""

import json
import os
import sys
import types

import pytest

# The dashboard code uses absolute ``backend.*`` imports, so the repo root must
# be importable regardless of the pytest working directory (backend/ or root).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard import scan as scan_mod  # noqa: E402
from backend.utilities.dashboard.scan import generate_scan_dashboard  # noqa: E402

_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "fixtures", "ai_bom_chart_contract_scandata.json")


@pytest.fixture(autouse=True)
def _stub_db(monkeypatch):
    """Stub the DB-backed remediation/status helpers (the only true externals)."""
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(scan_mod, "get_remediation_metrics", lambda *a, **k: {})
    monkeypatch.setattr(scan_mod, "get_issue_status_metrics", lambda *a, **k: {})


def _dashboard(scan_data: dict) -> dict:
    fake = types.SimpleNamespace(scan_data=scan_data, id=10_000_001)
    return generate_scan_dashboard("ai_bom", scan_object=fake)


# ── the real engineered scan_data -> non-empty chart arrays ──────────────────
def test_engineered_scandata_populates_all_three_charts() -> None:
    scan_data = json.load(open(_FIXTURE))
    dash = _dashboard(scan_data)

    sev = dash["severity_distribution"]
    assert sum(sev.values()) > 0, "severity_distribution empty -> Risk chart blank"
    assert sev["critical"] >= 1 and sev["high"] >= 1 and sev["low"] >= 1, sev

    assert dash["owasp_top_10_llm_issues"], "owasp_top_10_llm_issues empty -> OWASP blank"
    assert dash["compliance_controls"], "compliance_controls empty -> Compliance blank"
    # high-risk roll-up reflects the Critical+High findings
    assert dash["card_data"]["total_high_risk_assets"] >= 2


# ── crafted one-per-severity -> all four buckets bucket correctly ────────────
def _finding(impact: str, owasp: dict | None = None) -> dict:
    return {
        "title": f"asset-{impact}",
        "impact": impact,
        "component_type": "framework",
        "source": "demo",
        "license": "unknown",
        "risk_category": "demo",
        "component_name": f"asset-{impact}",
        "owasp_top_10_llm": owasp or {},
        "compliance_controls": {},
    }


def test_aggregator_buckets_all_four_severities() -> None:
    scan_data = {
        "results": [
            _finding("Critical", {"X": "LLM06:2025 - Sensitive Information Disclosure"}),
            _finding("High"),
            _finding("Medium"),
            _finding("Low"),
        ],
        "ai_bom_compliance": {
            "fda_524b": {"pass": 1, "fail": 2, "na": 0, "coverage": 0.33,
                         "requirements": [{"id": "524B-1", "verdict": "fail"}]},
            "disclaimer": "advisory",
        },
    }
    dash = _dashboard(scan_data)
    sev = dash["severity_distribution"]
    assert sev == {"critical": 1, "high": 1, "medium": 1, "low": 1}, sev
    assert dash["owasp_top_10_llm_issues"], "crafted OWASP did not aggregate"
    assert dash["compliance_controls"], "crafted compliance gap did not aggregate"


def test_no_compliance_gap_yields_empty_controls_not_crash() -> None:
    # All-NA / all-pass compliance -> compliance_controls empty (no false bars).
    scan_data = {
        "results": [_finding("Low")],
        "ai_bom_compliance": {
            "hipaa": {"pass": 0, "fail": 0, "na": 5, "coverage": None, "requirements": []},
            "disclaimer": "advisory",
        },
    }
    dash = _dashboard(scan_data)
    assert dash["compliance_controls"] == {}
    assert dash["severity_distribution"]["low"] == 1
