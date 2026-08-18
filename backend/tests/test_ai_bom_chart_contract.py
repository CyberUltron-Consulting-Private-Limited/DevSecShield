"""CHART-DATA-CONTRACT (backend / API-response side).

Drives the REAL ``generate_scan_dashboard`` ai_bom branch — the code that builds
the results-page dashboard payload — and asserts the three chart arrays come out
NON-EMPTY:

  * ``severity_distribution``   -> Risk-Metrics radar
  * ``owasp_top_10_llm_issues`` -> OWASP donut (keyed by LLM0x codes)
  * ``compliance_controls``     -> Compliance-Controls panel

Only true externals are stubbed: the DB-backed remediation/status helpers. The
aggregation itself runs for real (skill-testing-anti-patterns).
"""

import json
import os
import sys
import types

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard import scan as scan_mod  # noqa: E402
from backend.utilities.dashboard.scan import generate_scan_dashboard  # noqa: E402

_FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
    "ai_bom_chart_contract_scandata.json",
)


@pytest.fixture(autouse=True)
def _stub_db(monkeypatch):
    """Stub the DB-backed remediation/status helpers (the only true externals)."""
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(scan_mod, "get_remediation_metrics", lambda *a, **k: {})
    monkeypatch.setattr(scan_mod, "get_issue_status_metrics", lambda *a, **k: {})


def _dashboard(scan_data: dict) -> dict:
    fake = types.SimpleNamespace(scan_data=scan_data, id=10_000_001)
    return generate_scan_dashboard("ai_bom", scan_object=fake)


def _finding(
    impact: str,
    owasp: dict | None = None,
    compliance: dict | None = None,
) -> dict:
    return {
        "title": f"asset-{impact}",
        "impact": impact,
        "component_type": "framework",
        "source": "demo",
        "license": "unknown",
        "risk_category": "demo",
        "component_name": f"asset-{impact}",
        "owasp_top_10_llm": owasp or {},
        "compliance_controls": compliance if compliance is not None else {},
    }


def test_engineered_scandata_populates_all_three_charts() -> None:
    scan_data = json.load(open(_FIXTURE))
    dash = _dashboard(scan_data)

    sev = dash["severity_distribution"]
    assert sum(sev.values()) > 0, "severity_distribution empty -> Risk chart blank"
    assert sev["critical"] >= 1 and sev["high"] >= 1 and sev["low"] >= 1, sev

    owasp = dash["owasp_top_10_llm_issues"]
    assert owasp, "owasp_top_10_llm_issues empty -> OWASP blank"
    # Prefer short LLM0x keys; tolerate legacy full-label keys from frozen fixture
    # until the fixture is regenerated after the adapter/dashboard land.
    assert any(
        k.startswith("LLM") for k in owasp
    ), f"expected LLM* OWASP keys, got {list(owasp)}"
    assert dash["compliance_controls"], "compliance_controls empty -> Compliance blank"
    assert dash["card_data"]["total_high_risk_assets"] >= 2


def test_aggregator_buckets_all_four_severities() -> None:
    scan_data = {
        "results": [
            _finding("Critical", {"LLM02": "LLM02:2025 - Sensitive Information Disclosure"}),
            _finding("High"),
            _finding("Medium"),
            _finding("Low"),
        ],
        "ai_bom_compliance": {
            "fda_524b": {
                "pass": 1,
                "fail": 2,
                "na": 0,
                "coverage": 0.33,
                "requirements": [{"id": "524B-1", "verdict": "fail"}],
            },
            "disclaimer": "advisory",
        },
    }
    dash = _dashboard(scan_data)
    sev = dash["severity_distribution"]
    assert sev == {"critical": 1, "high": 1, "medium": 1, "low": 1}, sev
    assert dash["owasp_top_10_llm_issues"] == {"LLM02": 1}, dash["owasp_top_10_llm_issues"]
    assert dash["compliance_controls"], "crafted compliance gap did not aggregate"


def test_owasp_aggregates_by_code_not_label() -> None:
    scan_data = {
        "results": [
            _finding(
                "High",
                {
                    "LLM03": "LLM03:2025 - Supply Chain",
                    "LLM08": "LLM08:2025 - Vector and Embedding Weaknesses",
                },
            ),
            _finding(
                "Medium",
                {"LLM03": "LLM03:2025 - Supply Chain"},
                compliance={
                    "ISO42001_3": "ISO 42001 - Model Lifecycle Management",
                },
            ),
        ],
        "ai_bom_compliance": {"disclaimer": "advisory"},
    }
    dash = _dashboard(scan_data)
    assert dash["owasp_top_10_llm_issues"] == {"LLM03": 2, "LLM08": 1}
    assert "ISO 42001 - Model Lifecycle Management" in dash["compliance_controls"]


def test_no_compliance_gap_yields_empty_controls_not_crash() -> None:
    scan_data = {
        "results": [_finding("Low")],
        "ai_bom_compliance": {
            "hipaa": {
                "pass": 0,
                "fail": 0,
                "na": 5,
                "coverage": None,
                "requirements": [],
            },
            "disclaimer": "advisory",
        },
    }
    dash = _dashboard(scan_data)
    assert dash["compliance_controls"] == {}
    assert dash["severity_distribution"]["low"] == 1
