"""CBOM chart-data contract (backend / API-response side).

Drives the REAL ``generate_scan_dashboard`` cbom branch — the code that builds
the results-page dashboard payload for CbomResults — and asserts the three
legacy chart arrays come out NON-EMPTY when the adapter enrich + compliance
fallback are present:

  * ``severity_distribution`` -> Risk-Metrics radar
  * ``owasp_top_10_issues``  -> OWASP Top 10 panel
  * ``compliance_controls``  -> Compliance-Controls panel

Cases:
  1. Enriched per-row ``owasp_top_10`` / ``compliance_controls`` maps (adapter)
  2. Empty per-row maps + ``cbom_compliance`` with fail>0 (dashboard fallback)
  3. All-pass / fail=0 compliance + empty row maps -> compliance card empty, no crash

Only true externals are stubbed: the DB-backed remediation/status helpers.
"""

from __future__ import annotations

import os
import sys
import types

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard import scan as scan_mod  # noqa: E402
from backend.utilities.dashboard.scan import generate_scan_dashboard  # noqa: E402

_OWASP = {"CRYPTOGRAPHIC_FAILURES": "A02:2021 - Cryptographic Failures"}
_COMPLIANCE = {
    "ISO27001_A10_CRYPTOGRAPHY": "ISO 27001 - A.10 Cryptography",
    "NIST80053_SC": "NIST 800-53 - System and Communications Protection",
}


@pytest.fixture(autouse=True)
def _stub_db(monkeypatch):
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(scan_mod, "get_remediation_metrics", lambda *a, **k: {})
    monkeypatch.setattr(scan_mod, "get_issue_status_metrics", lambda *a, **k: {})


def _dashboard(scan_data: dict) -> dict:
    fake = types.SimpleNamespace(scan_data=scan_data, id=10_000_042)
    return generate_scan_dashboard("cbom", scan_object=fake)


def _row(
    *,
    title: str,
    impact: str,
    owasp: dict | None = None,
    compliance: dict | None = None,
    strength: str = "weak",
    algo_type: str = "block_cipher",
    quantum_safe: bool | None = False,
) -> dict:
    return {
        "title": title,
        "impact": impact,
        "algorithm_name": title,
        "algorithm_type": algo_type,
        "crypto_strength": strength,
        "quantum_safe": quantum_safe,
        "owasp_top_10": owasp if owasp is not None else {},
        "compliance_controls": compliance if compliance is not None else {},
    }


def test_enriched_rows_populate_owasp_compliance_and_severity() -> None:
    """Adapter-enriched flagged rows must fill all three legacy CBOM cards."""
    scan_data = {
        "results": [
            _row(title="3DES-CBC", impact="High", owasp=_OWASP, compliance=_COMPLIANCE),
            _row(
                title="RSA-2048",
                impact="Medium",
                owasp=_OWASP,
                compliance=_COMPLIANCE,
                strength="strong",
                algo_type="pke",
                quantum_safe=False,
            ),
            _row(
                title="AES-GCM",
                impact="Low",
                owasp={},
                compliance={},
                strength="quantum_safe",
                algo_type="block_cipher",
                quantum_safe=True,
            ),
        ],
        "cbom_json": {"components": [{}, {}, {}]},
        "cbom_compliance": {"disclaimer": "advisory"},
    }
    dash = _dashboard(scan_data)

    sev = dash["severity_distribution"]
    assert sum(sev.values()) == 3, sev
    assert sev["high"] == 1 and sev["medium"] == 1 and sev["low"] == 1, sev

    assert dash["owasp_top_10_issues"], "owasp_top_10_issues empty -> OWASP blank"
    assert "A02:2021 - Cryptographic Failures" in dash["owasp_top_10_issues"]
    assert dash["owasp_top_10_issues"]["A02:2021 - Cryptographic Failures"] == 2

    assert dash["compliance_controls"], "compliance_controls empty -> Compliance blank"
    assert "ISO 27001 - A.10 Cryptography" in dash["compliance_controls"]
    assert "NIST 800-53 - System and Communications Protection" in dash["compliance_controls"]


def test_cbom_compliance_fail_fallback_fills_compliance_card() -> None:
    """Empty per-row maps + cbom_compliance fails still populate compliance."""
    scan_data = {
        "results": [
            _row(title="AES-GCM", impact="Low", strength="quantum_safe", quantum_safe=True),
        ],
        "cbom_json": {"components": [{}]},
        "cbom_compliance": {
            "nist_800_57": {
                "title": "NIST SP 800-57",
                "pass": 1,
                "fail": 3,
                "coverage": 0.25,
                "requirements": [],
            },
            "sebi_cscrf_cbom": {
                "title": "SEBI CSCRF (CBOM)",
                "pass": 0,
                "fail": 2,
                "coverage": 0.0,
                "requirements": [],
            },
            "disclaimer": "advisory",
        },
    }
    dash = _dashboard(scan_data)
    assert dash["owasp_top_10_issues"] == {}, "clean row must not invent OWASP"
    assert dash["severity_distribution"]["low"] == 1
    assert dash["compliance_controls"]["NIST SP 800-57"] == 3
    assert dash["compliance_controls"]["SEBI CSCRF (CBOM)"] == 2


def test_all_pass_compliance_and_empty_rows_yield_empty_controls() -> None:
    scan_data = {
        "results": [
            _row(title="AES-GCM", impact="Low", strength="quantum_safe", quantum_safe=True),
        ],
        "cbom_compliance": {
            "nist_800_57": {
                "title": "NIST SP 800-57",
                "pass": 5,
                "fail": 0,
                "coverage": 1.0,
                "requirements": [],
            },
            "disclaimer": "advisory",
        },
    }
    dash = _dashboard(scan_data)
    assert dash["compliance_controls"] == {}
    assert dash["owasp_top_10_issues"] == {}
    assert dash["severity_distribution"]["low"] == 1
