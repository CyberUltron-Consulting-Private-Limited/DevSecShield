"""Lab UI r1 F3: scan #51's results page said PQC readiness 0 % (Safe 0, Broken today 12, Vulnerable 6) while its PDF
and the scan list said 10 % (2 safe): the page counted the finding rows only, the backend every row (an ML-KEM-768
row with no finding is a quantum-safe asset).  Integrator decision: readiness covers every cryptographic asset, as the
backend counts it.  One shared fixture (tests/fixtures/cbom_readiness_parity.json) holds stored rows and the numbers
every view must show; this test checks the backend side (cbom_metrics: the PDF, the scan dashboard and the scan list)
and that ``page_rows`` are what GET scan ``data`` serves; frontend components/cbom/quantumFilter.test.ts counts the
same ``page_rows`` with the page's rule and must get the same numbers.

Browser check after a rebuild: r1 bin/run cbom_results.js and cbom_pdf.js on scan 51: gauge 10 %, Quantum-safe 2.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.cbom_sources.cbom_metrics import CodeRowSummary, summarize_code_rows  # noqa: E402
from backend.utilities.cbom_sources.cbom_rows import page_row  # noqa: E402

CASES = json.loads((Path(__file__).parent / "fixtures" / "cbom_readiness_parity.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"][:40] for c in CASES])
def test_backend_views_show_the_fixture_numbers(case):
    want = case["expected"]
    pdf = summarize_code_rows(case["rows"])  # cbom_pdf and the single-scan dashboard
    listed = CodeRowSummary().add_rows(case["rows"])  # scan_list.generate_cbom_dashboard_data
    for summary in (pdf, listed):
        assert (summary.rows, summary.findings, summary.informational) == (want["rows"], want["findings"],
                                                                           want["informational"])
        assert summary.quantum == {"quantum_safe": want["safe"], "broken_today": want["broken"],
                                   "quantum_vulnerable": want["vulnerable"]}
        assert summary.readiness_pct == want["readiness"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"][:40] for c in CASES])
def test_the_page_gets_every_row_as_page_row_serves_it(case):
    assert [page_row(r) for r in case["rows"]] == case["page_rows"]
    # the page rows count the same as the stored rows (page_row only adds what display_row already decides)
    assert summarize_code_rows(case["page_rows"]).quantum == summarize_code_rows(case["rows"]).quantum


def test_get_scan_serves_page_rows():
    src = (_REPO_ROOT / "backend" / "routers" / "scans.py").read_text()
    assert "scan_result = [page_row(row) for row in scan_result]" in src
    ci = (_REPO_ROOT / "backend" / "utilities" / "cicd" / "cbom_page.py").read_text()
    assert '"data": [page_row(row) for row in rows if isinstance(row, dict)]' in ci
