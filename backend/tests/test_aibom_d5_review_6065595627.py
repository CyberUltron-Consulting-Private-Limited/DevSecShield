"""Review 6065595627 of #498 (D5 AI BOM, round 7), m5: the scan list, the team AI BOM dashboard and the team tile
read a stored scan's status the same way, case-insensitively, through one helper. A ``SUCCESS`` row that is partial is
partial on every surface, never on the team tile alone.

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_aibom_d5_review_6065595627.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests import test_aibom_d5_review_6063929550 as R6  # noqa: E402

# the route fixtures (a stand-in Mongo for the dashboard's findings)
api = R6.api
aibom_api = R6.aibom_api
page = R6.page

@pytest.mark.parametrize("status", ["success", "SUCCESS", "Success"])
def test_every_surface_counts_a_partial_scan_whatever_the_status_case(page, tmp_path, status):
    from backend.utilities.dashboard.scan_list import generate_ai_bom_dashboard_data
    from backend.utilities.dashboard.team import _partial_ai_bom_scans
    from backend.utilities.db.scan_list_item import return_ai_bom_list_item

    payload = R6._payload(tmp_path)
    partial = R6._Scan(id=1, scan_type="ai_bom", scan_status=status, scan_data=R6._partial_by_bom_only(payload),
                       info={}, owner_user=R6._OWNER)
    complete = R6._Scan(id=2, scan_type="ai_bom", scan_status=status, scan_data=payload, info={},
                        owner_user=R6._OWNER)
    assert return_ai_bom_list_item(partial)["completeness"] == "partial"
    assert return_ai_bom_list_item(complete)["completeness"] == "complete"
    # the list's risk data is read for the same rows the dashboards read
    assert return_ai_bom_list_item(complete)["risk_data"]["total_models"] >= 1
    team = generate_ai_bom_dashboard_data([partial, complete])
    assert team["card_data"]["partial_scans"] == 1 and team["partial_scan_ids"] == [1]
    assert _partial_ai_bom_scans([partial, complete]) == 1


def test_one_helper_decides_partial_for_every_surface():
    from backend.utilities.pdf import aibom_posture

    assert aibom_posture.scan_succeeded(R6._Scan(scan_status="SUCCESS"))
    assert not aibom_posture.scan_succeeded(R6._Scan(scan_status="failure"))
    assert not aibom_posture.scan_succeeded(R6._Scan(scan_status=None))
    partial = {"ai_bom_scores": {"completeness": "partial"}}
    assert aibom_posture.partial_ai_bom_scan(R6._Scan(scan_status="Success", scan_data=partial))
    assert not aibom_posture.partial_ai_bom_scan(R6._Scan(scan_status="failure", scan_data=partial))
