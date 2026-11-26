"""Review 6063929550 of #498 (D5 AI BOM, round 6), R5-M2 through the routes a customer calls: a partial scan has its
grade AND band withheld on GET /scan, whether the stored scores or only the BOM's metadata say partial; the scan
list, the team AI BOM dashboard and the team tile mark it; the PDF names the scanner in customer words.

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_aibom_d5_review_6063929550.py -q
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests import test_aibom_d5_qa2_profile as PROFILE  # noqa: E402
from backend.tests import test_aibom_d5_review_6037909737 as REVIEW  # noqa: E402

api = PROFILE.api
aibom_api = PROFILE.aibom_api
page = REVIEW.page
AUTH = REVIEW.AUTH

_APP = 'from openai import OpenAI\nc = OpenAI()\nr = c.chat.completions.create(model="gpt-4o", messages=[])\n'


def _payload(tmp_path: Path) -> dict:
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(_APP)
    return PROFILE._engine(root)


def _partial_by_bom_only(payload: dict) -> dict:
    """The BOM's metadata says partial; the stored scores do not (a scan stored before scores carried the flag)."""
    out = copy.deepcopy(payload)
    props = out["ai_bom_json"]["metadata"]["properties"]
    props.append({"name": "aibom:scanner_errors", "value": "net-env: RuntimeError (unexpected)"})
    props.append({"name": "aibom:scan_completeness", "value": "partial"})
    out["ai_bom_scores"] = {k: v for k, v in out["ai_bom_scores"].items() if k != "completeness"}
    return out


class _Scan(SimpleNamespace):  # a stored scan row: any other column reads None
    def __getattr__(self, _name):
        return None


_OWNER = SimpleNamespace(email="o@example.invalid", first_name="O", last_name="W", id=1)


def test_the_scan_get_withholds_grade_and_band_from_the_boms_partial_flag(page, tmp_path):
    _http, _engine, _team, get = page
    body, _base = get(_partial_by_bom_only(_payload(tmp_path)))
    scores = body["scan_metadata"]["ai_bom_scores"]
    assert scores["risk_grade"] == "—"
    assert scores["risk_band"] == "withheld"  # the page card never reads LOW
    assert scores["completeness"] == "partial"
    assert body["scan_metadata"]["ai_bom_completeness"]["status"] == "partial"


def test_a_complete_scan_keeps_its_band(page, tmp_path):
    _http, _engine, _team, get = page
    body, _base = get(_payload(tmp_path))
    scores = body["scan_metadata"]["ai_bom_scores"]
    assert scores["risk_band"] != "withheld" and scores["risk_grade"] != "—"
    assert body["scan_metadata"]["ai_bom_completeness"] is None


def test_the_scan_list_the_team_dashboard_and_the_team_tile_mark_a_partial_scan(page, tmp_path):
    from backend.utilities.dashboard.scan_list import generate_ai_bom_dashboard_data
    from backend.utilities.dashboard.team import _partial_ai_bom_scans
    from backend.utilities.db.scan_list_item import return_ai_bom_list_item

    payload = _payload(tmp_path)
    partial = _Scan(id=1, scan_type="ai_bom", scan_status="success", scan_data=_partial_by_bom_only(payload),
                    info={}, owner_user=_OWNER)
    complete = _Scan(id=2, scan_type="ai_bom", scan_status="success", scan_data=payload, info={}, owner_user=_OWNER)
    assert return_ai_bom_list_item(partial)["completeness"] == "partial"
    assert return_ai_bom_list_item(complete)["completeness"] == "complete"
    team = generate_ai_bom_dashboard_data([partial, complete])
    assert team["card_data"]["partial_scans"] == 1 and team["partial_scan_ids"] == [1]
    assert _partial_ai_bom_scans([partial, complete]) == 1


def test_the_pdf_names_the_scanner_in_customer_words(page, tmp_path):
    http, _engine, _team, get = page
    _body, base = get(_partial_by_bom_only(_payload(tmp_path)))
    text = PROFILE._pdf_text(http.get(f"{base}/export", headers=AUTH).content)
    assert "the network/endpoint scanner did not finish" in text
    assert "based on an incomplete scan" in text
    assert "net-env: RuntimeError (unexpected)" in text  # the technical detail, in the footnote
    assert "Grade withheld: scan incomplete" in text
