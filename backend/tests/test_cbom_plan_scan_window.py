"""The estimate says which sources wait for their scan window and when a run queued now may start (round 5, G3
item 5): Review & Run showed the window on the Network row only, so a servers or databases run was charged and then
sat "Queued · Outside the scan window"."""
import datetime as dt
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.tests.test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401


def _grid(open_hour: int | None) -> list[list[bool]]:
    return [[h == open_hour for h in range(24)] for _ in range(7)]


def _server_item(api) -> dict:
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    (item,) = [i for i in est["items"] if i["group"] == "servers"]
    return item


def test_estimate_reports_when_a_server_run_outside_the_window_starts(api, world):
    node_id, _t, _ = enroll_node(api)
    api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id))
    settings = api("GET", "/1/cbom/sources/settings").json()
    tz = (settings.get("settings") or settings).get("window_timezone")
    assert tz == "UTC" or tz  # the grid below is read in the team's time zone; UTC by default
    later = (dt.datetime.utcnow().hour + 3) % 24
    r = api("PATCH", "/1/cbom/sources/settings", json={"scan_window": _grid(later), "window_timezone": "UTC"})
    assert r.status_code == 200, r.text
    item = _server_item(api)
    assert item["status"] == "queued" and item["window_applies"] is True
    starts = dt.datetime.strptime(item["window_starts_at"], "%Y-%m-%dT%H:%M:%SZ")
    assert starts.hour == later and starts > dt.datetime.utcnow()

    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": [[True] * 24 for _ in range(7)]})
    item = _server_item(api)
    assert item["window_applies"] is True and item["window_starts_at"] is None  # inside the window: starts now


def test_a_server_with_no_window_limit_never_waits(api, world):
    node_id, _t, _ = enroll_node(api)
    api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id, window="any"))
    later = (dt.datetime.utcnow().hour + 3) % 24
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": _grid(later), "window_timezone": "UTC"})
    item = _server_item(api)
    assert item["status"] == "queued" and item["window_applies"] is False and item["window_starts_at"] is None
