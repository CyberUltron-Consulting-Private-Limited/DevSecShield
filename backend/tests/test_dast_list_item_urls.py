"""DAST scan list: "URLs scanned" and "Coverage %" come from the crawler's metadata.

The DAST worker stores ``{"results": [...], "metadata": {"urls_included": [...], "urls_excluded": [...], ...}}``
(RabbitMQ/dast_worker/helpers/crawler/crawler.py, dast_worker.py). The list item used to require a top-level
"urls_scanned" key that the worker never writes, so both columns showed 0 for every scan. Found while writing the
F2 (i) tip for these columns.
"""
from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from backend.utilities.db.scan_list_item import return_dast_list_item


def _scan(scan_data, status="success"):
    now = dt.datetime(2026, 11, 11, tzinfo=dt.timezone.utc)
    return SimpleNamespace(
        id=7, title="shop", created_at=now, last_updated=now, scan_status=status, credit_consumed=3.5, info=None,
        owner_user=SimpleNamespace(email="o@example.com", first_name="O", last_name="Wner"),
        scan_metadata={"target_url": "https://shop.example.com"}, scan_data=scan_data,
    )


def test_urls_scanned_and_coverage_from_crawler_metadata():
    data = {
        "results": [{"impact": "High"}],
        "metadata": {"urls_included": ["https://shop.example.com/", "https://shop.example.com/cart",
                                       "https://shop.example.com/login"],
                     "urls_excluded": ["https://shop.example.com/logout"],
                     "check_errors": {"urls_scanned": 3, "failed_urls_per_check": {}}},
    }
    item = return_dast_list_item(_scan(data))
    assert item["urls_scanned"] == 3
    assert item["coverage_percentage"] == 75.0
    assert item["target_url"] == "https://shop.example.com"


def test_no_exclusions_is_full_coverage():
    data = {"results": [], "metadata": {"urls_included": ["https://a.example/"], "urls_excluded": []}}
    item = return_dast_list_item(_scan(data))
    assert item["urls_scanned"] == 1
    assert item["coverage_percentage"] == 100.0


def test_missing_or_malformed_metadata_is_zero():
    for data in ({"results": []}, {"results": [], "metadata": {}}, {"results": [], "metadata": None},
                 {"results": [], "metadata": {"urls_included": "x", "urls_excluded": 5}}):
        item = return_dast_list_item(_scan(data))
        assert item["urls_scanned"] == 0
        assert item["coverage_percentage"] == 0


def test_unfinished_scan_has_no_counts():
    data = {"results": [], "metadata": {"urls_included": ["https://a.example/"], "urls_excluded": []}}
    item = return_dast_list_item(_scan(data, status="started"))
    assert item["urls_scanned"] == 0
