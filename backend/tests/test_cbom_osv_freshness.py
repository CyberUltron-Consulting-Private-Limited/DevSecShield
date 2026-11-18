"""CB-29: the code-scan PDF and the scan metadata say which crypto-library advisory data the scan matched."""
from __future__ import annotations

from backend.utilities.pdf.cbom_pdf import advisory_text


def test_advisory_text_names_the_snapshot_and_its_age():
    fresh = {"advisory_data": {"snapshot_version": "2026.11.14.1", "generated_at": "2026-11-14", "age_days": 1,
                               "stale": False}}
    assert advisory_text(fresh) == "OSV snapshot 2026.11.14.1, data as of 2026-11-14"
    stale = {"advisory_data": {**fresh["advisory_data"], "age_days": 40, "stale": True,
                               "online": {"asked": 3, "answered": 2}}}
    assert advisory_text(stale) == ("OSV snapshot 2026.11.14.1, data as of 2026-11-14 (stale: 40 days old); "
                                    "refreshed online for 2 of 3 package(s)")
    assert advisory_text({}) is None and advisory_text(None) is None  # scans from before the snapshot
    assert advisory_text({"advisory_data": {"generated_at": None}}) is None
