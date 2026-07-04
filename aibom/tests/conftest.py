"""Shared test fixtures.

The level-5 live-cloud scanner is gated on a CLASS attribute
(``LiveCloudScanner.client_factory``). A test that injects a fake provider must
not leak it into later tests; this autouse fixture resets it after every test so
the guard is durable even if a test forgets its own cleanup.
"""

from __future__ import annotations

import pytest

from aibom.scan.scanners.live_cloud_scan import LiveCloudScanner

# ``tests/fixtures/`` holds scan TARGETS (incl. the local chroma clone, which
# ships its own pytest suite). They are inputs to scan_repo, never our tests —
# exclude the whole tree from collection so a present clone can't break the run.
collect_ignore = ["fixtures"]


@pytest.fixture(autouse=True)
def _reset_live_cloud_client() -> None:
    yield
    LiveCloudScanner.client_factory = None
