"""Pin the committed team-rollup fixture to the Base_Commit bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_team_rollup_fixture_matches_the_base_commit_digest() -> None:
    pinned = json.loads(
        (FIXTURES / "base_commit_fixture_digests.json").read_text(encoding="ascii")
    )
    blob = (FIXTURES / "cbom_team_rollup_scans.json").read_bytes()
    assert hashlib.sha256(blob).hexdigest() == pinned["cbom_team_rollup_scans.json"]
