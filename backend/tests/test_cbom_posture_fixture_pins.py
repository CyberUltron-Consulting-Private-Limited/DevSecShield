"""Pin the committed team-rollup fixture bytes.

The file changes only by a regeneration with ``fixtures/make_cbom_team_rollup_fixture.py`` (whose
Appendix-B oracle must pass), which also updates the pinned digest.  Last regenerated in WP13 for the
round-5 engine; the earlier pin was the posture plan's Base_Commit blob.
"""

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
