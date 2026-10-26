"""Extract the six MEDIUM PDFs at the fixture's fixed time.

Run from the repository root with the backend environment::

    PYTHONPATH=. backend/.venv/bin/python backend/tests/fixtures/make_medium_base_text.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "backend" / "tests"))

from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    ScanHead,
    fold_scans,
)
from backend.utilities.pdf.cbom_deliverables import DELIVERABLES  # noqa: E402
from support.pdf_text import pdf_pages_text  # noqa: E402

FIXTURES = Path(__file__).resolve().parent
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=timezone.utc)
AS_OF = date(2026, 10, 19)


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def view_from_fixture() -> object:
    raw = json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))
    scans = raw["scans"]
    heads = [
        ScanHead(
            id=scan["id"],
            team_id=scan["team_id"],
            scan_type=scan["scan_type"],
            title=scan["title"],
            status=scan["status"],
            created_at=_ts(scan["created_at"]),
            last_updated=_ts(scan["last_updated"]),
            scan_metadata=scan["scan_metadata"],
        )
        for scan in scans
    ]
    blobs = {scan["id"]: scan["scan_data"] for scan in scans}
    return fold_scans(
        heads,
        lambda ids: {item: blobs[item] for item in ids if item in blobs},
        team_id=1,
        team_name="E2E Demo Team",
        now=NOW,
    )


def main() -> None:
    view = view_from_fixture()
    documents = {}
    for spec in DELIVERABLES.values():
        pages = pdf_pages_text(spec.build(view))
        documents[spec.slug] = pages
        print(spec.slug, len(pages), flush=True)
    payload = {
        "generated_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "as_of": AS_OF.isoformat(),
        "documents": documents,
    }
    (FIXTURES / "medium_base_text.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    blob = (FIXTURES / "cbom_team_rollup_scans.json").read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    (FIXTURES / "base_commit_fixture_digests.json").write_text(
        json.dumps(
            {"base_commit": "f7385517523212e50b20ec6f1947831a5ef19872",
             "cbom_team_rollup_scans.json": digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="ascii",
    )


if __name__ == "__main__":
    main()
