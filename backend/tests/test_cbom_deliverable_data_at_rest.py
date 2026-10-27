"""WP11c: Data-at-rest encryption assessment PDF (#9)."""

from __future__ import annotations

import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.tests.support.pdf_text import pdf_text  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import LibAgg, TeamCbomView  # noqa: E402
from backend.utilities.pdf import cbom_data_at_rest_pdf as data_pdf  # noqa: E402
from backend.utilities.pdf.report_branding import REPORT_META  # noqa: E402

SENTENCE = "stored data was not inspected"
_NOW = datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc)


def _bare() -> TeamCbomView:
    return TeamCbomView(
        team_id=7,
        team_name="Posture Team",
        generated_at=_NOW,
        as_of=date(2026, 10, 26),
        fingerprint="abcdef12",
    )


def _with_posture() -> TeamCbomView:
    view = _bare()
    view.included = 1
    view.eligible = 1
    view.fidelity_full = 1
    view.libs = (
        LibAgg(key="cryptography", name="cryptography", current_source_keys=("payments",), current=True),
    )
    view.posture = {
        "sources": [{"label": "payments", "status": "assessed", "fact_count": 1}],
        "facts": [
            {
                "id": "logs",
                "kind": "object_store",
                "provider": "aws",
                "address": "logs-bucket",
                "at_rest": "NOT_ENCRYPTED",
                "impact": "High",
                "location": "s3.tf:1",
                "key_management": "none",
                "declared": {"system": "billing", "classification": "restricted"},
                "finding_codes": ["UNENCRYPTED_AT_REST"],
            }
        ],
        "counts": {"facts": 1, "by_classification": {"restricted": 1}},
    }
    return view


def _visible(raw: bytes) -> str:
    """Text from the content-stream reader in ``backend/tests/support/pdf_text.py``."""
    return re.sub(r"\s+", " ", pdf_text(raw))


def test_report_key_is_registered():
    assert data_pdf.REPORT_KEY == "cbom_data_at_rest"
    assert data_pdf.REPORT_KEY in REPORT_META


def test_empty_view_pdf_states_that_stored_data_was_not_inspected():
    raw = data_pdf.build_pdf(_bare())
    assert raw.startswith(b"%PDF-")
    assert len(raw) > 3000
    visible = _visible(raw)
    assert SENTENCE in visible
    assert "no classification was declared" in visible
    assert "no backup retention or point-in-time recovery setting was declared" in visible


def test_duck_typed_posture_block_prints_declared_linkage_without_changing_the_limit():
    raw = data_pdf.build_pdf(_with_posture())
    visible = _visible(raw)
    assert raw.startswith(b"%PDF-")
    assert len(raw) > 3000
    assert SENTENCE in visible
    assert "logs-bucket" in visible
    assert "declared: billing" in visible
    assert "capability evidence, not proof that stored data is protected" in visible
    assert "cryptography" in visible
