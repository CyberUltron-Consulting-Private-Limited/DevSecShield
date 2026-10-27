"""The six MEDIUM documents change only by the recorded posture sentences."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "backend" / "tests"))

from backend.utilities.dashboard.cbom_team_rollup import ScanHead, fold_scans  # noqa: E402
from backend.utilities.pdf.cbom_deliverables import DELIVERABLES  # noqa: E402
from support.pdf_text import pdf_pages_text  # noqa: E402

FIXTURES = _REPO / "backend" / "tests" / "fixtures"
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=timezone.utc)
SIX = (
    "scope-baseline-register",
    "methodology-evidence-plan",
    "certificate-estate-register",
    "third-party-assurance-register",
    "pqc-migration-roadmap",
    "board-executive-report",
)
OLD_SCOPE = (
    "Method: static analysis of repositories and uploaded artefacts. It does not include "
    "live-network discovery, HSM/KMS custody or data-at-rest encryption."
)
NEW_SCOPE = (
    "Method: static analysis of repositories and uploaded artefacts, including declared "
    "infrastructure and server configuration (documents #5, #6 and #9) and offline import "
    "of TLS result files. It does not include live-network discovery, inspection of HSM "
    "or KMS custody, or inspection of stored data."
)
REPLACEMENTS = (
    (NEW_SCOPE, OLD_SCOPE),
    (
        "Declared KMS and HSM settings in configuration are assessed. Live HSM firmware, "
        "custodianship, and escrow are not inspected.",
        "No visibility into hardware security modules, key-management services or key custody.",
    ),
    (
        "Data-at-rest encryption is assessed from declared configuration only (document #9); "
        "the live state of databases, object stores and disks is not inspected.",
        "No assessment of data-at-rest encryption in databases, object stores or disks.",
    ),
    (
        "Whether stored data is actually encrypted. Declared settings are assessed in "
        "document #9 and are not proof of operation.",
        "Database, object-store and disk encryption is runtime configuration.",
    ),
)
SCANNER_MARKERS = (
    "posture_iac",
    "posture_server",
    "posture_database",
    "posture_tls_import",
    "posture_verification",
    "posture_linkage",
    "posture_findings",
    "Configuration posture",
)


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _view() -> object:
    raw = json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))
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
        for scan in raw["scans"]
    ]
    blobs = {scan["id"]: scan["scan_data"] for scan in raw["scans"]}
    return fold_scans(
        heads,
        lambda ids: {item: blobs[item] for item in ids if item in blobs},
        team_id=1,
        team_name="E2E Demo Team",
        now=NOW,
    )


def test_six_medium_documents_use_the_recorded_posture_sentences() -> None:
    view = _view()
    pages = {
        slug: " ".join(" ".join(pdf_pages_text(DELIVERABLES[slug].build(view))).split())
        for slug in SIX
    }
    methodology = pages["methodology-evidence-plan"]
    for new, old in REPLACEMENTS:
        assert " ".join(new.split()) in methodology
        assert old not in methodology
    for name in SCANNER_MARKERS:
        if name == "Configuration posture":
            continue
        assert name in methodology
    for slug, text in pages.items():
        assert "ZERO SHIELD" in text, slug
        assert "live-network" in text, slug
        assert "static analysis" in text, slug
