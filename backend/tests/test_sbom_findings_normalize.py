"""TDD lock: SBOM finding_data title/description at persist + slim reader."""

from __future__ import annotations

import os
import sys
from typing import Any

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.celery.sbom_finding_normalize import (  # noqa: E402
    normalize_sbom_finding_data,
)


# ── pure normalize ───────────────────────────────────────────────────────────


def test_normalize_missing_title_uses_dependency() -> None:
    out = normalize_sbom_finding_data(
        {"dependency": "requests@2.28.0", "impact": "high"}
    )
    assert out["title"] == "requests@2.28.0"
    assert out["description"] == ""
    assert out["dependency"] == "requests@2.28.0"
    assert out["impact"] == "high"


def test_normalize_blank_title_and_description() -> None:
    out = normalize_sbom_finding_data(
        {"title": "  ", "description": None, "dependency": "pkg@1"}
    )
    assert out["title"] == "pkg@1"
    assert out["description"] == ""


def test_normalize_no_title_no_dependency() -> None:
    out = normalize_sbom_finding_data({"impact": "low"})
    assert out["title"] == "Untitled finding"
    assert out["description"] == ""


def test_normalize_preserves_existing_title_description() -> None:
    row = {
        "title": "Known CVE",
        "description": "Details here",
        "dependency": "pkg@1",
        "impact": "critical",
    }
    out = normalize_sbom_finding_data(row)
    assert out["title"] == "Known CVE"
    assert out["description"] == "Details here"
    assert out is not row  # copy


def test_normalize_none_row() -> None:
    out = normalize_sbom_finding_data(None)
    assert out["title"] == "Untitled finding"
    assert out["description"] == ""


# ── create_findings insert shape ─────────────────────────────────────────────


class _FakeCollection:
    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []
        self.deleted: list[dict[str, Any]] = []

    def delete_many(self, query: dict) -> None:
        self.deleted.append(query)
        self.docs = [d for d in self.docs if d.get("scan_id") != query.get("scan_id")]

    def insert_many(self, docs: list) -> None:
        for d in docs:
            # ScanFindings TypedDict / plain dicts both accepted
            if hasattr(d, "keys"):
                self.docs.append(dict(d))
            else:
                self.docs.append(d)


class _FakeMongo:
    def __init__(self) -> None:
        self._col = _FakeCollection()

    def __getitem__(self, name: str) -> _FakeCollection:
        assert name == "scan_findings"
        return self._col


def test_create_findings_normalizes_sparse_sbom_rows() -> None:
    from backend.utilities.celery.create_findings import create_findings_in_mongo_db

    mongo = _FakeMongo()
    create_findings_in_mongo_db(
        scan_id=42,
        scan_results={
            "results": [
                {"dependency": "lodash@4.17.21", "impact": "medium", "cves": []},
                {
                    "title": "Real title",
                    "description": "Real desc",
                    "dependency": "left-pad@1",
                    "impact": "low",
                },
            ],
            "duration_of_scan": 1.0,
        },
        scan_type="sbom_sca",
        mongo_db=mongo,  # type: ignore[arg-type]
    )
    assert len(mongo._col.docs) == 2
    fd0 = mongo._col.docs[0]["finding_data"]
    fd1 = mongo._col.docs[1]["finding_data"]
    assert fd0["title"] == "lodash@4.17.21"
    assert "description" in fd0 and isinstance(fd0["description"], str)
    assert fd1["title"] == "Real title"
    assert fd1["description"] == "Real desc"


def test_create_findings_iac_not_normalized() -> None:
    """IAC branch must stay passthrough (no title invent)."""
    from backend.utilities.celery.create_findings import create_findings_in_mongo_db

    mongo = _FakeMongo()
    sparse = {"impact": "high", "location": "main.tf"}  # no title
    create_findings_in_mongo_db(
        scan_id=7,
        scan_results={"results": [sparse]},
        scan_type="iac",
        mongo_db=mongo,  # type: ignore[arg-type]
    )
    assert mongo._col.docs[0]["finding_data"] == sparse
    assert "title" not in mongo._col.docs[0]["finding_data"]


# ── reader sparse ────────────────────────────────────────────────────────────


def test_reader_sparse_sbom_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.utilities.db import findings as findings_mod

    sparse_docs = [
        {
            "_id": "abc123",
            "scan_id": 3,
            "finding_data": {
                "dependency": "urllib3@1.26",
                "impact": "high",
                "license_type": "permissive",
            },
            # finding_status deliberately omitted → soft default
        }
    ]

    monkeypatch.setattr(
        findings_mod,
        "get_findings_for_scan_id",
        lambda scan_id: sparse_docs,
    )
    rows = findings_mod.get_findings_for_scan_type("sbom_sca", 3)
    assert len(rows) == 1
    assert rows[0]["title"] == "urllib3@1.26"
    assert rows[0]["description"] == ""
    assert rows[0]["status"] == "not_started"
