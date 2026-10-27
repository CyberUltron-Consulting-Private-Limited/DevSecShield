"""Ledger rows for posture codes, coverage families, and import formats."""

from __future__ import annotations

import json
from pathlib import Path

from aibom.cbom.posture.findings import POSTURE_CODES

REPO = Path(__file__).resolve().parents[2]
LEDGER = REPO / "docs" / "cbom-research" / "LEDGER.md"
COVERAGE = REPO / "aibom" / "src" / "aibom" / "cbom" / "data" / "coverage_table.json"
FORMATS = REPO / "aibom" / "src" / "aibom" / "cbom" / "data" / "tls_import_formats.json"
SNIFF_FORMATS = ("nmap", "sslyze", "testssl_flat", "testssl_pretty")


def _providers() -> set[str]:
    payload = json.loads(COVERAGE.read_text(encoding="utf-8"))
    return {row["provider"] for row in payload["rows"]}


def _format_ids() -> set[str]:
    payload = json.loads(FORMATS.read_text(encoding="utf-8"))
    return {row["id"] for row in payload["rows"]}


def test_ledger_names_every_posture_code_family_and_import_format() -> None:
    text = LEDGER.read_text(encoding="utf-8")
    missing = sorted(
        code for code in POSTURE_CODES if f"posture-code:{code}" not in text
    )
    assert missing == []
    missing_families = sorted(
        name for name in _providers() if f"coverage-family:{name}" not in text
    )
    assert missing_families == []
    required = _format_ids() | set(SNIFF_FORMATS)
    missing_formats = sorted(
        name for name in required if f"import-format:{name}" not in text
    )
    assert missing_formats == []
