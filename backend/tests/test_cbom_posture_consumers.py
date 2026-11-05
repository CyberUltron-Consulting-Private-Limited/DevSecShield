"""Consumers of a posture scan: dashboard count, metadata, and findings."""

from __future__ import annotations

import sys
import types
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from backend.utilities.celery import create_findings
from backend.utilities.dashboard import scan as dashboard
from backend.utilities.dashboard.scan_metadata import get_scan_metadata


class _Findings:
    def __init__(self) -> None:
        self.docs: list[object] = []

    def delete_many(self, _query: object) -> None:
        self.docs.clear()

    def insert_many(self, docs: list[object]) -> None:
        self.docs.extend(docs)


class _Record:
    def __init__(self, **kwargs: object) -> None:
        self.__dict__.update(kwargs)


def test_dashboard_count_includes_fact_components(monkeypatch) -> None:
    """A configuration-posture fact the engine flagged is a row of the inventory table, so it counts as a crypto asset.

    rev4 M2: the card is those rows (``CodeRowSummary.crypto_assets``: findings + informational) on the scan page and
    the scan list alike, no longer ``len(cbom_json.components)``, which also counted the crypto libraries and clean
    facts the table never lists and so disagreed with the scan list."""
    from backend.utilities.cbom_sources.cbom_metrics import summarize_code_rows

    monkeypatch.setattr(dashboard, "get_findings_for_scan_id", lambda **_kwargs: [])
    rows = [{"title": "AES", "impact": None, "finding_codes": []},
            {"impact": "High", "name": "plain", "finding_codes": ["UNENCRYPTED_AT_REST"]}]
    scan = types.SimpleNamespace(
        id=7,
        scan_data={
            "results": rows,
            "cbom_json": {
                "components": [
                    {"bom-ref": "crypto-algo-aes", "name": "AES"},
                    {
                        "bom-ref": "crypto-cfg_plain",
                        "name": "relational_db: aws_db_instance.plain",
                        "properties": [{"name": "crypto:factSchema", "value": "1"}],
                    },
                ]
            },
        },
    )
    out = dashboard.generate_scan_dashboard("cbom", scan_object=scan)
    assert out["card_data"]["total_crypto_assets"] == 2 == summarize_code_rows(rows).crypto_assets
    assert out["card_data"]["total_crypto_vulnerabilities"] == 1 and out["card_data"]["total_informational"] == 1


def test_metadata_does_not_surface_cbom_posture() -> None:
    scan = types.SimpleNamespace(
        scan_metadata={},
        scan_data={
            "results": [],
            "cbom_posture": {"schema_version": 1, "facts": []},
        },
    )
    out = get_scan_metadata("cbom", scan)
    assert "cbom_posture" not in out


def test_posture_result_row_is_stored_as_a_finding(monkeypatch) -> None:
    findings = _Findings()
    monkeypatch.setattr(create_findings, "ScanFindings", _Record)
    create_findings.create_findings_in_mongo_db(
        7,
        {
            "results": [
                {"bom_ref": "crypto-cfg_plain", "name": "relational_db: plain"},
                {"bom_ref": "crypto-algo-aes", "name": "AES"},
            ]
        },
        "cbom",
        {"scan_findings": findings},
    )
    refs = [doc.finding_data["bom_ref"] for doc in findings.docs]
    assert refs == ["crypto-cfg_plain", "crypto-algo-aes"]
