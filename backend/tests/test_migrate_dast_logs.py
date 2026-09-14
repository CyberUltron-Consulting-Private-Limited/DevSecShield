"""Idempotent DAST cicd_log migration off SAST integrations."""

from __future__ import annotations

import types

from backend.utilities.cicd.migrate_dast_logs import (
    dast_logs_on_sast_query,
    migrate_dast_logs,
)


class _FakeCollection:
    def __init__(self, docs: list[dict]):
        self.docs = docs

    def update_many(self, filt: dict, update: dict):
        ids = set(filt["ci_cd_integration_id"]["$in"])
        want = filt["scan_settings_metadata.scan_type"]
        target = update["$set"]["ci_cd_integration_id"]
        modified = 0
        for doc in self.docs:
            meta = doc.get("scan_settings_metadata") or {}
            if doc.get("ci_cd_integration_id") in ids and meta.get("scan_type") == want:
                doc["ci_cd_integration_id"] = target
                modified += 1
        return types.SimpleNamespace(modified_count=modified)


def test_dast_logs_on_sast_query_matches_int_and_str() -> None:
    query = dast_logs_on_sast_query([4, 7])
    assert query["scan_settings_metadata.scan_type"] == "dast"
    assert 4 in query["ci_cd_integration_id"]["$in"]
    assert "4" in query["ci_cd_integration_id"]["$in"]
    assert 7 in query["ci_cd_integration_id"]["$in"]


def test_migrate_moves_dast_logs_and_leaves_sast() -> None:
    docs = [
        {"ci_cd_integration_id": 4, "scan_settings_metadata": {"scan_type": "dast"}},
        {"ci_cd_integration_id": "4", "scan_settings_metadata": {"scan_type": "dast"}},
        {"ci_cd_integration_id": 4, "scan_settings_metadata": {"scan_type": "sast"}},
        {"ci_cd_integration_id": 9, "scan_settings_metadata": {"scan_type": "dast"}},
    ]
    coll = _FakeCollection(docs)
    moved = migrate_dast_logs(coll, [4], 9)
    assert moved == 2
    assert docs[0]["ci_cd_integration_id"] == 9
    assert docs[1]["ci_cd_integration_id"] == 9
    assert docs[2]["ci_cd_integration_id"] == 4
    assert docs[3]["ci_cd_integration_id"] == 9
    assert migrate_dast_logs(coll, [4], 9) == 0
