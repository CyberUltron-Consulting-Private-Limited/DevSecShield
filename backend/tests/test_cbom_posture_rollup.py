"""WP10: posture fields on the team roll-up. Python 3.10."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard import cbom_team_rollup as roll  # noqa: E402

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
CANARY = "CANARY-POSTURE-SECRET"


def _compliance() -> dict:
    return {
        "nist_800_57": {
            "pass": 1,
            "pass_with_evidence": 0,
            "fail": 0,
            "out_of_scope": 0,
            "not_bom_evidenceable": 0,
            "na": 0,
            "coverage": None,
        }
    }


def blob(posture=None, *, present: bool = True) -> dict:
    data = {
        "results": [],
        "cbom_json": {"specVersion": "1.6", "components": []},
        "cbom_distributions": {"pqc": {}},
        "cbom_compliance": _compliance(),
    }
    if present:
        data["cbom_posture"] = {} if posture is None else posture
    return data


def marker(facts=(), **extra) -> dict:
    block = {
        "schema_version": 1,
        "lanes": ["posture_terraform"],
        "failed_lanes": [],
        "facts": list(facts),
        "imports": [],
        "diagnostics": [],
        "diagnostic_totals": {},
        "data_tables": [],
        "counts": {},
        "truncated": False,
        "dropped": {},
    }
    block.update(extra)
    return block


def fact(fact_id: str, **extra) -> dict:
    row = {
        "id": fact_id,
        "kind": "object_store",
        "provider": "aws",
        "format": "terraform",
        "verdict": "NOT_ENCRYPTED",
        "native_type": "aws_s3_bucket",
        "address": fact_id,
        "path": "main.tf",
        "line": 1,
        "impact": "High",
        "finding_codes": ["UNENCRYPTED_AT_REST"],
    }
    row.update(extra)
    return row


def head(
    scan_id: int,
    *,
    age_days: int = 1,
    repo: str = "https://github.com/o/r",
    status: str = "success",
    team: int = 1,
    meta: dict | None = None,
) -> roll.ScanHead:
    created = NOW - timedelta(days=age_days)
    return roll.ScanHead(
        id=scan_id,
        team_id=team,
        scan_type="cbom",
        title=f"scan-{scan_id}",
        status=status,
        created_at=created,
        last_updated=created + timedelta(minutes=2),
        scan_metadata=meta
        if meta is not None
        else {"zip_file_used": False, "repo_url": repo, "branch": "main"},
    )


def fold(pairs, **kwargs):
    blobs = {item.id: data for item, data in pairs}
    seen: list[list[int]] = []

    def load(ids):
        seen.append(list(ids))
        return {scan_id: blobs[scan_id] for scan_id in ids if scan_id in blobs}

    view = roll.fold_scans(
        [item for item, _data in pairs],
        load,
        team_id=kwargs.pop("team_id", 1),
        team_name="Posture Team",
        now=NOW,
        **kwargs,
    )
    return view, seen


def _text_of(view) -> str:
    parts = list(view.warnings) + list(view.posture.warnings)
    for agg in (*view.posture.facts, *view.posture.previously_seen):
        parts.append(repr(agg.fact))
    for row in view.posture.sources:
        parts.append(row.reason or "")
        parts.append(" ".join(row.lanes))
        parts.append(" ".join(row.failed_lanes))
    return "\n".join(parts)


def test_fold_limits_stay_at_the_wp1_values():
    assert roll.HISTORY_WINDOW == 200
    assert roll.HARD_MAX_SCANS == 1000
    assert roll.BATCH_SIZE == 20
    assert roll.MAX_POSTURE_ACCS == 100_000


def test_posture_dataclasses_construct_and_zero_is_empty():
    counts = roll.PostureCounts.zero()
    assert counts.facts == 0
    assert counts.kms.keys == 0
    assert counts.tri_state["at_rest"].coverage is None
    assert counts.tri_state["transport"].pass_ == 0
    empty = roll.PostureView.empty()
    assert empty.state == "none"
    assert empty.previously_seen_exact is True
    assert empty.counts.facts == 0
    moment = NOW
    roll.PostureFactAgg(
        source_key="repo:x",
        fact_id="a",
        current=False,
        first_seen=moment,
        last_seen=moment,
        scan_count=1,
        last_scan_id=1,
        fact={"id": "a"},
    )
    roll.PostureSourceAgg(
        key="repo:x",
        label="x",
        state="not_assessed",
        reason="rescan_needed",
        current_scan_id=1,
        last_scanned=moment,
        zero_facts=False,
        truncated=False,
        dropped=0,
        lanes=(),
        failed_lanes=(),
    )
    roll.PostureScan()
    roll.KmsCounts()
    roll.TriState()


def test_a_bad_posture_record_warns_without_echoing_scanned_text():
    poisoned = {
        "schema_version": CANARY,
        "lanes": [CANARY],
        "failed_lanes": [CANARY],
        "facts": [CANARY, {"kind": "object_store", "address": CANARY}],
        "imports": [CANARY],
        "diagnostics": [{"code": CANARY, "path": CANARY}],
    }
    view, _seen = fold([(head(1), blob(poisoned))])
    row = view.posture.sources[0]
    assert row.state == "malformed"
    assert row.reason == "malformed"
    assert row.zero_facts is False
    assert view.posture.counts.facts == 0
    assert view.posture.counts.tri_state["at_rest"].pass_ == 0
    assert view.posture.counts.tri_state["at_rest"].coverage is None
    assert any(line.startswith("scan #1: cbom_posture") for line in view.warnings)
    assert len(view.posture.warnings) >= 1
    assert CANARY not in _text_of(view)


def test_current_facts_come_from_the_newest_scan_only():
    older = marker(
        [
            fact("kept", verdict="ENCRYPTED_DECLARED", finding_codes=[]),
            fact("gone", address="only-older"),
        ]
    )
    newer = marker([fact("kept", verdict="NOT_ENCRYPTED")])
    created_old = NOW - timedelta(days=10)
    view, _seen = fold(
        [
            (head(2, age_days=1), blob(newer)),
            (head(1, age_days=10), blob(older)),
        ]
    )
    assert [agg.fact_id for agg in view.posture.facts] == ["kept"]
    current = view.posture.facts[0]
    assert current.current is True
    assert current.fact["verdict"] == "NOT_ENCRYPTED"
    assert current.scan_count == 2
    assert current.first_seen == created_old
    assert current.last_seen == NOW - timedelta(days=1)
    assert current.last_scan_id == 2
    assert [agg.fact_id for agg in view.posture.previously_seen] == ["gone"]
    previous = view.posture.previously_seen[0]
    assert previous.current is False
    assert "finding_codes" not in previous.fact
    assert view.posture.counts.facts == 1
    assert view.posture.counts.findings_by_code == {"UNENCRYPTED_AT_REST": 1}
    assert view.posture.counts.facts_with_findings_by_impact["High"] == 1


def test_facts_are_not_merged_across_sources_and_order_does_not_matter():
    left = marker([fact("bucket", provider="aws")])
    right = marker([fact("bucket", provider="gcp")])
    pairs = [
        (head(1, repo="https://github.com/o/left"), blob(left)),
        (head(2, repo="https://github.com/o/right"), blob(right)),
    ]
    forward, _seen = fold(pairs)
    backward, _seen = fold(list(reversed(pairs)), batch_size=1)
    assert forward.posture.counts.facts == 2
    assert {agg.fact["provider"] for agg in forward.posture.facts} == {"aws", "gcp"}
    assert [agg.fact_id for agg in forward.posture.facts] == [
        agg.fact_id for agg in backward.posture.facts
    ]
    assert forward.fingerprint == backward.fingerprint
    assert len({agg.source_key for agg in forward.posture.facts}) == 2


def test_posture_payload_does_not_move_the_fingerprint():
    one = head(1)
    bare, _seen = fold([(one, blob(present=False))])
    marked, _seen = fold([(one, blob(marker([fact("bucket")])))])
    assert bare.fingerprint == marked.fingerprint
    assert len(bare.fingerprint) == 12


def test_newest_facts_survive_the_accumulator_cap(monkeypatch):
    monkeypatch.setattr(roll, "MAX_POSTURE_ACCS", 1)
    newest = marker([fact("current-a"), fact("current-b")])
    older = marker([fact("current-a"), fact("old-only", address="old-only")])
    view, _seen = fold(
        [
            (head(2, age_days=1), blob(newest)),
            (head(1, age_days=5), blob(older)),
        ]
    )
    assert {agg.fact_id for agg in view.posture.facts} == {"current-a", "current-b"}
    assert view.posture.previously_seen_exact is False
    assert view.posture.counts.facts == 2
    assert all(agg.fact_id != "old-only" for agg in view.posture.previously_seen)


def test_an_older_full_dict_is_demoted_when_a_newer_scan_arrives_later():
    old_head = head(1, age_days=5)
    new_head = head(2, age_days=1)
    old_facts = roll.extract_scan_facts(
        old_head,
        blob(
            marker(
                [
                    fact("shared", verdict="ENCRYPTED_DECLARED", note=CANARY),
                    fact("only-old", note=CANARY),
                ]
            )
        ),
    )
    new_facts = roll.extract_scan_facts(
        new_head,
        blob(marker([fact("shared", verdict="NOT_ENCRYPTED")])),
    )
    acc = roll._SourceAcc()
    accs = roll._PostureAccs()
    rank_old = (old_facts.created_at, old_facts.scan_id)
    rank_new = (new_facts.created_at, new_facts.scan_id)
    acc.newest, acc.newest_rank = old_facts, rank_old
    roll._merge_posture(accs, acc, old_facts, rank_old)
    acc.newest, acc.newest_rank = new_facts, rank_new
    roll._merge_posture(accs, acc, new_facts, rank_new)
    shared = accs[(old_facts.source_key, "shared")]
    only_old = accs[(old_facts.source_key, "only-old")]
    assert shared.full is True
    assert shared.fact["verdict"] == "NOT_ENCRYPTED"
    assert only_old.full is False
    assert set(only_old.fact) == {
        "id",
        "kind",
        "native_type",
        "address",
        "path",
        "verdict",
    }
    assert CANARY not in repr(only_old.fact)


def test_register_cap_reports_the_omitted_rows(monkeypatch):
    monkeypatch.setattr(roll, "POSTURE_REGISTER_CAP", 1)
    rows = [fact("k1", kind="kms_key"), fact("k2", kind="kms_key")]
    view, _seen = fold([(head(1), blob(marker(rows)))])
    assert view.posture.counts.facts == 2
    assert len(view.posture.facts) == 2
    assert view.posture.omitted["kms_keys"] == 1


def test_data_file_keeps_the_oldest_valid_as_of_of_current_scans():
    older = marker(
        data_tables=[
            {"name": "keys.json", "data_version": "1", "valid_as_of": "2024-01-01"}
        ]
    )
    newer = marker(
        data_tables=[
            {"name": "keys.json", "data_version": "9", "valid_as_of": "2026-06-01"}
        ]
    )
    view, _seen = fold(
        [
            (head(1, repo="https://github.com/o/old"), blob(older)),
            (head(2, repo="https://github.com/o/new"), blob(newer)),
        ]
    )
    assert view.posture.data_tables == (
        {"name": "keys.json", "data_version": "1", "valid_as_of": "2024-01-01"},
    )


def test_omitted_kms_rotation_is_unknown_and_raises_no_finding():
    google = fact(
        "google-key",
        kind="kms_key",
        provider="gcp",
        verdict="ENCRYPTED_PROVIDER_DEFAULT",
        finding_codes=[],
        impact="Low",
        signals={},
    )
    azure = fact(
        "azure-key",
        kind="kms_key",
        provider="azure",
        verdict="UNKNOWN",
        finding_codes=[],
        impact="Low",
        signals={"rotation": "not_applicable"},
    )
    hinted = fact("dev-bucket", non_production_hint="lab")
    view, _seen = fold([(head(1), blob(marker([google, azure, hinted])))])
    kms = view.posture.counts.kms
    assert kms.keys == 2
    assert kms.rotation_unknown == 1
    assert kms.rotation_not_applicable == 1
    assert kms.rotation_disabled == 0
    assert "KMS_KEY_ROTATION_DISABLED" not in view.posture.counts.findings_by_code
    assert view.posture.counts.tri_state["at_rest"].fail == 1


def test_a_tier_a_scan_without_a_marker_stays_tier_a_and_not_assessed():
    view, _seen = fold([(head(1), blob(present=False))])
    assert view.sources[0].current_tier == "A"
    assert view.sources[0].current_fidelity == "full"
    row = view.posture.sources[0]
    assert row.state == "not_assessed"
    assert row.reason == "rescan_needed"
    assert row.zero_facts is False
    assert view.posture.state == "not_assessed"
    assert roll.posture_active(view) is False


def test_failed_latest_falls_back_and_ignores_the_failed_blob():
    success = marker([fact("live")])
    failed = blob(marker([fact("from-failed-blob", address=CANARY)]))
    view, seen = fold(
        [
            (head(2, age_days=1, status="failure"), failed),
            (head(1, age_days=8), blob(success)),
        ]
    )
    assert view.sources[0].last_attempt_status == "failure"
    assert view.sources[0].current_scan_id == 1
    assert [agg.fact_id for agg in view.posture.facts] == ["live"]
    assert CANARY not in _text_of(view)
    assert all(2 not in call for call in seen)


def test_an_uploaded_bom_without_a_marker_is_not_a_rescan():
    meta = {"cbom_file_used": True, "zip_file_used": False, "repo_url": None}
    view, _seen = fold([(head(1, meta=meta), blob(present=False))])
    row = view.posture.sources[0]
    assert row.state == "not_assessed"
    assert row.reason == "uploaded_bom_file"
    assert row.zero_facts is False


def test_static_and_imported_endpoints_pair_only_on_the_same_string():
    static = fact(
        "static",
        kind="tls_endpoint",
        verdict="ENCRYPTED_DECLARED",
        finding_codes=[],
        net={"endpoints": ["db.internal:443"], "min": "1.2"},
    )
    imported = fact(
        "imported",
        kind="tls_endpoint",
        provider="import",
        verdict="NOT_ENCRYPTED",
        finding_codes=["KNOWN_TLS_VULNERABILITY"],
        net={
            "endpoint": "db.internal:443",
            "protocols": [{"version": "1.0", "status": "offered"}],
        },
    )
    other = fact(
        "other",
        kind="tls_endpoint",
        verdict="UNKNOWN",
        finding_codes=[],
        net={"endpoint": "other.internal:443"},
    )
    view, _seen = fold(
        [
            (head(1, repo="https://github.com/o/cfg"), blob(marker([static]))),
            (
                head(2, repo="https://github.com/o/scan"),
                blob(marker([imported, other])),
            ),
        ]
    )
    by_id = {agg.fact_id: agg for agg in view.posture.facts}
    assert by_id["static"].discrepancy is True
    assert by_id["imported"].discrepancy is True
    assert by_id["static"].paired_with == f"{by_id['imported'].source_key}|imported"
    assert by_id["imported"].paired_with == f"{by_id['static'].source_key}|static"
    assert by_id["other"].paired_with is None
    assert by_id["other"].discrepancy is False


def test_a_foreign_team_canary_never_enters_the_view():
    foreign = head(9, team=2)
    own = head(1)
    view, seen = fold(
        [
            (foreign, blob(marker([fact("x", address=CANARY)]))),
            (own, blob(marker([fact("ok")]))),
        ]
    )
    assert view.posture.counts.facts == 1
    assert CANARY not in _text_of(view)
    assert all(9 not in call for call in seen)
