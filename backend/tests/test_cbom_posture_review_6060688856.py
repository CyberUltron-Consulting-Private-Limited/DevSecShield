"""Review 6060688856 of PR #499 (round 4): the reviewer's probes P1-P7 as tests.

M1  6058574998 F2 ranked the oldest source above recency, so a source read 120 days ago hid today's read in every
    team view (P4).  Latest observation wins again; the plan, status and ticket are the RESOURCE's
    (``remediation_group``: a group key derived from the cross-source identity, plus every copy's key).
M2  A ticket on another copy's key was hidden when the kept key had a plan without one, and Create tickets opened a
    second Jira issue (P1).
M3  The run list's status filter bucketed rows by their own key (P2).
M4  The team view and waves picked different statuses for one resource (P3): one resolver now.
m1  drift.job_gaps and zs:coverage_gap_count counted enrichment notes (P7).
m2  Unsegmented SSH collector + host agent on one host: two scopes, pinned here and stated in the D7 rubric.
m3  A plan survives the deletion of the source whose row was shown.
n1  ``_hsts_seconds`` crashed on "²" (P5).  n2  One ranking rule for certificates in the run fold and the team view.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomRemediationAssignment,
)
from backend.tests.support import two_aws_roles as AWS2  # noqa: E402
from backend.tests.test_cbom_posture_review_6058574998 import (  # noqa: E402
    T0,
    _asset,
    _job,
    _source,
    _team,
    _two_runs,
)
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import resource_identity as RI  # noqa: E402

NOW = dt.datetime(2026, 11, 24, 6, 0, tzinfo=dt.timezone.utc)


@pytest.fixture()
def engine(tmp_path):
    RI.clear_cache()
    engine = create_engine(f"sqlite:///{tmp_path / 'r6060688856.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    yield engine
    RI.clear_cache()


def _own_key(row: CbomCollectedAsset, ref: str) -> str:
    return ID.stable_key("node", ref, ID.node_identity(row))


def _row(s, run_id: int, source_id: int, kind: str = "kms_key", label: str | None = None) -> CbomCollectedAsset:
    rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id,
                                                   CbomCollectedAsset.source_id == source_id,
                                                   CbomCollectedAsset.asset_type == kind)
                  .order_by(CbomCollectedAsset.id)).all()
    return next(r for r in rows if label is None or ID.node_label(r) == label)


def _item(s, run_id: int, label: str, kind: str = "kms_key") -> dict:
    from backend.utilities.cbom_sources import waves as WAVES

    return next(i for i in WAVES.node_items(s, 1, s.get(CbomCollectionRun, run_id))
                if i["type"] == kind and i["label"] == label)


# ------------------------------------------------------------------------------------------------ M1 (P4)
def test_a_stale_source_never_hides_a_fresh_read(engine):
    from backend.utilities.cbom_sources import collections_view as CV

    with Session(engine) as s:
        _team(s)
        a = _source(s, "A old", "aws_account", "srcA")  # created first: 6058574998 F2 preferred it
        b = _source(s, "B fresh", "aws_account", "srcB")
        for src, at, tag in ((a, T0 - dt.timedelta(days=120), "old"), (b, T0, "fresh")):
            run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=tag, status="done")
            s.add(run)
            s.commit()
            job = _job(s, run, src, at)
            for item in AWS2.items():
                if item["job_id"] == 520:
                    _asset(s, run, job, src, item)
            s.commit()
        kept = CV.resolve([], CV.load_sources_result(s, 1, now=NOW).rows).sources_rows
    by_source: dict[str, int] = {}
    for row in kept:
        by_source[row.collection.source_name] = by_source.get(row.collection.source_name, 0) + 1
    assert by_source == {"B fresh": 229}  # 330e7d0a: {'B fresh': 14, 'A old': 215}


# ------------------------------------------------------------------------------------------------ M2 (P1)
def _jira(monkeypatch, created: list):
    from backend.utilities.cbom_sources import run_tickets as RT

    def fake_create(**kw):
        created.append(kw)
        return {"key": f"SEC-{98 + len(created)}"}

    searched: list[str] = []
    monkeypatch.setattr(RT.JIRA, "create_issue_in_project", fake_create)
    monkeypatch.setattr(RT.JIRA, "find_issue_by_label", lambda url, tok, label, jira_email=None: searched.append(label))
    monkeypatch.setattr(RT, "_jira_creds", lambda team: ("qa@example.com", "token", "https://jira.example"))
    return searched


def test_a_ticket_on_another_copy_is_found_when_the_kept_key_has_a_plan(engine, monkeypatch):
    from backend.utilities.cbom_sources import run_tickets as RT

    first, second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        s.add(CbomCollectionSettings(team_id=1, aws_external_id="x" * 32, jira_project_key="SEC"))
        a_row, b_row = _row(s, second, a_id, "cdn_tls"), _row(s, second, b_id, "cdn_tls")
        label = ID.node_label(a_row)
        s.add(CbomRemediationAssignment(team_id=1, asset_key=_own_key(b_row, "srcB"), source_ref="srcB",
                                        status="in_progress", ticket_key="SEC-7",
                                        ticket_url="https://jira.example/browse/SEC-7"))
        s.add(CbomRemediationAssignment(team_id=1, asset_key=_own_key(a_row, "srcA"), source_ref="srcA",
                                        status="open", wave=2, owner="ops"))
        s.commit()
        item = _item(s, second, label, "cdn_tls")
        assert item["asset_id"] == a_row.id  # run 2: A finished last, its row is shown
        assert item["assignment"]["ticket_key"] == "SEC-7"  # 330e7d0a: None (hidden)
    created: list = []
    _jira(monkeypatch, created)
    out = RT.create_tickets(engine, 1, 1, second, RT.TicketBody(asset_ids=[item["asset_id"]]))
    assert out["created"] == [] and [e["ticket_key"] for e in out["existing"]] == ["SEC-7"]
    assert created == []  # 330e7d0a: one more Jira issue (SEC-99)


def test_a_new_issue_carries_the_resource_label_and_a_search_reads_every_copy_label(engine, monkeypatch):
    from backend.utilities.cbom_sources import run_tickets as RT

    first, _second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        item = _item(s, first, ID.node_label(_row(s, first, a_id, "cdn_tls")), "cdn_tls")
    searched = _jira(monkeypatch, [])
    RT._jira_issue("https://jira.example", "t", "e", "SEC", "Task", item, {}, first, search_first=True)
    assert searched[0] == RT.label_for(item["group_key"]) == RT.label_for(item["asset_key"])
    with Session(engine) as s:
        copies = {_own_key(_row(s, first, a_id, "cdn_tls"), "srcA"), _own_key(_row(s, first, b_id, "cdn_tls"), "srcB")}
    assert {RT.label_for(k) for k in copies} <= set(searched)


# ------------------------------------------------------------------------------------------------ M3 (P2)
def test_the_status_filter_agrees_with_the_status_shown(engine):
    from backend.utilities.cbom_sources import run_assets as RA

    _first, second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        a_row, b_row = _row(s, second, a_id), _row(s, second, b_id)
        s.add(CbomRemediationAssignment(team_id=1, asset_key=_own_key(b_row, "srcB"), source_ref="srcB",
                                        status="in_progress"))
        s.commit()
        run = s.get(CbomCollectionRun, second)
        assert _item(s, second, ID.node_label(a_row))["assignment"]["status"] == "in_progress"
        doing = RA.list_run_assets(s, team_id=1, run=run, params={"page_size": 1000}, status="in_progress")
        todo = RA.list_run_assets(s, team_id=1, run=run, params={"page_size": 1000}, status="not_started")
    assert [i["id"] for i in doing["items"]] == [a_row.id] and doing["total"] == 1  # 330e7d0a: total 0
    assert a_row.id not in {i["id"] for i in todo["items"]}  # 330e7d0a: listed, showing "in_progress"


# ------------------------------------------------------------------------------------------------ M4 (P3)
def test_team_view_and_waves_give_one_status_for_one_resource(engine):
    from backend.utilities.cbom_sources import collections_view as CV

    with Session(engine) as s:
        _team(s)
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="three", status="done")
        s.add(run)
        s.commit()
        srcs = []
        for n, name in enumerate(("A", "B", "C")):
            src = _source(s, name, "aws_account", f"src{name}")
            job = _job(s, run, src, T0 + dt.timedelta(minutes=n))
            for item in AWS2.items():
                if item["job_id"] == 520 and item["type"] == "kms_key":
                    _asset(s, run, job, src, item)
            s.commit()
            srcs.append(src)
        rows = {src.source_uid: _row(s, run.id, src.id) for src in srcs}
        s.add(CbomRemediationAssignment(team_id=1, asset_key=_own_key(rows["srcB"], "srcB"), source_ref="srcB",
                                        status="in_progress"))
        s.add(CbomRemediationAssignment(team_id=1, asset_key=_own_key(rows["srcC"], "srcC"), source_ref="srcC",
                                        status="done", ticket_key="SEC-3"))
        s.commit()
        label = ID.node_label(rows["srcA"])
        waves_status = _item(s, run.id, label)["assignment"]["status"]
        kept = CV.resolve([], CV.load_sources_result(s, 1, now=NOW).rows).sources_rows
        team = next(r for r in kept if r.node_type == "kms_key" and r.row.get("location") == rows["srcA"].location)
    assert waves_status == team.row["remediation_status"] == "done"  # 330e7d0a: waves done, team view in_progress


def test_an_explicit_open_plan_on_the_group_key_wins_everywhere(engine):
    """The group key's own record is the primary: an explicit "open" on it is not overridden by another copy."""
    from backend.utilities.cbom_sources import collections_view as CV

    first, _second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        a_row, b_row = _row(s, first, a_id), _row(s, first, b_id)
        item = _item(s, first, ID.node_label(a_row))
        s.add(CbomRemediationAssignment(team_id=1, asset_key=item["group_key"], source_ref="srcA", status="open"))
        s.add(CbomRemediationAssignment(team_id=1, asset_key=_own_key(b_row, "srcB"), source_ref="srcB",
                                        status="done"))
        s.commit()
        assert _item(s, first, ID.node_label(a_row))["assignment"]["status"] == "open"
        kept = CV.resolve([], CV.load_sources_result(s, 1, now=NOW).rows).sources_rows
        team = next(r for r in kept if r.node_type == "kms_key" and r.row.get("location") == a_row.location)
    assert team.row["remediation_status"] == "open"


# ------------------------------------------------------------------------------------------------ m1 (P7)
def test_drift_and_the_export_count_an_enrichment_row_as_a_note():
    from types import SimpleNamespace

    from backend.utilities.cbom_sources import drift as D
    from backend.utilities.cbom_sources import inventory as INV
    from backend.utilities.cbom_sources.common import ENRICHMENT_ONLY

    note = SimpleNamespace(id=1, asset_type="coverage", target="aws:1", location="arn:aws:acm:us-east-1:1:acm#body-denied",
                           job_id=1, source_id=1, finding=None, attempt=1, created_at=None,
                           facts={"status": "denied", "incomplete": True, "scope": ["arn:aws:acm:us-east-1:1:"],
                                  ENRICHMENT_ONLY: "certificate body"})
    gap = SimpleNamespace(id=2, asset_type="coverage", target="aws:1", location="arn:aws:kms:us-east-1:1:kms#list",
                          job_id=1, source_id=1, finding=None, attempt=1, created_at=None,
                          facts={"status": "denied", "scope": ["arn:aws:kms:us-east-1:1:"]})
    assert [g.prefixes for g in D.job_gaps([note, gap])] == [("arn:aws:kms:us-east-1:1:",)]  # 330e7d0a: both
    props = {p["name"]: p["value"] for p in INV.coverage_gaps([note, gap], {}, {}, {})}
    assert props["zs:coverage_gap_count"] == "1" and props["zs:coverage_note_count"] == "1"


# ------------------------------------------------------------------------------------------------ m2 unsegmented hosts
def _ssh_and_agent(engine, segment: str | None) -> int:
    with Session(engine) as s:
        _team(s)
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="ec3", status="done")
        s.add(run)
        s.commit()
        for n, (name, node) in enumerate((("S-ssh", 11), ("S-agent", 12))):
            src = _source(s, name, "linux_servers", f"u{n}")
            job = _job(s, run, src, T0 + dt.timedelta(minutes=n), node_id=node, node_segment=segment)
            s.add(CbomCollectedAsset(team_id=1, run_id=run.id, job_id=job.id, source_id=src.id, attempt=1,
                                     asset_key=f"k{n}", asset_type="private_key", cdx_type="related-crypto-material",
                                     target="web1", location="/etc/ssl/private/web.key", name="web.key", facts={}))
            s.commit()
        return int(run.id)


def test_an_unsegmented_ssh_collector_and_host_agent_keep_web1_apart(engine):
    """Pinned: without a segment, scan node 11 (SSH) and node 12 (the agent on web1) are two networks, so their
    reads of the single-label host "web1" are two hosts (the safe rule of review 6058574998 F5)."""
    run_id = _ssh_and_agent(engine, None)
    with Session(engine) as s:
        assert RI.run_fold(s, 1, run_id).dropped == {}


def test_a_shared_segment_correlates_them(engine):
    run_id = _ssh_and_agent(engine, "web-lab")
    with Session(engine) as s:
        assert len(RI.run_fold(s, 1, run_id).dropped) == 1


def test_the_d7_rubric_states_the_unsegmented_rule():
    from backend.utilities.cbom_sources import network_estate as NE

    text = " ".join(rule for part, rule in NE.RUBRIC if part == "Divergence")
    assert "correlate only when both nodes share a segment" in text


# ------------------------------------------------------------------------------------------------ m3 source deleted
def test_a_plan_survives_the_deletion_of_the_source_whose_row_was_shown(engine):
    from backend.utilities.cbom_sources import waves as WAVES

    first, _second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        label = ID.node_label(_row(s, first, b_id))
        item = _item(s, first, label)  # run 1 shows B's row (B finished last)
        WAVES.upsert(s, 1, 1, WAVES.AssignmentBulk(run_id=first, items=[WAVES.AssignmentItem(
            asset_key=item["asset_key"], wave=1, status="in_progress", owner="ops")]),
            dt.datetime(2026, 11, 24, 6, 0))
        s.commit()
        assert item["asset_key"] == item["group_key"]  # a new plan goes to the resource's key
        s.delete(s.get(CbomCollectionSource, b_id))  # B deleted: its jobs and rows lose their source
        for job in s.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == b_id)).all():
            job.source_id = None
            s.add(job)
        s.commit()
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="only-A", status="done")
        s.add(run)
        s.commit()
        a = s.get(CbomCollectionSource, a_id)
        job = _job(s, run, a, T0 + dt.timedelta(days=2))
        for row in AWS2.items():
            if row["job_id"] == 520:
                _asset(s, run, job, a, row)
        s.commit()
        later = _item(s, run.id, label)
    assert later["assignment"]["status"] == "in_progress" and later["assignment"]["owner"] == "ops"


# ------------------------------------------------------------------------------------------------ n1 (P5), n2
@pytest.mark.parametrize("value,text", [("²", "A-"), ("31536000.0", "A-"), (31536000.0, "A+"), (-5, "A-")])
def test_hsts_values_never_crash_the_grade(value, text):
    from backend.tests.test_cbom_posture_review_6058574998 import _g

    modern = (["TLSv1.2", "TLSv1.3"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
                                       "TLSv1.3": ["TLS_AES_256_GCM_SHA384"]})
    assert _g(*modern, hsts_max_age=value).text == text  # 330e7d0a: "²" raised ValueError


def test_one_ranking_rule_for_certificates_in_the_run_fold_and_the_team_view():
    import inspect

    from backend.utilities.cbom_sources import collections_view as CV

    older = RI.Observation("a", "1", "res|certificate|arn", True, True, dt.datetime(2026, 1, 1), 1, "A")
    newer = RI.Observation("b", "2", "res|certificate|arn", True, True, dt.datetime(2026, 2, 1), 2, "B")
    assert RI.fold([older, newer]).kept == {"res|certificate|arn": "b"}  # the newest read, as the team view
    assert "preference" not in inspect.signature(RI.Observation).parameters
    assert "\"source_id\"" not in inspect.getsource(CV._rank)  # no per-source preference (6058574998 F2 removed)
