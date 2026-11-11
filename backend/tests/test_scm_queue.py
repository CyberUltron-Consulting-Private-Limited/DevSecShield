"""F3: credits per run, scan policies, the bounded fair queue, scheduled and push-triggered scans.

Everything runs on SQLite with a fake launcher (records what would be sent to Celery and plays the worker); the real
launcher's payloads are checked against the API's own StartScanPayload schema. ``SCM_TEST_PG_URL`` (or
``CBOM_TEST_PG_URL``) also runs the two-dispatcher race on PostgreSQL.

    cd backend && PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r uv run --with pytest python -m pytest \
      tests/test_scm_queue.py -q -p no:cacheprovider
"""
from __future__ import annotations

import datetime as dt
import itertools
import multiprocessing
import os
import sys
from collections import Counter
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "scm-test-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "scm-test-refresh")
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode())

from sqlalchemy import event  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import Scan, Team, TeamMembership, User  # noqa: E402
from backend.utilities.scm.models import (  # noqa: E402
    ScmConnection,
    ScmRepository,
    ScmScanPolicy,
    ScmScanRequest,
    ScmScanRun,
)
from backend.utilities.cbom_sources.crypto import encrypt_secrets  # noqa: E402
from backend.utilities.db.encryption import _get_fernet  # noqa: E402
from backend.utilities.db.schemas import StartScanPayload  # noqa: E402
from backend.utilities.scm import policies as P  # noqa: E402
from backend.utilities.scm import pricing  # noqa: E402
from backend.utilities.scm import queue as Q  # noqa: E402

NOW = dt.datetime(2026, 11, 11, 12, 0, 0)
LANGS = ["Python", "Java", "Go", "TypeScript", "HCL"]


# ----------------------------------------------------------------------------- world
def make_world(engine, *, repos_per_team=None, balances=None):
    repos_per_team = repos_per_team or {1: 12, 2: 4, 3: 2}
    balances = balances or {1: 1000.0, 2: 1000.0, 3: 0.05}
    ids: dict = {"users": {}, "conn": {}, "repos": {}}
    with Session(engine) as s:
        for team, balance in balances.items():
            s.add(Team(id=team, name=f"T{team}", credit_balance=balance))
        s.commit()
        for team in balances:
            u = User(email=f"admin{team}@t.test", password="x", first_name="a", last_name="b", profile_photo=None,
                     default_team_id=team)
            s.add(u)
            s.commit()
            s.add(TeamMembership(team_id=team, user_id=u.id, role="admin"))
            ids["users"][team] = u.id
            c = ScmConnection(team_id=team, owner_user_id=u.id, provider="github", auth_kind="token",
                              name=f"org{team}", name_lower=f"org{team}", api_base="https://api.github.com",
                              scope_kind="org", scope_name=f"org{team}", secret_encrypted=encrypt_secrets({"token": "t"}),
                              secret_fields=["token"], webhook_uid=os.urandom(16).hex())
            s.add(c)
            s.commit()
            ids["conn"][team] = c.id
            ids["repos"][team] = []
            for i in range(repos_per_team.get(team, 0)):
                r = ScmRepository(team_id=team, connection_id=c.id, external_id=f"{team}-{i}",
                                  full_name=f"org{team}/repo-{i:04d}", name=f"repo-{i:04d}", owner=f"org{team}",
                                  web_url=f"https://github.com/org{team}/repo-{i:04d}",
                                  clone_url=f"https://github.com/org{team}/repo-{i:04d}", default_branch="main",
                                  visibility="private", archived=False, fork=False, language=LANGS[i % len(LANGS)],
                                  topics=["pci"] if i % 2 == 0 else [], size_kb=512 * (1 + i % 4), in_scope=True,
                                  scope_reason="matched")
                s.add(r)
                s.commit()
                ids["repos"][team].append(r.id)
    return ids


@pytest.fixture()
def engine(tmp_path):
    _get_fernet.cache_clear()
    eng = create_engine(f"sqlite:///{tmp_path / 'q.db'}", connect_args={"check_same_thread": False})

    @event.listens_for(eng, "connect")
    def _fk(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    SQLModel.metadata.create_all(eng)
    return eng


class FakeLauncher:
    """Stands in for Celery: validates the payload like the API would, records it and returns a task id."""

    def __init__(self, fail_for: set[int] | None = None):
        self.sent: list[dict] = []
        self.fail_for = fail_for or set()
        self.counter = itertools.count(1)

    def __call__(self, engine, scan_type, scan_id, team_id, payload: StartScanPayload) -> str:
        if scan_id in self.fail_for:
            raise RuntimeError("broker down")
        section = getattr(payload, scan_type)
        assert section is not None and section.repo_context is not None
        task_id = f"task-{next(self.counter)}"
        with Session(engine) as s:
            scan = s.get(Scan, scan_id)
            scan.task_id, scan.scan_status = task_id, "pending"
            s.add(scan)
            s.commit()
        self.sent.append({"type": scan_type, "scan_id": scan_id, "team": team_id,
                          "repo_url": section.repo_context.repo_url, "branch": section.repo_context.branch,
                          "token": section.repo_context.PAT, "payload": payload.model_dump(mode="json")})
        return task_id


class FakeWorker:
    """Finishes scans when told to (``finish``), the way get_status_and_update_db stores a result."""

    def __init__(self, engine):
        self.engine = engine
        self.polled: Counter = Counter()

    def __call__(self, engine, scan: Scan) -> None:
        self.polled[scan.id] += 1

    def finish(self, scan_id: int, status: str = "success", results=None):
        with Session(self.engine) as s:
            scan = s.get(Scan, scan_id)
            scan.scan_status = status
            scan.scan_data = {"results": results or []} if status == "success" else {}
            s.add(scan)
            s.commit()


def token_for(_connection):
    return "ghp_testtoken"


def tick(engine, launcher, worker, now=NOW, **caps):
    Q.poll_tick(engine, now, status_reader=worker)
    return Q.dispatch_tick(engine, now, launcher=launcher, token_for=token_for, **caps)


def requests(engine, **where):
    with Session(engine) as s:
        q = select(ScmScanRequest)
        for k, v in where.items():
            q = q.where(getattr(ScmScanRequest, k) == v)
        return s.exec(q.order_by(ScmScanRequest.id)).all()


def balance(engine, team):
    with Session(engine) as s:
        return round(s.get(Team, team).credit_balance, 2)


# ----------------------------------------------------------------------------- pricing
def test_price_per_product_uses_the_worker_rates_and_minimums():
    mb = 1024
    assert pricing.price_c("sast", 1 * mb) == 205  # 1 MB / 0.5 + 0.04/0.836 = 2.0478 -> 2.05
    assert pricing.price_c("iac", 1 * mb) == 200
    assert pricing.price_c("sbom_sca", 50 * mb) == 1  # flat 0.01/0.836 = 0.012 -> 0.01
    assert pricing.price_c("cbom", 10) == 100  # CBOM code scans cost at least 1 credit (D3)
    assert pricing.price_c("cbom", 3 * mb) == 600
    assert pricing.price_c("ai_bom", 0) == 5  # 0.0478 -> 0.05
    assert pricing.price_c("iac", 0) == 1  # never free: at least 0.01
    with pytest.raises(ValueError):
        pricing.price_c("dast", 1)


# ----------------------------------------------------------------------------- policies
def test_policy_winner_is_deterministic_and_pinning_wins():
    pol = [P.PolicyView(id=3, position=10, enabled=True, selector={"topics_any": ["pci"]}, products=["sast"]),
           P.PolicyView(id=1, position=20, enabled=True, selector={}, products=["sbom_sca"]),
           P.PolicyView(id=2, position=10, enabled=False, selector={}, products=["iac"])]
    pci = {"full_name": "o/a", "name": "a", "topics": ["pci"], "archived": False, "fork": False,
           "language": "Go", "visibility": "private", "size_kb": 1}
    other = {**pci, "topics": []}
    assert P.winning_policy(pci, pol) == (pol[0], "selector")
    assert P.winning_policy(other, pol) == (pol[1], "selector")
    assert P.winning_policy(other, list(reversed(pol))) == (pol[1], "selector")  # order of the list never matters
    assert P.winning_policy(pci, pol, pinned_id=1) == (pol[1], "pinned")
    assert P.winning_policy(pci, [pol[2]]) == (None, "none")
    tie = [P.PolicyView(id=9, position=5, enabled=True, selector={}, products=["iac"]),
           P.PolicyView(id=4, position=5, enabled=True, selector={}, products=["sast"])]
    assert P.winning_policy(pci, tie)[0].id == 4  # same position: lower id


def test_schedule_slots():
    daily = P.ScheduleSpec(frequency="daily", time_of_day="02:30", timezone="Asia/Kolkata")
    # 02:30 IST = 21:00 UTC the day before
    assert P.next_run(daily, dt.datetime(2026, 11, 11, 12, 0)) == dt.datetime(2026, 11, 11, 21, 0)
    assert P.next_run(daily, dt.datetime(2026, 11, 11, 21, 0)) == dt.datetime(2026, 11, 12, 21, 0)
    weekly = P.ScheduleSpec(frequency="weekly", time_of_day="03:00", weekday=6, timezone="UTC")
    assert P.next_run(weekly, dt.datetime(2026, 11, 11, 12, 0)) == dt.datetime(2026, 11, 15, 3, 0)  # Sunday
    monthly = P.ScheduleSpec(frequency="monthly", time_of_day="00:15", monthday=28, timezone="UTC")
    assert P.next_run(monthly, dt.datetime(2026, 11, 28, 0, 15)) == dt.datetime(2026, 12, 28, 0, 15)
    assert P.next_run(P.ScheduleSpec(frequency="off"), NOW) is None
    with pytest.raises(ValueError):
        P.ScheduleSpec(frequency="daily", time_of_day="25:00")
    with pytest.raises(ValueError):
        P.ScheduleSpec(frequency="daily", time_of_day="02:00", timezone="Mars/Olympus")


# ----------------------------------------------------------------------------- runs and credits
def test_estimate_then_run_charges_once_and_409s_on_a_changed_price(engine):
    ids = make_world(engine)
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1][:5], products=["iac", "sbom_sca"])
    assert est["scans"] == 10 and est["repos"] == 5 and est["affordable"] is True
    assert est["credits"] == round(sum(pricing.price_c(p, 512 * (1 + i % 4)) for i in range(5)
                                       for p in ("iac", "sbom_sca")) / 100, 2)
    with pytest.raises(Q.EstimateChanged) as changed:
        Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1][:5],
                     products=["iac", "sbom_sca"], expected_credits=est["credits"] + 1, client_request_id="r1",
                     now=NOW)
    assert changed.value.estimate["credits"] == est["credits"]
    assert balance(engine, 1) == 1000.0 and requests(engine) == []
    run = Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1][:5],
                       products=["iac", "sbom_sca"], expected_credits=est["credits"], client_request_id="r1", now=NOW)
    assert run["queued"] == 10 and run["credits"] == est["credits"]
    assert balance(engine, 1) == round(1000.0 - est["credits"], 2)
    # the same client request id is the same run: nothing charged twice
    again = Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1][:5],
                         products=["iac", "sbom_sca"], expected_credits=est["credits"], client_request_id="r1", now=NOW)
    assert again["run_id"] == run["run_id"] and balance(engine, 1) == round(1000.0 - est["credits"], 2)
    # scans already queued are not queued (or charged) again by another run
    with Session(engine) as s:
        assert Q.estimate(s, 1, repo_ids=ids["repos"][1][:5], products=["iac"])["scans"] == 0


def test_insufficient_credits_creates_nothing(engine):
    ids = make_world(engine)
    with Session(engine) as s:
        est = Q.estimate(s, 3, repo_ids=ids["repos"][3], products=["cbom"])
    assert est["affordable"] is False and est["credits"] == 3.0 and est["balance"] == 0.05  # 0.5 MB -> 1, 1 MB -> 2
    with pytest.raises(Q.InsufficientCredits):
        Q.create_run(engine, 3, ids["users"][3], trigger="manual", repo_ids=ids["repos"][3], products=["cbom"],
                     expected_credits=est["credits"], client_request_id="x", now=NOW)
    assert requests(engine) == [] and balance(engine, 3) == 0.05


def test_sast_needs_a_supported_language_and_another_team_s_repos_are_ignored(engine):
    ids = make_world(engine)
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1][:5] + ids["repos"][2], products=["sast"])
    # languages cycle Python, Java, Go, TypeScript, HCL: SAST covers python, java and javascript/typescript only
    assert est["scans"] == 3 and Counter(r for _id, _p, r in est["skipped"]) == {"sast_language": 2}
    assert est["repos"] == 3  # team 2's repositories are not team 1's to scan


def test_cancel_refunds_queued_scans_once(engine):
    ids = make_world(engine)
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1][:4], products=["iac"])
    run = Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1][:4], products=["iac"],
                       expected_credits=est["credits"], client_request_id="c", now=NOW)
    launcher, worker = FakeLauncher(), FakeWorker(engine)
    tick(engine, launcher, worker, max_inflight=1, team_max=1)  # one dispatched, three still queued
    dispatched = requests(engine, status="dispatched")
    assert len(dispatched) == 1
    refunded = Q.cancel_run(engine, 1, run["run_id"])
    queued_price = sum(r.credits_c for r in requests(engine) if r.status == "cancelled")
    assert refunded == queued_price / 100 and refunded > 0
    assert Q.cancel_run(engine, 1, run["run_id"]) == 0  # never twice
    assert balance(engine, 1) == round(1000.0 - est["credits"] + refunded, 2)
    assert requests(engine, status="dispatched")[0].id == dispatched[0].id  # a dispatched scan keeps running


# ----------------------------------------------------------------------------- the dispatcher
def test_caps_are_never_exceeded_and_each_team_gets_its_share(engine):
    ids = make_world(engine, repos_per_team={1: 40, 2: 6, 3: 3}, balances={1: 1e4, 2: 1e4, 3: 1e4})
    for team in (1, 2, 3):
        with Session(engine) as s:
            est = Q.estimate(s, team, repo_ids=ids["repos"][team], products=["sbom_sca"])
        Q.create_run(engine, team, ids["users"][team], trigger="manual", repo_ids=ids["repos"][team],
                     products=["sbom_sca"], expected_credits=est["credits"], client_request_id=f"t{team}", now=NOW)
    launcher, worker = FakeLauncher(), FakeWorker(engine)
    first = tick(engine, launcher, worker, max_inflight=6, team_max=4)
    per_team = Counter(r.team_id for r in requests(engine, status="dispatched"))
    assert len(first) == 6 and per_team == {1: 2, 2: 2, 3: 2}  # water-filling: equal shares, not first-come
    # nothing more while the slots are full
    assert tick(engine, launcher, worker, max_inflight=6, team_max=4) == []
    # drain: finish whatever is in flight each tick; the global cap and the (optional, here 4) per-team cap hold on
    # every tick
    rounds = 0
    while requests(engine, status="queued") and rounds < 100:
        for r in requests(engine, status="dispatched"):
            worker.finish(r.scan_id)
        tick(engine, launcher, worker, max_inflight=6, team_max=4)
        inflight = Counter(r.team_id for r in requests(engine, status="dispatched"))
        assert sum(inflight.values()) <= 6 and max(inflight.values(), default=0) <= 4
        rounds += 1
    for r in requests(engine, status="dispatched"):
        worker.finish(r.scan_id)
    tick(engine, launcher, worker, max_inflight=6, team_max=4)
    assert Counter(r.status for r in requests(engine)) == {"done": 49}
    # the small teams finished long before the big one
    done_at = {}
    for idx, call in enumerate(launcher.sent):
        done_at.setdefault(call["team"], []).append(idx)
    assert max(done_at[3]) < 12 and max(done_at[2]) < 20


def test_a_team_alone_uses_every_slot_and_a_newcomer_takes_the_next_free_ones(engine):
    """Work-conserving water-filling (no per-team limit, the default): one team with a backlog fills the global cap;
    a second team that queues work takes the slots that free up until both have the same number in flight."""
    ids = make_world(engine, repos_per_team={1: 30, 2: 6}, balances={1: 1e4, 2: 1e4})
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1], products=["sbom_sca"])
    Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1], products=["sbom_sca"],
                 expected_credits=est["credits"], client_request_id="big", now=NOW)
    launcher, worker = FakeLauncher(), FakeWorker(engine)
    assert len(tick(engine, launcher, worker, max_inflight=6)) == 6  # alone: all six slots
    with Session(engine) as s:
        est2 = Q.estimate(s, 2, repo_ids=ids["repos"][2], products=["sbom_sca"])
    Q.create_run(engine, 2, ids["users"][2], trigger="manual", repo_ids=ids["repos"][2], products=["sbom_sca"],
                 expected_credits=est2["credits"], client_request_id="small", now=NOW)
    assert tick(engine, launcher, worker, max_inflight=6) == []  # full: nobody is pre-empted
    for r in requests(engine, status="dispatched")[:3]:  # three of team 1's scans finish
        worker.finish(r.scan_id)
    tick(engine, launcher, worker, max_inflight=6)
    assert Counter(r.team_id for r in requests(engine, status="dispatched")) == {1: 3, 2: 3}  # the newcomer caught up
    for r in requests(engine, status="dispatched"):
        worker.finish(r.scan_id)
    tick(engine, launcher, worker, max_inflight=6)
    assert Counter(r.team_id for r in requests(engine, status="dispatched")) == {1: 3, 2: 3}  # equal shares
    # an operator limit per team still holds when it is set
    for r in requests(engine, status="dispatched"):
        worker.finish(r.scan_id)
    tick(engine, launcher, worker, max_inflight=6, team_max=1)  # team 2 has nothing left to queue
    assert Counter(r.team_id for r in requests(engine, status="dispatched")) == {1: 1}


def test_priority_push_before_manual_before_schedule(engine):
    ids = make_world(engine, repos_per_team={1: 6}, balances={1: 1e4})
    repos = ids["repos"][1]
    Q.create_run(engine, 1, ids["users"][1], trigger="schedule", repo_ids=repos[:2], products=["iac"],
                 expected_credits=None, client_request_id="s", now=NOW)
    with Session(engine) as s:
        manual = Q.estimate(s, 1, repo_ids=repos[2:4], products=["iac"])
    Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=repos[2:4], products=["iac"],
                 expected_credits=manual["credits"], client_request_id="m", now=NOW)
    with Session(engine) as s:
        repo = s.get(ScmRepository, repos[5])
        Q.enqueue_push(s, repo, products=["iac"], branch="main", commit_sha="a" * 40, owner_user_id=ids["users"][1],
                       now=NOW)
        s.commit()
    launcher, worker = FakeLauncher(), FakeWorker(engine)
    order = []
    for _ in range(5):
        for r in requests(engine, status="dispatched"):
            worker.finish(r.scan_id)
        tick(engine, launcher, worker, max_inflight=1, team_max=1)
        order += [r.trigger for r in requests(engine, status="dispatched")]
    assert order == ["push", "manual", "manual", "schedule", "schedule"]


def test_push_enqueue_is_idempotent_and_charged_per_request(engine):
    ids = make_world(engine, repos_per_team={1: 2})
    with Session(engine) as s:
        repo = s.get(ScmRepository, ids["repos"][1][0])
        first = Q.enqueue_push(s, repo, products=["sbom_sca", "iac"], branch="main", commit_sha="b" * 40,
                               owner_user_id=ids["users"][1], now=NOW)
        s.commit()
        again = Q.enqueue_push(s, repo, products=["sbom_sca", "iac"], branch="main", commit_sha="b" * 40,
                               owner_user_id=ids["users"][1], now=NOW)
        s.commit()
    assert len(first["queued"]) == 2 and again["queued"] == [] and again["duplicates"] == 2
    assert balance(engine, 1) == round(1000.0 - (pricing.price_c("sbom_sca", 512) + pricing.price_c("iac", 512)) / 100, 2)


def test_dispatch_payload_is_the_api_payload_with_the_connection_token(engine):
    ids = make_world(engine, repos_per_team={1: 3})
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1][:1], products=["sast", "iac", "sbom_sca", "cbom", "ai_bom"])
    Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1][:1],
                 products=["sast", "iac", "sbom_sca", "cbom", "ai_bom"], expected_credits=est["credits"],
                 client_request_id="p", now=NOW)
    launcher, worker = FakeLauncher(), FakeWorker(engine)
    tick(engine, launcher, worker, max_inflight=10, team_max=10)
    assert sorted(c["type"] for c in launcher.sent) == ["ai_bom", "cbom", "iac", "sast", "sbom_sca"]
    for call in launcher.sent:
        assert call["repo_url"] == "https://github.com/org1/repo-0000" and call["branch"] == "main"
        assert call["token"] == "ghp_testtoken"
        StartScanPayload.model_validate(call["payload"])  # exactly what /start accepts
    sast = next(c for c in launcher.sent if c["type"] == "sast")
    assert sast["payload"]["sast"]["app_lang"] == "python"
    with Session(engine) as s:
        scans = s.exec(select(Scan).where(Scan.team_id == 1)).all()
        assert len(scans) == 5
        for scan in scans:
            assert scan.owner_user_id == ids["users"][1] and scan.credit_charged == scan.credit_consumed
            assert scan.scan_metadata["repo_url"] == "https://github.com/org1/repo-0000"
            assert scan.scan_metadata["scm"]["trigger"] == "manual"
            assert "ghp_testtoken" not in str(scan.scan_metadata)


def test_dispatch_failure_and_worker_failure_refund_exactly_once(engine):
    ids = make_world(engine, repos_per_team={1: 2})
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1], products=["iac"])
    Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1], products=["iac"],
                 expected_credits=est["credits"], client_request_id="f", now=NOW)
    start = balance(engine, 1)
    launcher, worker = FakeLauncher(fail_for={1}), FakeWorker(engine)  # scan id 1 cannot be sent
    tick(engine, launcher, worker, max_inflight=5, team_max=5)
    failed = requests(engine, status="failed")
    assert len(failed) == 1 and failed[0].refunded and "could not be sent" in failed[0].error
    assert balance(engine, 1) == round(start + failed[0].credits_c / 100, 2)
    with Session(engine) as s:
        scan = s.get(Scan, failed[0].scan_id)
        assert scan.scan_status == "failure" and scan.credit_charged is None  # nobody refunds it again
    ok = requests(engine, status="dispatched")[0]
    worker.finish(ok.scan_id, "failure")  # the worker failed: get_status_and_update_db refunds credit_charged
    tick(engine, launcher, worker)
    assert requests(engine, id=ok.id)[0].status == "failed" and not requests(engine, id=ok.id)[0].refunded


def test_a_removed_repository_is_skipped_and_refunded(engine):
    ids = make_world(engine, repos_per_team={1: 2})
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1], products=["iac"])
    Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1], products=["iac"],
                 expected_credits=est["credits"], client_request_id="rm", now=NOW)
    with Session(engine) as s:
        repo = s.get(ScmRepository, ids["repos"][1][0])
        repo.removed_at = NOW
        s.add(repo)
        s.commit()
    tick(engine, FakeLauncher(), FakeWorker(engine))
    skipped = requests(engine, status="skipped")
    assert len(skipped) == 1 and skipped[0].refunded and skipped[0].error == "The repository is no longer visible"


def test_completion_closes_requests_records_the_repo_and_finishes_the_run(engine):
    ids = make_world(engine, repos_per_team={1: 2})
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1], products=["sbom_sca"])
    run = Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1], products=["sbom_sca"],
                       expected_credits=est["credits"], client_request_id="d", now=NOW)
    launcher, worker = FakeLauncher(), FakeWorker(engine)
    tick(engine, launcher, worker)
    for r in requests(engine, status="dispatched"):
        worker.finish(r.scan_id, results=[{"dependency": "lodash@4.17.15", "title": "Prototype pollution",
                                           "impact": "high", "cves": ["CVE-2020-8203"]}])
    tick(engine, launcher, worker, now=NOW + dt.timedelta(minutes=5))
    assert {r.status for r in requests(engine)} == {"done"}
    with Session(engine) as s:
        assert s.get(ScmScanRun, run["run_id"]).status == "done"
        repo = s.get(ScmRepository, ids["repos"][1][0])
        assert repo.last_scan_summary["sbom_sca"]["status"] == "success"
        assert repo.last_scan_summary["sbom_sca"]["findings"] == 1


def test_stuck_dispatching_requests_are_requeued(engine):
    ids = make_world(engine, repos_per_team={1: 1})
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1], products=["iac"])
    Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1], products=["iac"],
                 expected_credits=est["credits"], client_request_id="st", now=NOW)
    with Session(engine) as s:
        r = s.exec(select(ScmScanRequest)).one()
        r.status, r.attempts = "dispatching", 1  # a dispatcher claimed it and died before sending it
        r.dispatched_at = NOW - dt.timedelta(minutes=20)
        s.add(r)
        s.commit()
    launcher = FakeLauncher()
    tick(engine, launcher, FakeWorker(engine))
    assert requests(engine)[0].status == "dispatched" and requests(engine)[0].attempts == 2


# ----------------------------------------------------------------------------- scheduled runs
def test_scheduled_policy_fires_once_per_slot_and_skips_when_unaffordable(engine):
    ids = make_world(engine, repos_per_team={1: 6, 3: 2})
    for team in (1, 3):
        with Session(engine) as s:
            s.add(ScmScanPolicy(team_id=team, owner_user_id=ids["users"][team], name="nightly", name_lower="nightly",
                                selector={"topics_any": ["pci"]}, products=["iac", "sbom_sca"], on_push=True,
                                schedule={"frequency": "daily", "time_of_day": "02:00", "timezone": "UTC"},
                                next_run_at=dt.datetime(2026, 11, 12, 2, 0)))
            s.commit()
    assert P.fire_due(engine, dt.datetime(2026, 11, 12, 1, 59)) == []
    fired = P.fire_due(engine, dt.datetime(2026, 11, 12, 2, 0, 30))
    assert len(fired) == 2
    by_team = {f["team_id"]: f for f in fired}
    assert by_team[1]["status"] == "queued" and by_team[1]["queued"] == 6  # 3 pci repos x 2 products
    assert by_team[3]["status"] == "skipped" and "credits" in by_team[3]["message"]
    assert P.fire_due(engine, dt.datetime(2026, 11, 12, 2, 1)) == []  # the slot fired once
    with Session(engine) as s:
        policies = {p.team_id: p for p in s.exec(select(ScmScanPolicy)).all()}
        assert policies[1].next_run_at == dt.datetime(2026, 11, 13, 2, 0) and policies[1].last_status == "queued"
        assert policies[3].last_status == "skipped" and policies[3].next_run_at == dt.datetime(2026, 11, 13, 2, 0)
    assert {r.trigger for r in requests(engine)} == {"schedule"} and len(requests(engine)) == 6


def _fire_in_child(url, when, barrier, out):
    from sqlalchemy import create_engine as ce

    eng = ce(url)
    barrier.wait()
    out.put(len(P.fire_due(eng, dt.datetime.fromisoformat(when))))


def _dispatch_in_child(url, barrier, out):
    from sqlalchemy import create_engine as ce

    eng = ce(url)
    barrier.wait()
    out.put(Q.dispatch_tick(eng, NOW, launcher=FakeLauncher(), token_for=token_for, max_inflight=5, team_max=5))


PG_URL = os.environ.get("SCM_TEST_PG_URL") or os.environ.get("CBOM_TEST_PG_URL")


@pytest.mark.skipif(not PG_URL, reason="set SCM_TEST_PG_URL (or CBOM_TEST_PG_URL) to run against PostgreSQL")
def test_two_schedulers_and_two_dispatchers_on_postgres():
    """A slot fires once and the caps hold when two processes tick at the same instant (advisory lock + CAS)."""
    pg = create_engine(PG_URL)
    SQLModel.metadata.drop_all(pg)
    SQLModel.metadata.create_all(pg)
    ids = make_world(pg, repos_per_team={1: 20}, balances={1: 1e4})
    with Session(pg) as s:
        s.add(ScmScanPolicy(team_id=1, owner_user_id=ids["users"][1], name="n", name_lower="n", selector={},
                            products=["iac"], schedule={"frequency": "daily", "time_of_day": "02:00", "timezone": "UTC"},
                            next_run_at=dt.datetime(2026, 11, 12, 2, 0)))
        s.commit()
    ctx = multiprocessing.get_context("fork")
    barrier, out = ctx.Barrier(2), ctx.Queue()
    procs = [ctx.Process(target=_fire_in_child, args=(PG_URL, "2026-11-12T02:00:05", barrier, out)) for _ in range(2)]
    [p.start() for p in procs]
    [p.join(60) for p in procs]
    assert sorted(out.get(timeout=5) for _ in procs) == [0, 1]
    assert len(requests(pg)) == 20
    barrier, out = ctx.Barrier(2), ctx.Queue()
    procs = [ctx.Process(target=_dispatch_in_child, args=(PG_URL, barrier, out)) for _ in range(2)]
    [p.start() for p in procs]
    [p.join(60) for p in procs]
    dispatched = [out.get(timeout=5) for _ in procs]
    assert sum(len(d) for d in dispatched) == 5 and len(set(itertools.chain(*dispatched))) == 5
    assert len(requests(pg, status="dispatched")) == 5
    SQLModel.metadata.drop_all(pg)
