"""F3 revival: repository scans from the fair queue are charged, estimated and refunded through the same path as a scan
started with /start (no free scans, no double refunds), and the SCM token never reaches a log or a stored row.

* Pricing: the minimum charge comes from ``utilities/scan/credit_estimate.py`` (the one /start applies).
* A dispatched scan is a Scan row like a /start one: ``credit_consumed`` = ``credit_charged`` = the price the run took,
  ``credit_estimate`` = ``credit_estimate.input_digest`` of the payload (without its token) + the price.
* Refunds: the REAL ``get_status_and_update_db`` (worker failure) and the REAL ``cancel_scan`` (scan page) refund the
  charge once; the queue books that refund on the request and run and never refunds it again.
* A launcher that raised after the task reached a worker leaves the scan dispatched and charged.
* Secrets (issue #88 pattern): the REAL ``celery_launcher`` -> ``start_scan_and_update_db`` -> ``format_input_for_scan``
  is run with a token generated at run time; the token reaches the worker's kwargs and nothing else (stdout, Scan rows,
  queue rows).

    cd backend && PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r python -m pytest \
      tests/test_scm_credits_and_secrets.py -q -p no:cacheprovider
"""
from __future__ import annotations

import datetime as dt
import secrets
import sys
import types
from collections import Counter
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.new_models import Scan, Team
from backend.tests.test_scm_queue import (
    NOW,
    FakeLauncher,
    balance,
    make_world,
    requests,
)
from backend.utilities.scan import credit_estimate
from backend.utilities.scm import pricing
from backend.utilities.scm import queue as Q
from backend.utilities.scm.common import redact_urls
from backend.utilities.scm.models import ScmScanRequest, ScmScanRun
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine, select


@pytest.fixture()
def engine(tmp_path):
    from backend.utilities.db.encryption import _get_fernet

    _get_fernet.cache_clear()
    eng = create_engine(f"sqlite:///{tmp_path / 'credits.db'}", connect_args={"check_same_thread": False})

    @event.listens_for(eng, "connect")
    def _fk(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    SQLModel.metadata.create_all(eng)
    return eng


class _Result:
    def __init__(self, state, result=None):
        self.state, self.result, self.info, self.traceback = state, result, None, None


class FakeCelery:
    """send_task (records the kwargs a worker would get), AsyncResult, control.revoke and the cancel marks."""

    def __init__(self):
        self.sent: list[dict] = []
        self.states: dict[str, _Result] = {}
        self.revoked: list[str] = []
        self.marked: list[str] = []  # the cancel marks a worker checks before and while it runs a task
        marks = types.SimpleNamespace(update_one=lambda flt, *_a, **_k: self.marked.append(flt["_id"]))
        self.control = types.SimpleNamespace(revoke=lambda task_id, **_kw: self.revoked.append(task_id))
        self.backend = types.SimpleNamespace(database={"scan_cancellations": marks})

    def send_task(self, name, kwargs, queue, task_id=None):
        task_id = task_id or f"task-{len(self.sent) + 1}"
        self.sent.append({"name": name, "kwargs": kwargs, "queue": queue, "id": task_id})
        return types.SimpleNamespace(id=task_id)

    def AsyncResult(self, task_id):
        return self.states.get(task_id, _Result("PENDING"))


@pytest.fixture()
def celery(monkeypatch, engine):
    """The real launcher, poller, refund and cancel code, with Celery faked and the credits module on the test DB."""
    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.scan import cancel_scan as cancel_mod
    from backend.utilities.scan import start_scan as start_mod
    from backend.utilities.team import credits as credits_mod

    app = FakeCelery()
    monkeypatch.setattr(start_mod, "get_celery_app", lambda: app)
    monkeypatch.setattr(cc, "get_celery_app", lambda: app)
    monkeypatch.setattr(credits_mod, "get_db", lambda: engine)
    findings = types.SimpleNamespace(delete_many=lambda *_a, **_k: None, insert_many=lambda *_a, **_k: None)
    monkeypatch.setattr(cc, "get_mongo_client_db", lambda: {"scan_findings": findings})
    monkeypatch.setattr(cc, "create_findings_in_mongo_db", lambda **_k: None)
    assert cancel_mod  # tell_workers imports get_celery_app from celery_connection at call time
    return app


def _token() -> str:
    return "ghs_" + secrets.token_hex(18)  # a GitHub App installation token's shape, generated per run


def _run(engine, ids, products, client_id="r1", n=1):
    with Session(engine) as s:
        est = Q.estimate(s, 1, repo_ids=ids["repos"][1][:n], products=products)
    return Q.create_run(engine, 1, ids["users"][1], trigger="manual", repo_ids=ids["repos"][1][:n], products=products,
                        expected_credits=est["credits"], client_request_id=client_id, now=NOW)


def _dispatch(engine, token, **kw):
    return Q.dispatch_tick(engine, NOW, launcher=kw.pop("launcher", Q.celery_launcher),
                           token_for=lambda _c: token, max_inflight=10, team_max=10)


def _poll(engine, now=NOW):
    return Q.poll_tick(engine, now, status_reader=Q.celery_status)


def _run_row(engine, run_id):
    with Session(engine) as s:
        return s.get(ScmScanRun, run_id)


# ----------------------------------------------------------------------------- pricing = /start's minimum
def test_repository_scan_minimum_is_the_start_minimum(monkeypatch):
    tiny = 1  # 1 KB: far below the minimum
    assert pricing.minimum("cbom") == credit_estimate.CBOM_CODE_SCAN_MIN_CREDITS
    assert pricing.credits("cbom", tiny) == credit_estimate.priced("cbom", {"repo_context": {}}, 0.0) == 1.0
    assert pricing.minimum("sbom_sca") == 0.01 and pricing.credits("sbom_sca", tiny) >= 0.01
    # one source of truth: change /start's minimum and the repository price follows
    monkeypatch.setattr(credit_estimate, "CBOM_CODE_SCAN_MIN_CREDITS", 2.5)
    assert pricing.credits("cbom", tiny) == 2.5 and pricing.minimum("cbom") == 2.5
    for product in pricing.PRODUCTS:  # never free
        assert pricing.price_c(product, 0) >= 1


# ----------------------------------------------------------------------------- the Scan row = a /start scan
def test_a_dispatched_repository_scan_is_charged_like_a_start_scan(engine, celery):
    ids = make_world(engine, repos_per_team={1: 1})
    start = balance(engine, 1)
    run = _run(engine, ids, ["cbom", "iac"])
    assert balance(engine, 1) == round(start - run["credits"], 2) and run["credits"] > 0
    token = _token()
    assert len(_dispatch(engine, token)) == 2
    with Session(engine) as s:
        scans = s.exec(select(Scan).where(Scan.team_id == 1).order_by(Scan.id)).all()
        reqs = {r.scan_id: r for r in s.exec(select(ScmScanRequest)).all()}
        assert sum(float(sc.credit_charged) for sc in scans) == run["credits"]
        for scan in scans:
            req = reqs[scan.id]
            assert scan.credit_charged == scan.credit_consumed == pricing.as_credits(req.credits_c) > 0
            assert scan.credit_charged >= pricing.minimum(scan.scan_type)
            assert scan.task_id and scan.scan_status == "pending"
            # the estimate /start would store for this input: same digest, same formula (no re-estimate needed)
            sent = next(c for c in celery.sent if c["id"] == scan.task_id)
            section = sent["kwargs"]["repo_dict_context"]
            assert section["PAT"] == token  # the worker gets the token it clones with
            assert scan.credit_estimate["formula"] == credit_estimate.formula_version(scan.scan_type)
            assert scan.credit_estimate["pricing"] == pricing.FORMULA
            assert scan.credit_estimate["minimum"] == pricing.minimum(scan.scan_type)
            assert len(scan.credit_estimate["digest"]) == 64
            assert token not in str(scan.credit_estimate)


# ----------------------------------------------------------------------------- refunds: the scan path, once
def test_worker_failure_is_refunded_once_by_the_scan_path_and_booked_on_the_run(engine, celery):
    ids = make_world(engine, repos_per_team={1: 1})
    start = balance(engine, 1)
    run = _run(engine, ids, ["iac"])
    _dispatch(engine, _token())
    (req,) = requests(engine)
    with Session(engine) as s:
        task = s.get(Scan, req.scan_id).task_id
    celery.states[task] = _Result("FAILURE", RuntimeError("Clone failed: https://x-access-token:ghs_leak@github.com/o/r"))
    _poll(engine)
    _poll(engine, NOW + dt.timedelta(minutes=1))  # a second poll changes nothing
    assert balance(engine, 1) == start  # charged once, refunded once
    (req,) = requests(engine)
    assert req.status == "failed" and req.refunded and "ghs_leak" not in (req.error or "")
    row = _run_row(engine, run["run_id"])
    assert row.refunded_c == row.credits_c and row.status == "done"
    assert Q.cancel_run(engine, 1, run["run_id"]) == 0  # nothing left to refund
    assert balance(engine, 1) == start


def test_a_cancel_on_the_scan_page_refunds_once_and_the_run_shows_it(engine, celery):
    from backend.utilities.scan.cancel_scan import cancel_scan

    ids = make_world(engine, repos_per_team={1: 1})
    start = balance(engine, 1)
    run = _run(engine, ids, ["cbom"])
    _dispatch(engine, _token())
    (req,) = requests(engine)
    out = cancel_scan(engine, scan_id=req.scan_id, team_id=1, scan_type="cbom", user_id=ids["users"][1])
    assert out["refunded_credits"] == run["credits"] and balance(engine, 1) == start
    _poll(engine)
    (req,) = requests(engine)
    assert req.status == "cancelled" and req.refunded
    assert _run_row(engine, run["run_id"]).refunded_c == _run_row(engine, run["run_id"]).credits_c
    assert balance(engine, 1) == start  # the poll moved no credits


def test_a_successful_scan_stays_charged(engine, celery):
    ids = make_world(engine, repos_per_team={1: 1})
    start = balance(engine, 1)
    run = _run(engine, ids, ["sbom_sca"])
    _dispatch(engine, _token())
    (req,) = requests(engine)
    with Session(engine) as s:
        task = s.get(Scan, req.scan_id).task_id
    celery.states[task] = _Result("SUCCESS", {"results": []})
    _poll(engine)
    (req,) = requests(engine)
    assert req.status == "done" and not req.refunded
    assert balance(engine, 1) == round(start - run["credits"], 2)
    assert _run_row(engine, run["run_id"]).refunded_c == 0


def test_a_launcher_that_fails_after_the_task_was_sent_keeps_the_scan_dispatched_and_charged(engine):
    ids = make_world(engine, repos_per_team={1: 1})
    start = balance(engine, 1)
    run = _run(engine, ids, ["iac"])

    class SentThenRaised(FakeLauncher):
        def __call__(self, engine, scan_type, scan_id, team_id, payload, *, task_id=None):
            super().__call__(engine, scan_type, scan_id, team_id, payload, task_id=task_id)  # the task reached a worker
            raise RuntimeError("database went away while reading the task id back")

    launcher = SentThenRaised()
    assert _dispatch(engine, "ghp_x", launcher=launcher) == [requests(engine)[0].id]
    (req,) = requests(engine)
    assert req.status == "dispatched" and not req.refunded and req.task_id
    with Session(engine) as s:
        scan = s.get(Scan, req.scan_id)
        assert scan.scan_status == "pending" and scan.credit_charged == run["credits"]
    assert balance(engine, 1) == round(start - run["credits"], 2)  # not a free scan


def test_a_scan_that_never_reached_a_worker_is_refunded_by_the_queue_only(engine):
    ids = make_world(engine, repos_per_team={1: 1})
    start = balance(engine, 1)
    _run(engine, ids, ["iac"])
    assert _dispatch(engine, "ghp_x", launcher=FakeLauncher(fail_for={1})) == []
    (req,) = requests(engine)
    assert req.status == "failed" and req.refunded and balance(engine, 1) == start
    with Session(engine) as s:
        assert s.get(Scan, req.scan_id).credit_charged is None  # nothing for the scan path to refund again


# ----------------------------------------------------------------------------- the token is never logged or stored
@pytest.mark.parametrize("product", ["sast", "iac", "sbom_sca", "cbom", "ai_bom"])
def test_dispatching_a_repository_scan_never_logs_the_token(engine, celery, capsys, product):
    ids = make_world(engine, repos_per_team={1: 1})
    _run(engine, ids, [product])
    token = _token()
    capsys.readouterr()
    assert len(_dispatch(engine, token)) == 1
    out = capsys.readouterr()
    assert celery.sent and celery.sent[0]["kwargs"]["repo_dict_context"]["PAT"] == token  # the worker has it
    assert "kwargs:" in out.out  # the assembled-kwargs line is still written, with the token replaced
    assert token not in out.out and token not in out.err
    with Session(engine) as s:
        for row in [*s.exec(select(Scan)).all(), *s.exec(select(ScmScanRequest)).all(),
                    *s.exec(select(ScmScanRun)).all()]:
            assert token not in str(row.model_dump())
    assert Team  # imported for the world


def test_a_worker_error_copied_onto_a_request_never_carries_a_clone_token():
    token = _token()
    assert redact_urls(f"Clone failed: https://x-access-token:{token}@github.com/o/r (exit 128)") == \
        "Clone failed: https://***@github.com/o/r (exit 128)"
    assert token not in redact_urls(f"see http://u:{token}@h/x and https://{token}@h/y")
    assert redact_urls("no URL here") == "no URL here"


# ----------------------------------------------------------------------------- lost tasks, caps, crash windows
def _tick_at(engine, now, token="ghp_x", **kw):
    """One queue tick with the real Celery-facing code (launcher, poller, cancel path), on the fake Celery app."""
    Q.poll_tick(engine, now)
    return Q.dispatch_tick(engine, now, token_for=lambda _c: token, task_state=Q.celery_task_state,
                           withdraw=Q.celery_withdraw, **kw)


def _team_world(engine, repos_per_team, balances=None):
    return make_world(engine, repos_per_team=repos_per_team, balances=balances or {t: 1000.0 for t in repos_per_team})


def _queue(engine, ids, team, products=("iac",), n=None, client_id=None):
    repo_ids = ids["repos"][team][:n] if n else ids["repos"][team]
    with Session(engine) as s:
        est = Q.estimate(s, team, repo_ids=repo_ids, products=list(products))
    return Q.create_run(engine, team, ids["users"][team], trigger="manual", repo_ids=repo_ids, products=list(products),
                        expected_credits=est["credits"], client_request_id=client_id or f"run-{team}", now=NOW)


def test_the_default_team_cap_is_half_the_global_cap_and_configurable(engine, celery, monkeypatch):
    monkeypatch.delenv("REPO_SCAN_TEAM_MAX_INFLIGHT", raising=False)
    assert Q.env_team_max_inflight(8) == 4 and Q.env_team_max_inflight(1) == 1
    monkeypatch.setenv("REPO_SCAN_TEAM_MAX_INFLIGHT", "0")
    assert Q.env_team_max_inflight(8) == 0  # explicit: no per-team limit
    monkeypatch.setenv("REPO_SCAN_TEAM_MAX_INFLIGHT", "3")
    assert Q.env_team_max_inflight(8) == 3
    monkeypatch.delenv("REPO_SCAN_TEAM_MAX_INFLIGHT")
    ids = _team_world(engine, {1: 12, 2: 3})
    _queue(engine, ids, 1)
    assert len(_tick_at(engine, NOW, max_inflight=8)) == 4  # alone, one team still takes only half the slots
    _queue(engine, ids, 2)
    assert len(_tick_at(engine, NOW, max_inflight=8)) == 3  # the other team gets slots straight away
    by_team = Counter(r.team_id for r in requests(engine, status="dispatched"))
    assert by_team == {1: 4, 2: 3}


def test_a_lost_task_frees_its_slot_and_is_refunded_once_through_the_cancel_path(engine, celery, monkeypatch):
    monkeypatch.setenv("REPO_SCAN_START_TIMEOUT_MIN", "60")
    ids = _team_world(engine, {1: 2, 2: 1})
    start1, start2 = balance(engine, 1), balance(engine, 2)
    run = _queue(engine, ids, 1, n=1)
    # a worker took the message and died (OOM, restart): the task stays PENDING for ever
    assert len(_tick_at(engine, NOW, max_inflight=1, team_max=1)) == 1
    _queue(engine, ids, 2)
    assert _tick_at(engine, NOW + dt.timedelta(minutes=59), max_inflight=1, team_max=1) == []  # slot still held
    (lost,) = requests(engine, team_id=1)
    with Session(engine) as s:
        task = s.get(Scan, lost.scan_id).task_id
    sent = _tick_at(engine, NOW + dt.timedelta(minutes=61), max_inflight=1, team_max=1)
    lost = requests(engine, id=lost.id)[0]
    assert lost.status == "failed" and lost.refunded and "No scan worker picked this scan up within 60" in lost.error
    with Session(engine) as s:
        scan = s.get(Scan, lost.scan_id)
        assert scan.scan_status == "cancelled" and scan.info["timed_out"] and scan.info["refunded_credits"] > 0
    assert task in celery.revoked and task in celery.marked  # a worker that finds it later never runs it
    assert balance(engine, 1) == start1  # charged once, refunded once
    row = _run_row(engine, run["run_id"])
    assert row.refunded_c == row.credits_c and row.status == "done"
    assert len(sent) == 1 and requests(engine, team_id=2)[0].status == "dispatched"  # the freed slot is used
    assert balance(engine, 2) < start2
    _tick_at(engine, NOW + dt.timedelta(minutes=90), max_inflight=1, team_max=1)
    assert balance(engine, 1) == start1  # nothing refunded twice


def test_a_scan_that_finished_meanwhile_is_kept_not_refunded(engine, celery, monkeypatch):
    monkeypatch.setenv("REPO_SCAN_RUN_TIMEOUT_MIN", "180")
    ids = _team_world(engine, {1: 1})
    start = balance(engine, 1)
    run = _queue(engine, ids, 1)
    _tick_at(engine, NOW)
    (req,) = requests(engine)
    with Session(engine) as s:
        task = s.get(Scan, req.scan_id).task_id
    celery.states[task] = _Result("STARTED")
    _tick_at(engine, NOW + dt.timedelta(minutes=170))
    assert requests(engine)[0].status == "dispatched"  # running, within the run timeout
    celery.states[task] = _Result("SUCCESS", {"results": []})  # it finished just as the timeout passed
    _tick_at(engine, NOW + dt.timedelta(minutes=181))
    (req,) = requests(engine)
    assert req.status == "done" and not req.refunded and task not in celery.revoked
    assert balance(engine, 1) == round(start - run["credits"], 2)


def test_a_scan_running_past_the_run_timeout_is_stopped_and_refunded(engine, celery, monkeypatch):
    monkeypatch.setenv("REPO_SCAN_RUN_TIMEOUT_MIN", "180")
    ids = _team_world(engine, {1: 1})
    start = balance(engine, 1)
    _queue(engine, ids, 1)
    _tick_at(engine, NOW)
    (req,) = requests(engine)
    with Session(engine) as s:
        task = s.get(Scan, req.scan_id).task_id
    celery.states[task] = _Result("STARTED")  # its worker is gone, the result backend still says STARTED
    _tick_at(engine, NOW + dt.timedelta(minutes=181))
    (req,) = requests(engine)
    assert req.status == "failed" and req.refunded and "did not finish within 180 minutes" in req.error
    assert task in celery.marked and balance(engine, 1) == start


class _DiesAfterSend:
    """The real launcher's send (the queue's chosen task id reaches the broker), then the dispatcher process dies
    before the id is stored on the scan: BaseException, as a SIGKILL would leave it."""

    def __init__(self, app):
        self.app = app

    def __call__(self, engine, scan_type, scan_id, team_id, payload, *, task_id=None):
        self.app.send_task(name=f"scan_worker.{scan_type}", kwargs={}, queue="scan_worker_queue", task_id=task_id)
        raise SystemExit("dispatcher killed")


def _crash_after_send(engine, celery):
    with pytest.raises(SystemExit):
        Q.dispatch_tick(engine, NOW, launcher=_DiesAfterSend(celery), token_for=lambda _c: "ghp_x",
                        max_inflight=4, team_max=4)
    (req,) = requests(engine)
    assert req.status == "dispatching" and req.task_id and len(celery.sent) == 1
    assert req.task_id == celery.sent[0]["id"]  # the id was stored before the send
    return req


def test_crash_right_after_send_a_task_a_worker_has_is_adopted_not_sent_again(engine, celery):
    ids = _team_world(engine, {1: 1})
    start = balance(engine, 1)
    run = _queue(engine, ids, 1)
    req = _crash_after_send(engine, celery)
    celery.states[req.task_id] = _Result("STARTED")  # a worker is running it
    later = NOW + Q.DISPATCH_LEASE + dt.timedelta(seconds=1)
    _tick_at(engine, later)
    (adopted,) = requests(engine)
    assert adopted.status == "dispatched" and adopted.task_id == req.task_id
    assert len(celery.sent) == 1 and req.task_id not in celery.revoked  # not run twice
    celery.states[req.task_id] = _Result("SUCCESS", {"results": []})
    _tick_at(engine, later + dt.timedelta(minutes=1))
    assert requests(engine)[0].status == "done"
    assert balance(engine, 1) == round(start - run["credits"], 2)  # charged once: not free


def test_crash_right_after_send_a_task_no_worker_has_is_withdrawn_and_sent_once_more(engine, celery):
    ids = _team_world(engine, {1: 1})
    start = balance(engine, 1)
    run = _queue(engine, ids, 1)
    req = _crash_after_send(engine, celery)
    first = req.task_id  # PENDING: still in the broker, or never there
    later = NOW + Q.DISPATCH_LEASE + dt.timedelta(seconds=1)
    _tick_at(engine, later)  # recovery withdraws it and re-queues ...
    _tick_at(engine, later + dt.timedelta(seconds=5))  # ... and the next tick sends it under a new id
    (again,) = requests(engine)
    assert again.status == "dispatched" and again.task_id != first and again.attempts == 2
    assert first in celery.revoked and first in celery.marked  # the first copy can never run: one run in all
    assert [c["id"] for c in celery.sent] == [first, again.task_id]
    assert balance(engine, 1) == round(start - run["credits"], 2)  # still charged exactly once


def test_a_launcher_error_after_send_withdraws_the_task_before_refunding(engine, celery):
    ids = _team_world(engine, {1: 1})
    start = balance(engine, 1)
    _queue(engine, ids, 1)

    class SentThenFailed(_DiesAfterSend):
        def __call__(self, engine, scan_type, scan_id, team_id, payload, *, task_id=None):
            self.app.send_task(name="scan_worker.iac", kwargs={}, queue="scan_worker_queue", task_id=task_id)
            raise RuntimeError("could not store the task id")  # e.g. get_scan_metadata_for_type raised

    assert _tick_at(engine, NOW, launcher=SentThenFailed(celery)) == []
    (req,) = requests(engine)
    assert req.status == "failed" and req.refunded and balance(engine, 1) == start
    assert celery.sent[0]["id"] in celery.marked  # refunded AND withdrawn: it can never run for free
