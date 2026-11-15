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
        marks = types.SimpleNamespace(update_one=lambda *_a, **_k: None)
        self.control = types.SimpleNamespace(revoke=lambda task_id, **_kw: self.revoked.append(task_id))
        self.backend = types.SimpleNamespace(database={"scan_cancellations": marks})

    def send_task(self, name, kwargs, queue):
        task_id = f"task-{len(self.sent) + 1}"
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
        def __call__(self, engine, scan_type, scan_id, team_id, payload):
            super().__call__(engine, scan_type, scan_id, team_id, payload)  # the task reached a worker
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
