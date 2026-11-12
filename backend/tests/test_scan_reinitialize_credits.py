"""Reinitialize charges what the new input costs (#33).

POST /{team}/{type}/scan/{id}/reinitialize sends a new worker run, with a new input, for a scan that was already
estimated, charged and queued. Before #33 it never priced the new input: pay for a tiny archive, reinitialize with a
huge one for free. The rules proved here (backend/utilities/scan/reinitialize.py):

* the new input is priced with the estimator a new scan uses; only the positive difference against what the scan
  already paid is charged, in the same transaction as the claim, and recorded in the credits ledger;
* the same input costs nothing (no new estimate) and a smaller one is never refunded;
* a balance too small for the difference is refused with 402 before anything is queued;
* the target checks of a new scan run before any credit moves (DAST address rule, git host allow-list, archive);
* only a dispatched scan the worker has not picked up yet can be reinitialized (409 ``not_pending`` otherwise,
  whenever it is seen), the replaced run is withdrawn, and a poll of the replaced run never changes the scan;
* two reinitializes at once charge once; a second one while the first is sending its run waits (409 ``starting``);
* a cancel or a failure afterwards refunds everything that was paid, once, each with its ledger line (the failure's
  in the transaction that marks the scan failed);
* the claim names both runs and keeps what it replaced: a claim left behind by a dead request is given back by the
  sweeper (or a later reinitialize), and a cancel withdraws both runs (the out-of-process kill:
  test_reinitialize_crash_window.py).

Hermetic: SQLite + TestClient, fake Celery, fake S3 upload, fake DNS. The same races against a real PostgreSQL with
threads: test_reinitialize_race_postgres.py.
"""
import asyncio
import datetime as dt
import io
import itertools
import json
import os
import secrets
import sys
import threading
import types
import zipfile
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import HTTPException, UploadFile
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", secrets.token_urlsafe(48))  # generated: no key-shaped literal in the tree

from backend.new_models import Scan, Team, TeamMembership, User  # noqa: E402
from backend.utilities.db.schemas import StartScanPayload  # noqa: E402
from backend.utilities.scan import credit_estimate  # noqa: E402


def _zip(content_size: int, fill: bytes = b"a") -> bytes:
    """A real zip archive (the dispatcher refuses anything else) whose one file has ``content_size`` bytes. Fixed
    timestamp, so the same size and fill give the same bytes (and the same input digest)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(zipfile.ZipInfo("src/a.txt", date_time=(2020, 1, 1, 0, 0, 0)), fill * content_size)
    return buf.getvalue()


ZIP_PAYLOAD = json.dumps({"cbom": {"zip_file_used": True}})
SMALL, BIG, BIGGER = _zip(50), _zip(750), _zip(1000)  # fake estimator: 1 credit per 100 bytes, CBOM minimum 1 credit
FAKE_PAT = "-".join(("pat", "t2", secrets.token_hex(4)))  # generated at run time: no token-shaped literal
DAST_PASSWORD = secrets.token_hex(6)  # generated at run time


def _dast(target="https://app.example/", max_urls=100, login="https://app.example/login", extra=None):
    return json.dumps({"dast": {
        "target_url": target, "max_urls": max_urls, "additional_urls_to_scan": extra,
        "auth": {"login_url": login, "xpath_of_username_field": "//u", "xpath_of_password_field": "//p",
                 "username": "qa", "password": DAST_PASSWORD, "xpath_of_submit_button": "//b"},
    }})


def _sast(repo_url="https://github.com/acme/app", branch="main"):
    return json.dumps({"sast": {"app_lang": "python", "repo_context": {
        "mode": "github", "repo_url": repo_url, "PAT": FAKE_PAT, "branch": branch}}})


def _estimate_of(kind: str, payload: str, data: bytes | None, credits: float) -> dict:
    """What /estimate_credits stores for this input (the input digest, formula, minimum and price)."""
    section = getattr(StartScanPayload.model_validate_json(payload), kind).model_dump(mode="json")  # as the routes do
    return {**credit_estimate.input_digest(kind, section, data), "minimum": credit_estimate.minimum_credits(kind, section),
            "credits": credits}


# id: (team, owner, type, status, task_id, credit_consumed, credit_charged, credit_estimate)
SCANS = {
    1: (1, 1, "cbom", "pending", "t-1", 1.0, 1.0, ("cbom", ZIP_PAYLOAD, SMALL, 1.0)),  # paid 1 credit, queued
    2: (1, 1, "dast", "pending", "t-2", 8.0, 8.0, ("dast", _dast(), None, 8.0)),
    3: (1, 1, "sast", "pending", "t-3", 2.0, 2.0, ("sast", _sast(), None, 2.0)),
    4: (1, 1, "cbom", "pending", None, 1.0, 1.0, ("cbom", ZIP_PAYLOAD, SMALL, 1.0)),  # /start claimed it, not sent yet
    5: (1, 1, "cbom", "failure", "t-5", 1.0, 1.0, ("cbom", ZIP_PAYLOAD, SMALL, 1.0)),
    6: (1, 1, "cbom", "pending", "t-6", 2.0, None, None),  # dispatched before the digest and credit_charged existed
    7: (2, 2, "cbom", "pending", "t-7", 1.0, 1.0, ("cbom", ZIP_PAYLOAD, SMALL, 1.0)),  # team 2's scan
    8: (1, 1, "cbom", "NOT_STARTED", None, 1.0, None, ("cbom", ZIP_PAYLOAD, SMALL, 1.0)),  # estimated, never started
}


class _Result:
    def __init__(self, state, result=None):
        self.state, self.result, self.info, self.traceback = state, result, None, None


class _Marks:
    def __init__(self):
        self.docs = {}

    def update_one(self, flt, update, upsert=False):
        self.docs.setdefault(flt["_id"], {}).update(update["$set"])


class FakeCelery:
    """send_task / AsyncResult / control.revoke / backend.database: what dispatch, the poller and cancel use."""

    def __init__(self):
        self.sent: list[tuple[str, dict, str, str]] = []
        self.states: dict[str, _Result] = {}
        self.revoked: list[str] = []
        self.asked: list[str] = []  # the task ids the backend asked Celery about
        self.marks = _Marks()
        self.control = types.SimpleNamespace(revoke=lambda task_id, **_kw: self.revoked.append(task_id))
        self.backend = types.SimpleNamespace(database={"scan_cancellations": self.marks})
        self.fail_send = False
        self.on_send = None  # a hook run inside send_task, before the task id is returned

    def send_task(self, name, kwargs, queue, task_id=None):
        if self.fail_send:
            raise RuntimeError("broker down")
        task_id = task_id or f"new-{len(self.sent) + 1}"  # a reinitialize names its run's id (before its claim)
        self.sent.append((name, kwargs, queue, task_id))
        if self.on_send is not None:
            hook, self.on_send = self.on_send, None
            hook(task_id)
        return types.SimpleNamespace(id=task_id)

    def AsyncResult(self, task_id):  # noqa: N802 (Celery's name)
        self.asked.append(task_id)
        return self.states.get(task_id, _Result("PENDING"))


DNS = {"app.example": ["93.184.216.34"], "backend": ["172.20.0.5"], "meta.example": ["169.254.169.254"],
       "rebind.example": ["93.184.216.34", "10.0.0.7"]}


@pytest.fixture()
def http(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    now = dt.datetime.now(dt.timezone.utc)
    with Session(engine) as s:
        s.add(Team(id=1, name="one", credit_balance=100.0))
        s.add(Team(id=2, name="two", credit_balance=100.0))
        for uid, team in ((1, 1), (2, 2), (3, 1)):
            s.add(User(id=uid, email=f"u{uid}@example.test", password="x", first_name="u", last_name=str(uid),
                       default_team_id=team))
        s.add(TeamMembership(team_id=1, user_id=1, role="admin"))
        s.add(TeamMembership(team_id=1, user_id=3, role="member"))  # a member who did not start the scans
        s.add(TeamMembership(team_id=2, user_id=2, role="admin"))
        for sid, (team, owner, kind, status, task, consumed, charged, est) in SCANS.items():
            s.add(Scan(id=sid, team_id=team, owner_user_id=owner, scan_type=kind, scan_status=status, task_id=task,
                       credit_consumed=consumed, credit_charged=charged, created_at=now,
                       credit_estimate=_estimate_of(*est) if est else None))
        s.commit()

    celery = FakeCelery()
    calls = {"estimate": [], "uploads": [], "deleted": [], "findings": []}

    from backend.routers import scans as scans_router
    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.dast import ssrf
    from backend.utilities.db import s3_utils
    from backend.utilities.scan import estimate_scan, format_input
    from backend.utilities.scan import start_scan as start_mod
    from backend.utilities.team import credits as credits_mod
    from backend.utilities.team import validation

    async def fake_estimate(scan_type, engine, start_scan_payload, uploaded_file=None):
        """The real estimator formats the input first (the target checks and the upload), then a worker prices it."""
        await format_input.format_input_for_scan(scan_type=scan_type, start_scan_payload=start_scan_payload,
                                                 uploaded_file=uploaded_file)
        calls["estimate"].append(scan_type)
        if scan_type == "dast":
            return start_scan_payload.dast.max_urls * 0.08
        if scan_type == "sast":
            return 2.0 if start_scan_payload.sast.repo_context.branch == "main" else 5.0
        await uploaded_file.seek(0)
        with zipfile.ZipFile(io.BytesIO(await uploaded_file.read())) as zf:
            return zf.infolist()[0].file_size / 100

    def fake_upload(fileobj, extension=".zip"):
        calls["uploads"].append(len(fileobj.getvalue()))
        return {"bucket": "test-bucket", "object_name": f"obj-{len(calls['uploads'])}{extension}"}

    async def fake_user(_engine, authorization):
        return types.SimpleNamespace(id=int((authorization or "Bearer 1").split()[-1]))

    def resolve(host):
        if host not in DNS:
            raise ssrf.DastSsrfError(f"Could not resolve host {host}")
        return list(DNS[host])

    monkeypatch.delenv("DAST_ALLOWED_PRIVATE", raising=False)
    monkeypatch.delenv("GIT_ALLOWED_HOSTS", raising=False)
    monkeypatch.setattr(ssrf, "_resolve_ips", resolve)
    monkeypatch.setattr(scans_router, "get_db", lambda: engine)
    monkeypatch.setattr(scans_router, "get_user_from_header_or_raise_exception", fake_user)
    monkeypatch.setattr(scans_router, "check_if_user_is_in_team", validation.check_if_user_is_in_team)
    monkeypatch.setattr(scans_router, "get_mongo_client_db", lambda: {})
    monkeypatch.setattr(scans_router, "estimate_credits", fake_estimate)  # /estimate_credits and /start
    monkeypatch.setattr(estimate_scan, "estimate_credits", fake_estimate)  # reinitialize
    monkeypatch.setattr(credits_mod, "get_db", lambda: engine)
    monkeypatch.setattr(cc, "get_celery_app", lambda: celery)
    monkeypatch.setattr(start_mod, "get_celery_app", lambda: celery)
    ids = itertools.count(1)
    try:  # readable run ids: new-1, new-2... (the module exists from the #57 review fixes on)
        from backend.utilities.scan import claim_token
        monkeypatch.setattr(claim_token, "new_task_id", lambda: f"new-{next(ids)}")
    except ImportError:
        pass
    monkeypatch.setattr(format_input, "upload_file", fake_upload)
    monkeypatch.setattr(s3_utils, "delete_file", lambda bucket, key: calls["deleted"].append(key) or True)
    monkeypatch.setattr(cc, "get_mongo_client_db", lambda: {"scan_findings": types.SimpleNamespace(
        delete_many=lambda *_a, **_k: None)})
    monkeypatch.setattr(cc, "create_findings_in_mongo_db", lambda **k: calls["findings"].append(k["scan_id"]))
    from backend.main import app

    return TestClient(app), engine, celery, calls


def _reinit(client, scan_id, kind, payload, data=None, user=1, team=1):
    files = {"uploaded_file": ("code.zip", data, "application/zip")} if data is not None else None
    return client.post(f"/{team}/{kind}/scan/{scan_id}/reinitialize", data={"start_scan_payload_string": payload},
                       files=files, headers={"Authorization": f"Bearer {user}"})


async def _reinit_direct(scan_id, kind, payload, data=None, user=1, team=1):
    """The route called as a coroutine, for a second request interleaved inside the first one."""
    from backend.routers import scans as scans_router

    upload = UploadFile(file=io.BytesIO(data), filename="code.zip") if data is not None else None
    try:
        out = await scans_router.reinitialize_scan(type=kind, scan_id=scan_id, team_id=team,
                                                    start_scan_payload_string=payload, uploaded_file=upload,
                                                    Authorization=f"Bearer {user}")
    except HTTPException as exc:
        return exc.status_code, {"detail": exc.detail}
    if hasattr(out, "status_code"):
        return out.status_code, json.loads(out.body)
    return 200, out


def _in_thread(coro_factory):
    """Run a request on its own thread (and event loop) while the first one is blocked in a synchronous call."""
    box = {}
    thread = threading.Thread(target=lambda: box.update(result=asyncio.run(coro_factory())))
    thread.start()
    thread.join(30)
    return box["result"]


def _scan(engine, scan_id):
    with Session(engine) as s:
        scan = s.get(Scan, scan_id)
        s.expunge(scan)
        return scan


def _balance(engine, team=1):
    with Session(engine) as s:
        return s.get(Team, team).credit_balance


def _set_balance(engine, value, team=1):
    with Session(engine) as s:
        row = s.get(Team, team)
        row.credit_balance = value
        s.add(row)
        s.commit()


LEDGER = sa.text("SELECT * FROM creditledger ORDER BY id")


def _ledger(engine):
    """The ledger's lines, amounts in credits (read from the milli-credit columns)."""
    with engine.connect() as conn:
        rows = [dict(r._mapping) for r in conn.execute(LEDGER)]
    out = []
    for r in rows:
        detail = r.get("detail")
        detail = json.loads(detail) if isinstance(detail, str) else detail
        mc = "delta_mc" in r
        out.append({"team_id": r["team_id"], "scan_id": r["scan_id"], "user_id": r["user_id"],
                    "delta": r["delta_mc"] / 1000 if mc else r["delta"],
                    "balance_after": (r["balance_after_mc"] / 1000 if r["balance_after_mc"] is not None else None)
                    if mc else r["balance_after"],
                    "reason": r["reason"], "detail": detail, "movement_key": r.get("movement_key"),
                    "ref": (r.get("ref_type"), r.get("ref_id"))})
    return out


def _lines(engine):
    return [(e["reason"], e["delta"]) for e in _ledger(engine)]


def _unchanged(engine, celery, scan_id=1, task="t-1", charged=1.0, balance=100.0):
    scan = _scan(engine, scan_id)
    assert (scan.scan_status, scan.task_id, scan.credit_charged) == ("pending", task, charged)
    assert _balance(engine) == balance
    assert celery.sent == [] and celery.revoked == []


# ===================================================================================== the price of the new input
def _sent_upload_sizes(celery, calls) -> list[int]:
    """The size of the archive each run sent to the worker carries (fake_upload names its objects obj-<n>.zip)."""
    sizes = []
    for _name, kwargs, _queue, _task in celery.sent:
        obj = (kwargs.get("zip_dict_context") or {}).get("object_name", "")
        if obj.startswith("obj-"):
            sizes.append(calls["uploads"][int(obj[4:].split(".")[0]) - 1])
    return sizes


def test_issue_33_a_bigger_input_is_never_sent_to_the_worker_unpaid(http):
    """#33 as reported, using only what dev already had (no ledger, no new response fields), so it runs on both trees:
    pay 1 credit for a small archive, reinitialize with a 7.5-credit one. On dev 3399452 the route answered 200, sent
    the big archive to the worker, and the team was charged nothing more (balance 100, credit_charged 1)."""
    client, engine, celery, calls = http
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 200, r.text
    assert _sent_upload_sizes(celery, calls) == [len(BIG)]  # the costlier input is the run the worker gets
    paid = round(1.0 + (100.0 - _balance(engine)), 2)  # 1 credit at /start plus whatever the reinitialize took
    assert paid >= 7.5, f"a 7.5-credit run was sent while the scan has paid {paid} credit(s) in total"
    assert _scan(engine, 1).credit_charged == paid  # a cancel or failure would give back exactly what was paid


def test_a_bigger_input_charges_the_difference_once_and_records_it(http):
    client, engine, celery, calls = http
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)  # paid 1 credit; the new archive costs 7.5
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["credits_charged"], body["credits_total"], body["credits_required"]) == (6.5, 7.5, 7.5)
    assert _balance(engine) == 93.5
    scan = _scan(engine, 1)
    assert (scan.scan_status, scan.task_id, scan.credit_charged, scan.credit_consumed) == ("pending", "new-1", 7.5, 7.5)
    assert scan.credit_estimate["digest"] == _estimate_of("cbom", ZIP_PAYLOAD, BIG, 7.5)["digest"]
    assert calls["estimate"] == ["cbom"]
    assert [(name, queue) for name, _k, queue, _t in celery.sent] == [("scan_worker.cbom", "scan_worker_queue")]
    assert celery.revoked == ["t-1"] and "t-1" in celery.marks.docs  # the replaced run is withdrawn
    (entry,) = _ledger(engine)
    assert (entry["team_id"], entry["scan_id"], entry["user_id"], entry["delta"], entry["balance_after"],
            entry["reason"]) == (1, 1, 1, -6.5, 93.5, "scan_reinitialize_charge")
    assert (entry["detail"]["previous_charged"], entry["detail"]["price"], entry["detail"]["total"]) == (1.0, 7.5, 7.5)
    assert entry["movement_key"] == "scan:1:reinit:new-1" and entry["ref"] == ("scan", "1")
    assert "reinitialize_claim" in scan.credit_estimate  # what a give-back would restore (kept, harmless)


def test_successive_reinitializes_cost_the_highest_price_in_total(http):
    client, engine, celery, _calls = http
    for data, charged, total in ((BIG, 6.5, 7.5), (BIGGER, 2.5, 10.0), (BIGGER, 0.0, 10.0), (SMALL, 0.0, 10.0)):
        r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, data)
        assert r.status_code == 200, r.text
        assert (r.json()["credits_charged"], r.json()["credits_total"]) == (charged, total)
    assert _balance(engine) == 91.0 and _scan(engine, 1).credit_charged == 10.0  # 1 paid at start + 9
    assert [e["delta"] for e in _ledger(engine)] == [-6.5, -2.5]
    assert celery.revoked == ["t-1", "new-1", "new-2", "new-3"] and _scan(engine, 1).task_id == "new-4"


def test_the_same_input_charges_nothing_and_replaces_the_queued_run(http):
    client, engine, celery, calls = http
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, SMALL)  # what was estimated and paid
    assert r.status_code == 200, r.text
    assert (r.json()["credits_charged"], r.json()["credits_total"]) == (0.0, 1.0)
    assert calls["estimate"] == []  # same input digest: no new estimate
    assert _balance(engine) == 100.0 and _ledger(engine) == []
    assert len(celery.sent) == 1 and celery.revoked == ["t-1"]  # one run replaced by one run, never two
    assert _scan(engine, 1).credit_charged == 1.0


def test_the_same_input_after_a_pricing_change_still_costs_nothing(http):
    client, engine, _celery, calls = http
    with Session(engine) as s:
        scan = s.get(Scan, 1)
        scan.credit_estimate = {**scan.credit_estimate, "formula": "cbom-2026.10-old"}
        s.add(scan)
        s.commit()
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, SMALL)
    assert r.status_code == 200 and r.json()["credits_charged"] == 0.0
    assert calls["estimate"] == [] and _balance(engine) == 100.0


def test_a_smaller_input_is_charged_nothing_and_never_refunded(http):
    client, engine, celery, calls = http
    r = _reinit(client, 2, "dast", _dast(max_urls=50))  # paid 8 credits; 50 URLs cost 4
    assert r.status_code == 200, r.text
    assert (r.json()["credits_charged"], r.json()["credits_total"], r.json()["credits_required"]) == (0.0, 8.0, 4.0)
    assert _balance(engine) == 100.0 and _scan(engine, 2).credit_charged == 8.0 and _ledger(engine) == []
    assert calls["estimate"] == ["dast"] and celery.sent[0][0] == "dast_worker.dast"


def test_a_scan_from_before_the_digest_is_priced_against_what_it_paid(http):
    client, engine, _celery, calls = http
    assert _reinit(client, 6, "cbom", ZIP_PAYLOAD, SMALL).json()["credits_charged"] == 0.0  # 1 credit <= 2 paid
    r = _reinit(client, 6, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 200 and r.json()["credits_charged"] == 5.5  # 7.5 against the 2 credits paid
    assert _balance(engine) == 94.5 and _scan(engine, 6).credit_charged == 7.5
    assert calls["estimate"] == ["cbom", "cbom"]


def test_a_new_branch_is_priced_and_the_ledger_never_holds_the_token(http):
    client, engine, _celery, _calls = http
    r = _reinit(client, 3, "sast", _sast(branch="release"))  # main cost 2, this branch costs 5
    assert r.status_code == 200 and r.json()["credits_charged"] == 3.0
    (entry,) = _ledger(engine)
    assert entry["delta"] == -3.0 and FAKE_PAT not in json.dumps(entry)
    assert FAKE_PAT not in json.dumps(_scan(engine, 3).credit_estimate)


# ===================================================================================== refusals: nothing charged, nothing queued
def test_too_small_a_balance_is_refused_with_402_and_nothing_is_queued(http):
    client, engine, celery, calls = http
    _set_balance(engine, 3.0)
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)  # needs 6.5 more
    assert r.status_code == 402, r.text
    body = r.json()
    assert body["code"] == "insufficient_credits"
    assert (body["credits_required"], body["credits_paid"], body["credits_difference"], body["credit_balance"]) == \
        (7.5, 1.0, 6.5, 3.0)
    assert "6.5 more credits" in body["detail"] and "Nothing was charged" in body["detail"]
    _unchanged(engine, celery, balance=3.0)
    assert _scan(engine, 1).credit_estimate["digest"] == _estimate_of("cbom", ZIP_PAYLOAD, SMALL, 1.0)["digest"]
    assert calls["uploads"] == [len(BIG)]  # the estimate's upload only: the run's input was never uploaded
    assert _ledger(engine) == []


def test_a_balance_of_exactly_the_difference_is_enough(http):
    """Boundary (QA mutants N9/N10): 6.5 credits pay a 6.5 difference, to a balance of exactly 0."""
    client, engine, celery, _calls = http
    _set_balance(engine, 6.5)
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 200 and r.json()["credits_charged"] == 6.5, r.text
    assert _balance(engine) == 0.0 and _scan(engine, 1).credit_charged == 7.5
    (entry,) = _ledger(engine)
    assert (entry["delta"], entry["balance_after"]) == (-6.5, 0.0)


def test_one_credit_short_is_worded_in_the_singular(http):
    client, engine, _celery, _calls = http
    _set_balance(engine, 0.5)
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, _zip(200))  # costs 2, paid 1: 1 more credit
    assert r.status_code == 402 and r.json()["credits_difference"] == 1.0, r.text
    assert "1 more credit is needed" in r.json()["detail"]


def test_a_balance_spent_elsewhere_after_the_check_is_refused_by_the_charge_itself(http, monkeypatch):
    """Another tab spends the balance between the pre-check and the claim: the conditional debit refuses and the claim
    is rolled back with it (one transaction), so the scan keeps its run and the balance never goes negative."""
    from backend.utilities.scan import format_input

    client, engine, celery, calls = http
    real = format_input.format_input_for_scan
    seen = []

    async def spend_then_format(**kwargs):
        seen.append(1)
        if len(seen) == 2:  # the reinitialize's own formatting, after its balance check
            _set_balance(engine, 1.0)
        return await real(**kwargs)

    monkeypatch.setattr(format_input, "format_input_for_scan", spend_then_format)
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 402, r.text
    assert len(seen) == 2
    _unchanged(engine, celery, balance=1.0)
    assert _ledger(engine) == []
    assert calls["deleted"] == ["obj-2.zip"]  # the run's upload is removed again


@pytest.mark.parametrize("payload, message", [
    (_dast(target="http://169.254.169.254/latest/meta-data/", login="http://169.254.169.254/login"), "metadata"),
    (_dast(target="http://meta.example/", login="http://meta.example/login"), "metadata"),
    (_dast(target="http://backend:8080/", login="http://backend:8080/login"), "private"),
    (_dast(target="http://127.0.0.1/", login="http://127.0.0.1/login"), "private"),
    (_dast(target="http://rebind.example/", login="http://rebind.example/login"), "10.0.0.7"),
    (_dast(max_urls=500, extra=["http://backend:8080/admin"]), "not in allowlist"),
])
def test_a_blocked_dast_target_is_refused_before_anything_is_charged(http, payload, message):
    client, engine, celery, _calls = http
    r = _reinit(client, 2, "dast", payload)
    assert r.status_code == 400, r.text
    assert message in r.json()["detail"]
    _unchanged(engine, celery, scan_id=2, task="t-2", charged=8.0)


@pytest.mark.parametrize("repo_url", ["https://github.com.evil.example/acme/app", "https://evil.example/acme/app",
                                      "http://github.com/acme/app", "file:///etc/passwd"])
def test_a_disallowed_git_host_is_refused(http, repo_url):
    client, engine, celery, _calls = http
    r = _reinit(client, 3, "sast", _sast(repo_url=repo_url))
    assert r.status_code == 422, r.text
    _unchanged(engine, celery, scan_id=3, task="t-3", charged=2.0)


def test_an_upload_that_is_not_a_zip_archive_is_refused(http):
    client, engine, celery, _calls = http
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, b"definitely not a zip archive" * 40)
    assert r.status_code == 400 and "not a zip archive" in r.json()["detail"]
    _unchanged(engine, celery)


def test_only_the_scans_owner_in_its_team_can_reinitialize(http):
    client, engine, celery, _calls = http
    assert _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG, user=3).status_code == 400  # a member, not the owner
    assert _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG, user=2).status_code == 403  # not in team 1
    assert _reinit(client, 7, "cbom", ZIP_PAYLOAD, BIG).status_code == 404  # team 2's scan through team 1's path
    assert _reinit(client, 1, "sast", _sast()).status_code == 404  # wrong type for the scan
    _unchanged(engine, celery)


def test_reinitialize_waits_until_the_scan_has_been_dispatched(http):
    """A /start that has claimed the scan (pending, no task yet) may still be estimating: a reinitialize then would
    send a second, unpaid run."""
    client, engine, celery, _calls = http
    r = _reinit(client, 4, "cbom", ZIP_PAYLOAD, SMALL)
    assert r.status_code == 409 and r.json()["code"] == "starting"
    assert celery.sent == [] and _scan(engine, 4).task_id is None and _balance(engine) == 100.0


@pytest.mark.parametrize("scan_id, scan_status", [(8, "NOT_STARTED"), (5, "failure")])
def test_a_scan_that_is_not_waiting_in_the_queue_gets_one_stable_code(http, scan_id, scan_status):
    """"Not queued" answers 409 not_pending whenever it is seen: here, before the worker is asked (e13e24f answered 400
    with no code here, and 409 already_started after asking the worker)."""
    client, engine, celery, _calls = http
    r = _reinit(client, scan_id, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 409 and r.json()["code"] == "not_pending", r.text
    assert r.json()["scan_status"] == scan_status and "Nothing was charged" in r.json()["detail"]
    assert celery.sent == [] and _balance(engine) == 100.0 and _ledger(engine) == []


def test_a_type_without_a_withdrawable_worker_task_is_refused(http):
    client, engine, celery, _calls = http
    r = _reinit(client, 1, "leakage", json.dumps({}))
    assert r.status_code == 400 and "cannot be reinitialized" in r.json()["detail"], r.text
    assert celery.sent == [] and _balance(engine) == 100.0


@pytest.mark.parametrize("state, stored", [("STARTED", "started"), ("RETRY", "retry")])
def test_reinitialize_is_refused_once_the_worker_has_picked_the_run_up(http, state, stored):
    client, engine, celery, _calls = http
    celery.states["t-1"] = _Result(state)
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 409 and r.json()["code"] == "not_pending", r.text
    assert "Nothing was charged" in r.json()["detail"]
    assert celery.sent == [] and celery.revoked == [] and _balance(engine) == 100.0
    assert _scan(engine, 1).scan_status == stored and _scan(engine, 1).task_id == "t-1"


# ===================================================================================== concurrency
def test_two_reinitializes_at_once_charge_the_difference_once(http, monkeypatch):
    """B runs to the end while A is being priced; A's claim then finds the scan changed and charges nothing."""
    from backend.utilities.scan import estimate_scan

    client, engine, celery, calls = http
    real = estimate_scan.estimate_credits
    inner = {}

    async def estimate_with_b_inside(**kwargs):
        if not inner:
            inner["b"] = "running"
            inner["b"] = await _reinit_direct(1, "cbom", ZIP_PAYLOAD, BIG)
        return await real(**kwargs)

    monkeypatch.setattr(estimate_scan, "estimate_credits", estimate_with_b_inside)
    a = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    b_status, b_body = inner["b"]
    assert b_status == 200 and b_body["credits_charged"] == 6.5
    assert a.status_code == 409 and a.json()["code"] == "reinitialize_conflict", a.text
    assert "Nothing was charged" in a.json()["detail"]
    assert _balance(engine) == 93.5 and [e["delta"] for e in _ledger(engine)] == [-6.5]
    assert [t for *_x, t in celery.sent] == ["new-1"] and _scan(engine, 1).task_id == "new-1"
    assert celery.revoked == ["t-1"]
    # A's run input was uploaded before its claim was lost: removed again (the estimate's own uploads are not runs)
    assert calls["deleted"] == [f"obj-{len(calls['uploads'])}.zip"]


def test_a_reinitialize_while_another_one_sends_its_run_is_refused_and_the_first_one_completes(http):
    """B arrives while A holds its claim and sends its run: B is refused with 409 ``starting`` and charges nothing;
    A's run is recorded. (Taking A's claim over, as e13e24f did, could strand the scan: next test.)"""
    client, engine, celery, _calls = http
    inner = {}
    celery.on_send = lambda _task: inner.update(b=_in_thread(lambda: _reinit_direct(1, "cbom", ZIP_PAYLOAD, BIGGER)))
    a = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert inner["b"][0] == 409 and inner["b"][1]["code"] == "starting", inner["b"]
    assert "Nothing was charged" in inner["b"][1]["detail"]
    assert a.status_code == 200 and a.json()["credits_charged"] == 6.5, a.text
    assert _scan(engine, 1).task_id == "new-1" and _scan(engine, 1).credit_charged == 7.5
    assert _balance(engine) == 93.5 and _lines(engine) == [("scan_reinitialize_charge", -6.5)]
    assert celery.revoked == ["t-1"] and [t for *_x, t in celery.sent] == ["new-1"]


def test_a_scan_is_never_left_on_a_claim_whose_runs_were_all_withdrawn(http):
    """e13e24f let B take over A's claim while A was sending. A then lost (409 superseded) and withdrew its own run AND
    the replaced run t-1; when B's send then failed, B gave the scan back to A's claim: pending on a claim nobody
    records, every run withdrawn, A's 6.5 kept, nothing left to run. The scan must always end on a run that goes ahead."""
    client, engine, celery, _calls = http
    b_reached, a_done, box = threading.Event(), threading.Event(), {}

    def b_send_fails_after_a(_task):  # only if B gets as far as sending: wait for A to finish, then the broker fails
        b_reached.set()
        a_done.wait(10)
        raise RuntimeError("broker down")

    def b_request():
        try:
            box["b"] = asyncio.run(_reinit_direct(1, "cbom", ZIP_PAYLOAD, BIGGER))
        finally:
            b_reached.set()

    def a_sending(_task):
        celery.on_send = b_send_fails_after_a
        box["thread"] = threading.Thread(target=b_request)
        box["thread"].start()
        b_reached.wait(10)  # B was refused, or B claimed and is sending

    celery.on_send = a_sending
    a = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    a_done.set()
    box["thread"].join(10)
    scan = _scan(engine, 1)
    sent = [t for *_x, t in celery.sent]
    assert scan.task_id in sent and scan.task_id not in celery.revoked, (
        f"scan left on {scan.task_id!r} (status {scan.scan_status}, charged {scan.credit_charged}); "
        f"sent {sent}, withdrawn {celery.revoked}; A {a.status_code}, B {box.get('b')}")
    assert a.status_code == 200 and box["b"][0] == 409 and box["b"][1]["code"] == "starting"
    assert _balance(engine) == 93.5 and scan.credit_charged == 7.5


# ===================================================================================== refunds still behave
def test_cancel_after_a_top_up_refunds_everything_once(http):
    client, engine, _celery, _calls = http
    assert _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG).status_code == 200
    assert _balance(engine) == 93.5
    r = client.post("/1/cbom/scan/1/cancel", headers={"Authorization": "Bearer 1"})
    assert r.status_code == 200 and r.json()["refunded_credits"] == 7.5  # the 1 credit of /start and the 6.5 top-up
    again = client.post("/1/cbom/scan/1/cancel", headers={"Authorization": "Bearer 1"})
    assert again.status_code == 409 and again.json()["code"] == "already_cancelled"
    assert _balance(engine) == 101.0 and _scan(engine, 1).scan_status == "cancelled"  # 93.5 + 7.5, once
    # every movement of this scan has its line, so the ledger tells the same story as the balance (+1.0 overall)
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_cancel_refund", 7.5)]
    assert [e["movement_key"] for e in _ledger(engine)] == ["scan:1:reinit:new-1", "scan:1:cancel"]
    assert sum(e["delta"] for e in _ledger(engine)) == _balance(engine) - 100.0


def test_failure_after_a_top_up_refunds_everything_once(http):
    from backend.utilities.celery import celery_connection as cc

    client, engine, celery, _calls = http
    assert _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG).status_code == 200
    assert _balance(engine) == 93.5 and _scan(engine, 1).credit_charged == 7.5
    celery.states["new-1"] = _Result("FAILURE", RuntimeError("worker crashed"))
    for _ in range(2):
        cc.get_status_and_update_db(1, "new-1", Scan, engine)
    assert _scan(engine, 1).scan_status == "failure" and _balance(engine) == 101.0  # 93.5 + everything paid, once
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_failure_refund", 7.5)]
    assert _ledger(engine)[1]["movement_key"] == "scan:1:failure" and _ledger(engine)[1]["balance_after"] == 101.0


def test_a_failure_never_commits_without_its_refund(http, monkeypatch):
    """The failure refund is written in the transaction that flips the status: if the refund cannot be written, the
    scan is not marked failed either, and the next poll does both (e13e24f committed the failure first and refunded in
    a second transaction: a crash or a database error in between kept the charge for a failed scan)."""
    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.team import credit_ledger

    client, engine, celery, _calls = http
    assert _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG).status_code == 200
    celery.states["new-1"] = _Result("FAILURE", RuntimeError("worker crashed"))

    def lost(*_a, **_k):
        raise RuntimeError("database connection lost")

    real_move = getattr(credit_ledger, "move", None)  # (raising=False: the same test runs on e13e24f, which had none)
    monkeypatch.setattr(credit_ledger, "move",
                        lambda session, **kw: lost() if kw.get("reason") == "scan_failure_refund" else real_move(
                            session, **kw), raising=False)
    if hasattr(cc, "refund_credits_to_team"):  # the e13e24f path: the refund in its own transaction
        monkeypatch.setattr(cc, "refund_credits_to_team", lost)
    try:
        cc.get_status_and_update_db(1, "new-1", Scan, engine)
    except HTTPException:
        pass
    assert (_scan(engine, 1).scan_status, _balance(engine)) == ("pending", 93.5), "failed without its refund"
    monkeypatch.setattr(credit_ledger, "move", real_move, raising=False)
    cc.get_status_and_update_db(1, "new-1", Scan, engine)
    assert (_scan(engine, 1).scan_status, _balance(engine)) == ("failure", 101.0)
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_failure_refund", 7.5)]


def test_a_reinitialize_racing_a_cancel_ends_cancelled_and_refunded_once(http):
    from backend.utilities.scan.cancel_scan import cancel_scan

    client, engine, celery, _calls = http
    outcome = {}
    celery.on_send = lambda _task: outcome.update(
        cancel=cancel_scan(engine, scan_id=1, team_id=1, scan_type="cbom", user_id=1))
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 409 and r.json()["code"] == "superseded", r.text
    assert outcome["cancel"]["refunded_credits"] == 7.5  # what the scan had paid, the top-up included
    scan = _scan(engine, 1)
    assert scan.scan_status == "cancelled" and _balance(engine) == 101.0  # 93.5 + 7.5: refunded once, in full
    assert "new-1" in celery.revoked and "t-1" in celery.revoked  # neither run goes ahead
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_cancel_refund", 7.5)]


def test_a_cancel_whose_run_is_replaced_under_it_cancels_the_new_run_and_refunds_everything(http, monkeypatch):
    """Found by the PostgreSQL race test: a reinitialize that replaces the task between the cancel's read and its
    compare-and-set made the cancel answer 409 "not started" and the scan carry on. The cancel now reads the row
    again and cancels the run that replaced it."""
    from backend.utilities.scan import cancel_scan as cancel_mod

    client, engine, celery, _calls = http
    real = cancel_mod.refunded_credits
    inner = {}

    def refunded_then_replaced(scan):
        amount = real(scan)
        if not inner:  # the cancel has read the row; a whole reinitialize lands before its compare-and-set
            inner["r"] = _in_thread(lambda: _reinit_direct(1, "cbom", ZIP_PAYLOAD, BIG))
        return amount

    monkeypatch.setattr(cancel_mod, "refunded_credits", refunded_then_replaced)
    r = client.post("/1/cbom/scan/1/cancel", headers={"Authorization": "Bearer 1"})
    assert inner["r"][0] == 200 and inner["r"][1]["credits_charged"] == 6.5
    assert r.status_code == 200, r.text
    assert r.json()["refunded_credits"] == 7.5
    assert _scan(engine, 1).scan_status == "cancelled" and _balance(engine) == 101.0
    assert celery.revoked == ["t-1", "new-1"]  # the replaced run (by the reinitialize), then the new one (cancel)
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_cancel_refund", 7.5)]


def test_a_failed_dispatch_gives_the_difference_back_and_keeps_the_queued_run(http):
    client, engine, celery, calls = http
    celery.fail_send = True
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 500, r.text
    scan = _scan(engine, 1)
    assert (scan.scan_status, scan.task_id, scan.credit_charged, scan.credit_consumed) == ("pending", "t-1", 1.0, 1.0)
    assert scan.credit_estimate == _estimate_of("cbom", ZIP_PAYLOAD, SMALL, 1.0)  # restored exactly, no claim left
    # the queued run goes ahead; the new run's id is withdrawn in case the broker took it before failing
    assert _balance(engine) == 100.0 and celery.revoked == ["new-1"]
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_reinitialize_refund", 6.5)]
    assert _ledger(engine)[1]["movement_key"] == "scan:1:reinit-refund:new-1"
    assert _ledger(engine)[1]["detail"]["by"] == "dispatch_failure"
    assert calls["deleted"] == ["obj-2.zip"]


def test_a_run_sent_but_not_recorded_is_withdrawn_and_the_claim_given_back(http, monkeypatch):
    """The run reached the broker, then recording it failed: the run is withdrawn (it would run unpaid and unseen),
    the scan goes back to its queued run and the difference comes back (QA mutant N1)."""
    from backend.utilities.scan import start_scan as start_mod

    client, engine, celery, _calls = http

    def broken_metadata(**_kw):
        raise RuntimeError("database error while recording the run")

    monkeypatch.setattr(start_mod, "get_scan_metadata_for_type", broken_metadata)
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 500, r.text
    assert [t for *_x, t in celery.sent] == ["new-1"] and "new-1" in celery.revoked and "t-1" not in celery.revoked
    scan = _scan(engine, 1)
    assert (scan.scan_status, scan.task_id, scan.credit_charged) == ("pending", "t-1", 1.0)
    assert _balance(engine) == 100.0
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_reinitialize_refund", 6.5)]


def test_a_poll_of_the_replaced_run_never_changes_the_scan(http):
    """The scan list polls in a background task with the task ids it read; one of them may be the replaced run."""
    from backend.utilities.celery import celery_connection as cc

    client, engine, celery, calls = http
    assert _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG).status_code == 200
    for state, result in (("SUCCESS", {"results": [{"id": 1}], "duration_of_scan": 1}),
                          ("FAILURE", RuntimeError("old run failed")), ("REVOKED", None), ("STARTED", None)):
        celery.states["t-1"] = _Result(state, result)
        status, data, _scan_obj = cc.get_status_and_update_db(1, "t-1", Scan, engine)
        assert (status, data) == ("pending", {}), state
        scan = _scan(engine, 1)
        assert (scan.scan_status, scan.task_id, scan.scan_data) == ("pending", "new-1", {}), state
    assert calls["findings"] == [] and _balance(engine) == 93.5


def test_a_poll_whose_task_is_replaced_while_it_runs_reports_the_stored_scan(http, monkeypatch):
    """A poll of t-1 sees it succeed; a whole reinitialize lands before the poll's compare-and-set, which then stores
    nothing. The poll must report the scan as stored (pending on the new run), not the replaced run's success
    (QA mutant N3: the second replaced-task return in get_status_and_update_db)."""
    from backend.utilities.celery import celery_connection as cc

    client, engine, celery, calls = http
    inner = {}
    main = threading.current_thread()

    class OldRunSucceeded:
        state, info, traceback = "SUCCESS", None, None

        @property
        def result(self):  # read after the poll's checks, before its compare-and-set: the reinitialize lands here
            if not inner:
                inner["r"] = _in_thread(lambda: _reinit_direct(1, "cbom", ZIP_PAYLOAD, BIG))
            return {"results": [{"id": 1}], "duration_of_scan": 1}

    real = celery.AsyncResult
    monkeypatch.setattr(celery, "AsyncResult",
                        lambda task_id: OldRunSucceeded() if threading.current_thread() is main and task_id == "t-1"
                        else real(task_id))
    status, data, _obj = cc.get_status_and_update_db(1, "t-1", Scan, engine)
    assert inner["r"][0] == 200, inner["r"]
    assert (status, data) == ("pending", {})
    scan = _scan(engine, 1)
    assert (scan.scan_status, scan.task_id, scan.scan_data) == ("pending", "new-1", {})
    assert calls["findings"] == [] and _balance(engine) == 93.5


# ===================================================================================== the claim: crash window (#57 review)
def test_the_claim_carries_what_a_give_back_needs(http):
    """The claim's own UPDATE names the run being sent and the run it replaces, and keeps the replaced task, charge and
    estimate: a process killed after the claim leaves everything needed to give it back."""
    from backend.utilities.celery import celery_connection as cc

    client, engine, celery, _calls = http
    seen = {}

    def look(_task):
        scan = _scan(engine, 1)
        asked_before = list(celery.asked)
        polled = cc.get_status_and_update_db(1, scan.task_id, Scan, engine)[0]  # a list poll of the claim
        seen.update(task=scan.task_id, claim=scan.credit_estimate.get("reinitialize_claim"), lines=_lines(engine),
                    balance=_balance(engine), polled=polled, asked=celery.asked[len(asked_before):])

    celery.on_send = look
    assert _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG).status_code == 200
    assert seen["task"] == "reinit-new-1.t-1"
    assert seen["claim"] == {"task_id": "t-1", "credit_charged": 1.0, "credit_consumed": 1.0,
                             "credit_estimate": _estimate_of("cbom", ZIP_PAYLOAD, SMALL, 1.0)}
    assert seen["lines"] == [("scan_reinitialize_charge", -6.5)] and seen["balance"] == 93.5
    assert seen["polled"] == "pending" and seen["asked"] == []  # a claim is not a Celery task: never asked about


def _strand_a_claim(http, monkeypatch):
    """A reinitialize whose process cannot give its claim back (the broker failed, then the database did): what a
    process killed between the claim and the record leaves (the out-of-process kill: test_reinitialize_crash_window.py)."""
    from backend.utilities.scan import reinitialize as reinit_mod

    client, engine, celery, _calls = http
    real = reinit_mod.give_back_claim

    def unreachable(*_a, **_k):
        raise RuntimeError("database unreachable")

    monkeypatch.setattr(reinit_mod, "give_back_claim", unreachable)
    celery.fail_send = True
    assert _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG).status_code == 500
    monkeypatch.setattr(reinit_mod, "give_back_claim", real)
    celery.fail_send = False
    scan = _scan(engine, 1)
    assert (scan.task_id, scan.credit_charged, _balance(engine)) == ("reinit-new-1.t-1", 7.5, 93.5)
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5)] and celery.revoked == []
    return reinit_mod


def _age_claim(engine, scan_id=1, minutes=11):
    with Session(engine) as s:
        scan = s.get(Scan, scan_id)
        scan.last_updated = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)
        s.add(scan)
        s.commit()


def test_a_claim_left_behind_is_given_back_by_the_sweeper(http, monkeypatch):
    client, engine, celery, _calls = http
    reinit_mod = _strand_a_claim(http, monkeypatch)
    assert reinit_mod.sweep_stale_claims(engine) == []  # fresh: its request may still be sending
    later = dt.datetime.now(dt.timezone.utc) + reinit_mod.STALE_CLAIM_AFTER + dt.timedelta(seconds=1)
    assert reinit_mod.sweep_stale_claims(engine, now=later) == [1]
    scan = _scan(engine, 1)
    assert (scan.scan_status, scan.task_id, scan.credit_charged, scan.credit_consumed) == ("pending", "t-1", 1.0, 1.0)
    assert scan.credit_estimate == _estimate_of("cbom", ZIP_PAYLOAD, SMALL, 1.0)
    assert _balance(engine) == 100.0
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_reinitialize_refund", 6.5)]
    assert _ledger(engine)[1]["detail"]["by"] == "sweeper"
    assert celery.revoked == ["new-1"]  # the claim's run, in case it was sent; the queued run t-1 goes ahead
    assert reinit_mod.sweep_stale_claims(engine, now=later) == []  # once

    from backend.utilities.dast import beat  # the scheduler sidecar runs the sweep every tick

    assert beat.sweep_reinitialize_claims(engine=engine) == []


def test_a_reinitialize_waits_for_a_fresh_claim_and_gives_a_stale_one_back_first(http, monkeypatch):
    client, engine, celery, _calls = http
    _strand_a_claim(http, monkeypatch)
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 409 and r.json()["code"] == "starting", r.text
    assert _balance(engine) == 93.5 and len(_ledger(engine)) == 1
    _age_claim(engine)
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 200 and (r.json()["credits_charged"], r.json()["credits_total"]) == (6.5, 7.5), r.text
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_reinitialize_refund", 6.5),
                              ("scan_reinitialize_charge", -6.5)]
    assert _ledger(engine)[1]["detail"]["by"] == "reinitialize"
    assert _scan(engine, 1).task_id == "new-2" and _balance(engine) == 93.5
    assert celery.revoked == ["new-1", "t-1"]  # the stale claim's run, then the run this reinitialize replaced


def test_a_cancel_of_a_scan_left_on_a_claim_withdraws_both_runs_and_refunds_everything(http, monkeypatch):
    client, engine, celery, _calls = http
    _strand_a_claim(http, monkeypatch)
    r = client.post("/1/cbom/scan/1/cancel", headers={"Authorization": "Bearer 1"})
    assert r.status_code == 200 and r.json()["refunded_credits"] == 7.5, r.text
    assert _balance(engine) == 101.0 and _scan(engine, 1).scan_status == "cancelled"
    assert set(celery.revoked) == {"new-1", "t-1"} and set(celery.marks.docs) == {"new-1", "t-1"}
    assert _lines(engine) == [("scan_reinitialize_charge", -6.5), ("scan_cancel_refund", 7.5)]


# ===================================================================================== "Run again" is a new scan, charged at start
def test_a_failed_scan_is_never_rerun_for_free_and_run_again_is_charged_at_start(http):
    client, engine, celery, calls = http
    hdr = {"Authorization": "Bearer 1"}
    failed = _reinit(client, 5, "cbom", ZIP_PAYLOAD, BIG)  # failed: not waiting in the queue
    assert failed.status_code == 409 and failed.json()["code"] == "not_pending", failed.text
    start_failed = client.post("/1/cbom/scan/5/start", data={"start_scan_payload_string": ZIP_PAYLOAD},
                               files={"uploaded_file": ("code.zip", BIG, "application/zip")}, headers=hdr)
    assert start_failed.status_code == 400
    assert celery.sent == [] and _balance(engine) == 100.0
    # "Run again" (frontend components/scan-run-again.tsx): a new scan, then the estimate and Start a new scan has
    new_id = client.post("/1/cbom/scan", json={"title": "again"}, headers=hdr).json()["scan_id"]
    files = {"uploaded_file": ("code.zip", BIG, "application/zip")}
    no_estimate = client.post(f"/1/cbom/scan/{new_id}/start", data={"start_scan_payload_string": ZIP_PAYLOAD},
                              files=files, headers=hdr)
    assert no_estimate.status_code == 400 and "estimate" in no_estimate.json()["detail"]
    est = client.post(f"/1/cbom/scan/{new_id}/estimate_credits", data={"start_scan_payload_string": ZIP_PAYLOAD},
                      files={"uploaded_file": ("code.zip", BIG, "application/zip")}, headers=hdr)
    assert est.status_code == 200 and est.json()["credits_required"] == 7.5
    started = client.post(f"/1/cbom/scan/{new_id}/start", data={"start_scan_payload_string": ZIP_PAYLOAD},
                          files={"uploaded_file": ("code.zip", BIG, "application/zip")}, headers=hdr)
    assert started.status_code == 200, started.text
    assert _balance(engine) == 92.5 and _scan(engine, new_id).credit_charged == 7.5 and len(celery.sent) == 1
