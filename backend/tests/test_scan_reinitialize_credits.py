"""Reinitialize charges what the new input costs (#33).

POST /{team}/{type}/scan/{id}/reinitialize sends a new worker run, with a new input, for a scan that was already
estimated, charged and queued. Before #33 it never priced the new input: pay for a tiny archive, reinitialize with a
huge one for free. The rules proved here (backend/utilities/scan/reinitialize.py):

* the new input is priced with the estimator a new scan uses; only the positive difference against what the scan
  already paid is charged, in the same transaction as the claim, and recorded in the credits ledger;
* the same input costs nothing (no new estimate) and a smaller one is never refunded;
* a balance too small for the difference is refused with 402 before anything is queued;
* the target checks of a new scan run before any credit moves (DAST address rule, git host allow-list, archive);
* only a dispatched scan the worker has not picked up yet can be reinitialized, the replaced run is withdrawn, and a
  poll of the replaced run never changes the scan;
* two reinitializes at once charge once; a cancel or a failure afterwards refunds everything that was paid, once.

Hermetic: SQLite + TestClient, fake Celery, fake S3 upload, fake DNS. The same races against a real PostgreSQL with
threads: test_reinitialize_race_postgres.py.
"""
import asyncio
import datetime as dt
import io
import json
import os
import sys
import threading
import types
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException, UploadFile
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "t2-reinitialize-test-secret-not-for-production-use")

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
SECRET_PAT = "ghp_t2SecretTokenThatMustNeverBeStored000"


def _dast(target="https://app.example/", max_urls=100, login="https://app.example/login", extra=None):
    return json.dumps({"dast": {
        "target_url": target, "max_urls": max_urls, "additional_urls_to_scan": extra,
        "auth": {"login_url": login, "xpath_of_username_field": "//u", "xpath_of_password_field": "//p",
                 "username": "qa", "password": "dast-password-not-stored", "xpath_of_submit_button": "//b"},
    }})


def _sast(repo_url="https://github.com/acme/app", branch="main"):
    return json.dumps({"sast": {"app_lang": "python", "repo_context": {
        "mode": "github", "repo_url": repo_url, "PAT": SECRET_PAT, "branch": branch}}})


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
        self.marks = _Marks()
        self.control = types.SimpleNamespace(revoke=lambda task_id, **_kw: self.revoked.append(task_id))
        self.backend = types.SimpleNamespace(database={"scan_cancellations": self.marks})
        self.fail_send = False
        self.on_send = None  # a hook run inside send_task, before the task id is returned

    def send_task(self, name, kwargs, queue):
        if self.fail_send:
            raise RuntimeError("broker down")
        task_id = f"new-{len(self.sent) + 1}"
        self.sent.append((name, kwargs, queue, task_id))
        if self.on_send is not None:
            hook, self.on_send = self.on_send, None
            hook(task_id)
        return types.SimpleNamespace(id=task_id)

    def AsyncResult(self, task_id):  # noqa: N802 (Celery's name)
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


def _ledger(engine):
    from backend.new_models import CreditLedgerEntry

    with Session(engine) as s:
        rows = s.exec(select(CreditLedgerEntry).order_by(CreditLedgerEntry.id)).all()
        return [{"team_id": r.team_id, "scan_id": r.scan_id, "user_id": r.user_id, "delta": r.delta,
                 "balance_after": r.balance_after, "reason": r.reason, "detail": r.detail} for r in rows]


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
    assert entry["delta"] == -3.0 and SECRET_PAT not in json.dumps(entry)
    assert SECRET_PAT not in json.dumps(_scan(engine, 3).credit_estimate)


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


@pytest.mark.parametrize("state, stored", [("STARTED", "started"), ("RETRY", "retry")])
def test_reinitialize_is_refused_once_the_worker_has_picked_the_run_up(http, state, stored):
    client, engine, celery, _calls = http
    celery.states["t-1"] = _Result(state)
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 409 and r.json()["code"] == "already_started", r.text
    assert celery.sent == [] and celery.revoked == [] and _balance(engine) == 100.0
    assert _scan(engine, 1).scan_status == stored and _scan(engine, 1).task_id == "t-1"


# ===================================================================================== concurrency
def test_two_reinitializes_at_once_charge_the_difference_once(http, monkeypatch):
    """B runs to the end while A is being priced; A's claim then finds the scan changed and charges nothing."""
    from backend.utilities.scan import estimate_scan

    client, engine, celery, _calls = http
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


def test_a_reinitialize_during_another_ones_dispatch_takes_over_and_the_total_is_the_highest_price(http):
    """B arrives after A charged (A is sending its run): B prices against what A made the scan pay, A's run is
    withdrawn when it finds the scan is not its own any more, and the scan pays exactly B's price in total."""
    client, engine, celery, _calls = http
    inner = {}
    celery.on_send = lambda _task: inner.update(b=_in_thread(lambda: _reinit_direct(1, "cbom", ZIP_PAYLOAD, BIGGER)))
    a = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    b_status, b_body = inner["b"]
    assert b_status == 200 and (b_body["credits_charged"], b_body["credits_total"]) == (2.5, 10.0)
    assert a.status_code == 409 and a.json()["code"] == "superseded", a.text
    assert "stays with the scan" in a.json()["detail"]  # A's 6.5 is part of what B priced against, never "not charged"
    assert _scan(engine, 1).task_id == "new-2" and _scan(engine, 1).credit_charged == 10.0
    assert _balance(engine) == 91.0 and [e["delta"] for e in _ledger(engine)] == [-6.5, -2.5]
    # A's own run and the run A replaced are withdrawn; B withdraws what it replaced (A's claim, never a real run)
    assert sorted(t for t in celery.revoked if not t.startswith("reinit-")) == ["new-1", "t-1"]
    assert [t for *_x, t in celery.sent] == ["new-1", "new-2"]


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


def test_failure_after_a_top_up_refunds_everything_once(http):
    from backend.utilities.celery import celery_connection as cc

    client, engine, celery, _calls = http
    assert _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG).status_code == 200
    assert _balance(engine) == 93.5 and _scan(engine, 1).credit_charged == 7.5
    celery.states["new-1"] = _Result("FAILURE", RuntimeError("worker crashed"))
    for _ in range(2):
        cc.get_status_and_update_db(1, "new-1", Scan, engine)
    assert _scan(engine, 1).scan_status == "failure" and _balance(engine) == 101.0  # 93.5 + everything paid, once


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
    assert [e["reason"] for e in _ledger(engine)] == ["scan_reinitialize_charge"]  # the cancel gave it back


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


def test_a_failed_dispatch_gives_the_difference_back_and_keeps_the_queued_run(http):
    client, engine, celery, calls = http
    celery.fail_send = True
    r = _reinit(client, 1, "cbom", ZIP_PAYLOAD, BIG)
    assert r.status_code == 500, r.text
    scan = _scan(engine, 1)
    assert (scan.scan_status, scan.task_id, scan.credit_charged, scan.credit_consumed) == ("pending", "t-1", 1.0, 1.0)
    assert scan.credit_estimate["digest"] == _estimate_of("cbom", ZIP_PAYLOAD, SMALL, 1.0)["digest"]
    assert _balance(engine) == 100.0 and celery.revoked == []
    assert [(e["reason"], e["delta"]) for e in _ledger(engine)] == [("scan_reinitialize_charge", -6.5),
                                                                    ("scan_reinitialize_refund", 6.5)]
    assert calls["deleted"] == ["obj-2.zip"]


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


# ===================================================================================== "Run again" is a new scan, charged at start
def test_a_failed_scan_is_never_rerun_for_free_and_run_again_is_charged_at_start(http):
    client, engine, celery, calls = http
    hdr = {"Authorization": "Bearer 1"}
    assert _reinit(client, 5, "cbom", ZIP_PAYLOAD, BIG).status_code == 400  # failed: not pending
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
