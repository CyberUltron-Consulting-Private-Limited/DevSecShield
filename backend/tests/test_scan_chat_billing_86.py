"""Issue #86: a scan chat message is charged before the model is called, and refunded once if no answer comes back.

Before: ``POST /{team_id}/{type}/scan/{scan_id}/message`` checked the balance (``check_if_team_has_enough_credits``),
stored the message, called the model and only then debited (``deduct_credits_from_team_for_message``). Concurrent
messages from a team whose balance covers one all passed the check and all got an answer; the debits that no longer
fit were refused after the answers were stored.

Now: one conditional debit (``UPDATE team SET credit_balance = credit_balance - 0.006 WHERE credit_balance >= 0.006``)
and its credit ledger row ``chat:<message id>:charge``, in one transaction, before anything is stored or the model is
called. A refused debit gets the same reply as a low balance always did, with nothing stored. Any failure before the
answer comes back refunds the message once (``chat:<message id>:refund``, only for a charge that committed).

The tests run the real route over a real credit balance (SQLite always; PostgreSQL too when ``CBOM_TEST_PG_URL`` is
set, as in CI, each test in a schema of its own), with thread-safe in-memory stand-ins for the two Mongo collections
and for the model (``backend.utilities.ai.chatbot.create_response``), and send the messages concurrently, each on its
own thread and event loop, as on an API with several workers.

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \\
      PG_USER=ci PG_USER_PASS=ci PG_DB=ci uv run python -m pytest tests/test_scan_chat_billing_86.py -q
"""
from __future__ import annotations

import asyncio
import copy
import datetime as dt
import logging
import sys
import threading
import types
import uuid
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import sqlalchemy as sa  # noqa: E402
from bson import ObjectId  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

import backend.utilities.cbom_sources.billing  # noqa: E402,F401  (the ledger table, in create_all)

from backend.new_models import Scan, Team, TeamMembership, User  # noqa: E402

COST = 0.006
REFUSED = {"content": "Team does not have enough credits to send a message"}
MODEL_FAILED = "Could not generate response , try again later"  # what create_response raises when the model fails
from backend.tests.support.pg_test_db import cbom_test_pg_url  # noqa: E402  (review 6065677758 n1)
PG = cbom_test_pg_url()  # a database named *test* only
BACKENDS = ["sqlite"] + (["pg"] if PG else [])


# ------------------------------------------------------------------------------------------------ stand-ins
class Collection:
    """``insert_one`` / ``count_documents`` of one Mongo collection, thread-safe."""

    def __init__(self):
        self.docs: list[dict] = []
        self.lock = threading.Lock()
        self.fail_insert: Exception | None = None

    def insert_one(self, doc):
        with self.lock:
            if self.fail_insert is not None:
                raise self.fail_insert
            doc.setdefault("_id", ObjectId())  # as pymongo does
            self.docs.append(copy.deepcopy(dict(doc)))
            return types.SimpleNamespace(inserted_id=doc["_id"])

    def count_documents(self, flt):
        with self.lock:
            return sum(1 for d in self.docs if all(d.get(k) == v for k, v in flt.items()))


@pytest.fixture()
def model(monkeypatch):
    """The model behind ``create_response``: counts its calls, answers after ``delay`` seconds (long enough for every
    concurrent message to be in flight), stores its answer like the real one, or fails like it."""
    state = {"calls": 0, "mode": "ok", "delay": 0.3}
    lock = threading.Lock()

    async def create_response(scan_id, mongo_db, scan_type, scan_results, content, role, **_kw):
        with lock:
            state["calls"] += 1
        await asyncio.sleep(state["delay"])
        if state["mode"] == "http500":  # the real create_response turns every error into this
            raise HTTPException(status_code=500, detail=MODEL_FAILED)
        if state["mode"] == "raise":
            raise RuntimeError("model endpoint reset the connection")
        answer = f"answer to {content}"
        for name in ("message_log", "active_context"):
            mongo_db[name].insert_one({"scan_id": scan_id, "content": answer, "type": "message", "sender": "assistant",
                                       "created_at": dt.datetime.now(dt.timezone.utc)})
        return {"content": answer, "reasoning": ""}

    chatbot = types.ModuleType("backend.utilities.ai.chatbot")
    chatbot.create_response = create_response  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "backend.utilities.ai.chatbot", chatbot)
    return state


def _pg_engine():
    """A schema of its own (never touches the tables other tests create), dropped afterwards."""
    schema = f"chat86_{uuid.uuid4().hex[:12]}"
    admin = create_engine(PG)
    with admin.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(PG, connect_args={"options": f"-csearch_path={schema}"}, pool_size=16, max_overflow=8)

    def cleanup():
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()

    return engine, cleanup


@pytest.fixture(params=BACKENDS)
def world(request, monkeypatch, tmp_path, model):
    if request.param == "pg":
        engine, cleanup = _pg_engine()
    else:
        # a file database, one connection per thread: the requests below run like separate API workers
        engine = create_engine(f"sqlite:///{tmp_path / 'credits.db'}",
                               connect_args={"check_same_thread": False, "timeout": 30})
        cleanup = engine.dispose
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=1.0))
        s.commit()
        s.add(User(id=1, email="u@example.test", password="x", first_name=None, last_name=None, profile_photo=None,
                   session_active=True))
        s.commit()
        s.add(TeamMembership(team_id=1, user_id=1, role="member"))  # scan.update
        s.commit()
        s.add(Scan(id=7, team_id=1, owner_user_id=1, scan_type="sast", scan_status="success",
                   scan_data={"results": [{"title": "SQL injection in login()"}]}))
        s.commit()
    mongo = {"message_log": Collection(), "active_context": Collection()}

    async def user(*_a, **_k):
        return types.SimpleNamespace(id=1, email="u@example.test")

    from backend.routers import scans
    from backend.utilities.team import credits as credits_mod

    monkeypatch.setattr(scans, "get_db", lambda: engine)
    monkeypatch.setattr(scans, "get_mongo_client_db", lambda: mongo)
    monkeypatch.setattr(scans, "get_user_from_header_or_raise_exception", user)
    monkeypatch.setattr(scans, "check_if_user_is_in_team", lambda *_a, **_k: None)
    monkeypatch.setattr(credits_mod, "get_db", lambda: engine)
    monkeypatch.setattr(scans.write_limiter, "times", 10_000)
    yield types.SimpleNamespace(engine=engine, mongo=mongo, model=model)
    cleanup()


def _balance(engine) -> float:
    with Session(engine) as s:
        return s.get(Team, 1).credit_balance


def _set_balance(engine, value: float) -> None:
    with Session(engine) as s:
        team = s.get(Team, 1)
        team.credit_balance = value
        s.add(team)
        s.commit()


def _ledger(engine) -> list[tuple]:
    from backend.utilities.cbom_sources.billing import CbomCreditEntry

    with Session(engine) as s:
        return sorted((r.idem_key, r.kind, r.reason, r.amount_c, r.team_id, r.run_id, r.job_id)
                      for r in s.exec(select(CbomCreditEntry)).all())


def _authorization() -> str:
    from backend.utilities.auth.auth_utils import create_access_token

    return f"Bearer {create_access_token('u@example.test', version=0)}"


def _send_all(texts: list[str]) -> list:
    """Every message in flight at once, each on its own thread and event loop (BACKEND_WORKERS): a blocking call in
    one request does not hold the others back."""
    from concurrent.futures import ThreadPoolExecutor

    import httpx

    from backend.main import app

    start = threading.Barrier(len(texts))

    def one(text):
        async def go():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
                start.wait()
                return await client.post("/1/sast/scan/7/message", json={"user_message": text},
                                         headers={"Authorization": _authorization()})

        return asyncio.run(go())

    with ThreadPoolExecutor(max_workers=len(texts)) as pool:
        return list(pool.map(one, texts))


def _content(response) -> str:
    try:
        return str(response.json().get("content", ""))
    except ValueError:
        return ""


def _user_messages(world) -> list[dict]:
    return [d for d in world.mongo["message_log"].docs if d["sender"] == "user"]


# ------------------------------------------------------------------------------------------------ tests
@pytest.mark.parametrize("paid, sent", [(1, 8), (2, 6)], ids=["balance-for-one", "balance-for-two"])
def test_concurrent_messages_get_only_the_answers_the_balance_pays_for(world, paid, sent):
    """The issue's steps: a team whose balance covers ``paid`` messages sends ``sent`` at once on a finished scan."""
    _set_balance(world.engine, paid * COST)
    responses = _send_all([f"q{i}" for i in range(sent)])
    assert world.model["calls"] == paid, [(r.status_code, r.text) for r in responses]  # dev: one call per message
    answered = [r for r in responses if r.status_code == 200 and _content(r).startswith("answer to ")]
    refused = [r for r in responses if r.status_code == 200 and r.json() == REFUSED]
    assert len(answered) == paid and len(refused) == sent - paid, [(r.status_code, r.text) for r in responses]
    assert _balance(world.engine) == pytest.approx(0.0, abs=1e-9)
    ledger = _ledger(world.engine)
    assert [row[1] for row in ledger] == ["charge"] * paid  # one charge per answer, none for a refusal, no refunds
    # a refused message stores nothing: the stored user messages are the answered ones, each named by its charge
    users = _user_messages(world)
    assert sorted(d["content"] for d in users) == sorted(_content(r).removeprefix("answer to ") for r in answered)
    assert sorted(f"chat:{d['_id']}:charge" for d in users) == [row[0] for row in ledger]
    assert len(world.mongo["message_log"].docs) == len(world.mongo["active_context"].docs) == 2 * paid


def test_the_conditional_debit_decides_not_the_balance_check(world, monkeypatch):
    """The balance check is only an early refusal. A message that passed it while other messages spent the last
    credits (the race above, made deterministic) is refused by the debit: no model call, nothing stored or charged,
    and the same reply as a low balance."""
    from backend.routers import scans

    _set_balance(world.engine, 0.0)
    monkeypatch.setattr(scans, "check_if_team_has_enough_credits", lambda *_a, **_k: True)
    r = _send_all(["q"])[0]
    assert (r.status_code, r.json()) == (200, REFUSED), r.text  # dev: the model answered, then a 400
    assert world.model["calls"] == 0
    assert world.mongo["message_log"].docs == [] and world.mongo["active_context"].docs == []
    assert _ledger(world.engine) == [] and _balance(world.engine) == 0.0


def test_a_balance_below_one_message_is_refused_before_anything_is_written(world):
    """Unchanged: the low-balance reply (HTTP 200, this content), no model call, nothing stored or charged."""
    _set_balance(world.engine, COST / 2)
    r = _send_all(["q"])[0]
    assert (r.status_code, r.json()) == (200, REFUSED), r.text
    assert world.model["calls"] == 0 and _ledger(world.engine) == []
    assert world.mongo["message_log"].docs == [] and world.mongo["active_context"].docs == []
    assert _balance(world.engine) == pytest.approx(COST / 2)


@pytest.mark.parametrize("mode, detail", [("http500", MODEL_FAILED),
                                          ("raise", "Error in sending message , please try again later")])
def test_a_failed_model_call_is_refunded_exactly_once(world, mode, detail):
    world.model.update(mode=mode, delay=0)
    r = _send_all(["q"])[0]
    assert (r.status_code, r.json()["detail"]) == (500, detail), r.text  # the error the customer always saw
    assert world.model["calls"] == 1
    assert _balance(world.engine) == pytest.approx(1.0)  # charged before the call, given back once after it failed
    (message,) = _user_messages(world)
    assert [row[:4] for row in _ledger(world.engine)] == [(f"chat:{message['_id']}:charge", "charge", "chat_message", 1),
                                                          (f"chat:{message['_id']}:refund", "refund", "chat_message", 1)]
    # the next message is charged and answered as usual
    world.model["mode"] = "ok"
    again = _send_all(["again"])[0]
    assert (again.status_code, _content(again)) == (200, "answer to again")
    assert _balance(world.engine) == pytest.approx(1.0 - COST)
    assert [row[1] for row in _ledger(world.engine)].count("charge") == 2


def test_a_message_that_cannot_be_stored_is_refunded_and_never_reaches_the_model(world):
    world.mongo["message_log"].fail_insert = RuntimeError("mongo is down")
    r = _send_all(["q"])[0]
    assert r.status_code == 500, r.text
    assert world.model["calls"] == 0
    assert _balance(world.engine) == pytest.approx(1.0)
    assert [row[1] for row in _ledger(world.engine)] == ["charge", "refund"]


def test_a_cancelled_model_call_is_refunded(world):
    """A request cancelled while the model works (a shutdown, a client gone) got no answer: it is refunded."""
    from backend.routers import scans
    from backend.utilities.db.schemas import SendMessageToScanData

    world.model["delay"] = 30

    async def go():
        task = asyncio.ensure_future(scans.send_message_to_scan(
            team_id=1, type="sast", data=SendMessageToScanData(user_message="q"), scan_id=7,
            Authorization=_authorization()))
        while world.model["calls"] == 0:
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(go())
    assert _balance(world.engine) == pytest.approx(1.0)
    assert [row[1] for row in _ledger(world.engine)] == ["charge", "refund"]


def test_a_refund_happens_once_and_only_for_a_committed_charge(world):
    from backend.utilities.ai import paid_chat as CHAT

    engine = world.engine
    assert CHAT.refund(engine, 1, "never-charged") is False  # nothing to give back: no credit is minted
    assert _balance(engine) == pytest.approx(1.0) and _ledger(engine) == []
    assert CHAT.charge(engine, 1, "m1") is True and CHAT.charge(engine, 1, "m1") is False  # a message is charged once
    assert _balance(engine) == pytest.approx(1.0 - COST)
    assert CHAT.refund(engine, 1, "m1") is True and CHAT.refund(engine, 1, "m1") is False  # and refunded once
    assert _balance(engine) == pytest.approx(1.0)
    assert _ledger(engine) == [("chat:m1:charge", "charge", "chat_message", 1, 1, None, None),
                               ("chat:m1:refund", "refund", "chat_message", 1, 1, None, None)]
    _set_balance(engine, COST / 2)
    with pytest.raises(CHAT.InsufficientCredits):
        CHAT.charge(engine, 1, "m2")
    assert _balance(engine) == pytest.approx(COST / 2) and len(_ledger(engine)) == 2  # a refused debit writes nothing


def test_a_refund_that_fails_never_hides_the_model_error(world, monkeypatch, caplog):
    """The refund cannot reach the database: the customer still gets the model's error, and the log names the
    message's charge so it can be given back by hand."""
    from backend.utilities.ai import paid_chat as CHAT

    world.model.update(mode="http500", delay=0)

    def unreachable(*_a, **_k):
        raise RuntimeError("database went away")

    monkeypatch.setattr(CHAT, "refund", unreachable)
    with caplog.at_level(logging.ERROR, logger="backend.ai.chat"):
        r = _send_all(["q"])[0]
    assert (r.status_code, r.json()["detail"]) == (500, MODEL_FAILED), r.text
    (message,) = _user_messages(world)
    assert f"refund FAILED team=1 message={message['_id']}" in caplog.text
