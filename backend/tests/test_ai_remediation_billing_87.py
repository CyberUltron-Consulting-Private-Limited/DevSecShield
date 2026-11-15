"""Issue #87: AI remediation of a finding is charged before it is generated, and never given away.

Before: the route checked the balance, generated, stored the remediation in Mongo and only then debited; a stored
remediation is served from the cache without a charge. Concurrent requests at a low balance all passed the check and
all called the model; when the debit was then refused the remediation stayed stored and was served free.

Now: claim the finding (one conditional Mongo update: at most one generation per finding at a time), debit with the
atomic conditional UPDATE (``deduct_credits_from_team``), generate, store only while the claim is ours, refund when
generation fails. These tests run the real route over a real (SQLite) credit balance, with a thread-safe in-memory
stand-in for the ``scan_findings`` collection that implements the filters the route uses, and requests sent
concurrently.

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \\
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \\
      python -m pytest tests/test_ai_remediation_billing_87.py -q -p no:cacheprovider
"""
from __future__ import annotations

import asyncio
import copy
import datetime as dt
import sys
import threading
import time
import types
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from bson import ObjectId  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from backend.new_models import Scan, Team  # noqa: E402

COST = 0.05
_MISSING = object()


# ------------------------------------------------------------------------------------------------ scan_findings
def _get(doc, path):
    value = doc
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _matches(doc, flt) -> bool:
    for key, cond in flt.items():
        if key == "$or":
            if not any(_matches(doc, sub) for sub in cond):
                return False
            continue
        value = _get(doc, key)
        if isinstance(cond, dict) and cond and all(k.startswith("$") for k in cond):
            for op, arg in cond.items():
                if op == "$ne" and value is not _MISSING and value == arg:
                    return False
                if op == "$exists" and (value is not _MISSING) != bool(arg):
                    return False
                if op == "$lt" and (value is _MISSING or not value < arg):
                    return False
                if op not in ("$ne", "$exists", "$lt"):
                    raise AssertionError(f"operator {op} not supported by the stand-in")
        elif value is _MISSING or value != cond:
            return False
    return True


class Findings:
    """``find_one`` / ``update_one`` with Mongo's single-document atomicity (one lock)."""

    def __init__(self, docs):
        self.docs = {d["_id"]: d for d in docs}
        self.lock = threading.Lock()
        self.updates: list[dict] = []

    def find_one(self, flt):
        with self.lock:
            for doc in self.docs.values():
                if _matches(doc, flt):
                    return copy.deepcopy(doc)
        return None

    def update_one(self, flt, update):
        with self.lock:
            for doc in self.docs.values():
                if _matches(doc, flt):
                    for key, value in (update.get("$set") or {}).items():
                        doc[key] = copy.deepcopy(value)
                    for key in (update.get("$unset") or {}):
                        doc.pop(key, None)
                    self.updates.append(update)
                    return types.SimpleNamespace(matched_count=1, modified_count=1)
        return types.SimpleNamespace(matched_count=0, modified_count=0)


# ------------------------------------------------------------------------------------------------ app
@pytest.fixture()
def world(monkeypatch, tmp_path):
    # a file database, one connection per thread: the requests below run like separate API workers
    engine = create_engine(f"sqlite:///{tmp_path / 'credits.db'}", connect_args={"check_same_thread": False,
                                                                                "timeout": 30})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=1.0))
        s.add(Scan(id=7, team_id=1, owner_user_id=1, scan_type="sast", scan_status="success",
                   created_at=dt.datetime.now(dt.timezone.utc)))
        s.commit()
    ids = [ObjectId() for _ in range(8)]
    findings = Findings([{"_id": oid, "scan_id": 7, "finding_data": {"title": f"f{i}"}} for i, oid in enumerate(ids)])
    calls = {"generate": 0, "mode": "ok", "delay": 0.3}
    calls_lock = threading.Lock()

    def generate(finding_data, scan_type):
        with calls_lock:
            calls["generate"] += 1
        time.sleep(calls["delay"])  # the model call: long enough for every concurrent request to arrive
        if calls["mode"] == "raise":
            raise RuntimeError("model endpoint reset the connection")
        if calls["mode"] == "failed":
            return {"generated_at": "now", "status": "failed", "error": "model said no"}
        return {"generated_at": "now", "status": "completed", "fix": {"fixed_code": finding_data["title"]},
                "exploit_payload": {}, "diff": ""}

    async def user(*_a, **_k):
        return types.SimpleNamespace(id=1, email="u@example.test")

    from backend.routers import scans
    from backend.utilities import ratelimit
    from backend.utilities.ai import remediation as remediation_mod
    from backend.utilities.team import credits as credits_mod

    monkeypatch.setattr(scans, "get_db", lambda: engine)
    monkeypatch.setattr(scans, "get_mongo_client_db", lambda: {"scan_findings": findings})
    monkeypatch.setattr(scans, "get_user_from_header_or_raise_exception", user)
    monkeypatch.setattr(scans, "check_if_user_is_in_team", lambda *_a, **_k: None)
    monkeypatch.setattr(credits_mod, "get_db", lambda: engine)
    monkeypatch.setattr(remediation_mod, "generate_remediation", generate)
    for limiter in (scans.start_limiter, scans.remediate_limiter):
        monkeypatch.setattr(limiter, "times", 10_000)
    ratelimit.reset_all()
    yield types.SimpleNamespace(engine=engine, findings=findings, ids=ids, calls=calls)
    ratelimit.reset_all()


def _balance(engine) -> float:
    with Session(engine) as s:
        return s.get(Team, 1).credit_balance


def _set_balance(engine, value: float) -> None:
    with Session(engine) as s:
        team = s.get(Team, 1)
        team.credit_balance = value
        s.add(team)
        s.commit()


def _post_all(oids) -> list:
    """Every request in flight at once, each on its own thread and event loop, as on an API with several workers
    (BACKEND_WORKERS): a blocking call in one request does not hold the others back."""
    from concurrent.futures import ThreadPoolExecutor

    import httpx

    from backend.main import app

    start = threading.Barrier(len(oids))

    def one(oid):
        async def go():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
                start.wait()
                return await client.post(f"/1/sast/scan/7/finding/{oid}/remediate",
                                         headers={"Authorization": "Bearer t"})

        return asyncio.run(go())

    with ThreadPoolExecutor(max_workers=len(oids)) as pool:
        return list(pool.map(one, oids))


def _doc(world, oid):
    return world.findings.docs[oid]


# ------------------------------------------------------------------------------------------------ tests
def test_concurrent_requests_for_one_finding_generate_and_charge_once(world):
    oid = world.ids[0]
    responses = _post_all([oid] * 8)
    codes = sorted(r.status_code for r in responses)
    assert world.calls["generate"] == 1, codes
    assert codes.count(200) >= 1 and set(codes) <= {200, 409}, [r.text for r in responses]
    assert _balance(world.engine) == pytest.approx(1.0 - COST)  # charged exactly once
    assert _doc(world, oid)["remediation"]["status"] == "completed"
    assert "remediation_claim" not in _doc(world, oid)
    busy = [r for r in responses if r.status_code == 409]
    assert all("being generated" in r.json()["detail"] for r in busy)
    # stored after the charge: served from the cache from now on, with no further charge or model call
    again = _post_all([oid])[0]
    assert again.status_code == 200 and again.json()["status"] == "completed"
    assert world.calls["generate"] == 1 and _balance(world.engine) == pytest.approx(1.0 - COST)


def test_low_balance_concurrent_requests_never_get_a_free_remediation(world):
    _set_balance(world.engine, 2 * COST)  # enough for exactly two
    responses = _post_all(world.ids[:6])
    codes = [r.status_code for r in responses]
    assert sorted(codes) == [200, 200, 402, 402, 402, 402], [r.text for r in responses]
    assert world.calls["generate"] == 2  # the refused ones never reached the model
    assert _balance(world.engine) == pytest.approx(0.0)
    for oid, r in zip(world.ids[:6], responses):
        doc = _doc(world, oid)
        assert "remediation_claim" not in doc
        if r.status_code == 402:
            assert "remediation" not in doc  # nothing stored, so nothing served free later
            assert "not have enough credits" in r.json()["detail"]
        else:
            assert doc["remediation"]["status"] == "completed"
    # a refused finding is still refused at 0 credits (no cached copy exists)
    assert _post_all([world.ids[5]])[0].status_code == 402 and world.calls["generate"] == 2


@pytest.mark.parametrize("mode, code", [("failed", 200), ("raise", 500)])
def test_a_failed_generation_is_refunded_and_not_cached(world, mode, code):
    world.calls["mode"] = mode
    world.calls["delay"] = 0
    oid = world.ids[1]
    r = _post_all([oid])[0]
    assert r.status_code == code, r.text
    assert _balance(world.engine) == pytest.approx(1.0)  # debited, then refunded
    doc = _doc(world, oid)
    assert "remediation_claim" not in doc
    assert (doc.get("remediation") or {}).get("status") != "completed"
    if mode == "failed":
        assert r.json()["status"] == "failed" and doc["remediation"]["status"] == "failed"
    # the next attempt is a normal, charged generation
    world.calls["mode"] = "ok"
    r = _post_all([oid])[0]
    assert r.status_code == 200 and r.json()["status"] == "completed"
    assert _balance(world.engine) == pytest.approx(1.0 - COST)


def test_a_stale_claim_does_not_block_the_finding_forever(world):
    """A worker that died mid-generation leaves its claim; after the claim's lifetime another request may take it."""
    from backend.utilities.ai import paid_remediation as PR

    world.calls["delay"] = 0
    oid, fresh = world.ids[2], world.ids[3]
    _doc(world, oid)["remediation_claim"] = {"token": "dead", "at": time.time() - PR.CLAIM_TTL_S - 1}
    _doc(world, fresh)["remediation_claim"] = {"token": "live", "at": time.time()}
    stale, live = _post_all([oid, fresh])
    assert stale.status_code == 200 and stale.json()["status"] == "completed"
    assert live.status_code == 409 and _doc(world, fresh)["remediation_claim"]["token"] == "live"
    assert world.calls["generate"] == 1 and _balance(world.engine) == pytest.approx(1.0 - COST)


def test_cbom_ai_assist_moves_no_credits():
    """The CBOM AI assistant (routers/cbom_ai.py) is free: it neither debits nor refunds, so #87's ordering cannot
    apply to it (its in-process answer cache holds nothing that was paid for)."""
    root = _REPO_ROOT / "backend"
    for path in [root / "routers" / "cbom_ai.py", *(root / "utilities" / "cbom_ai").glob("*.py")]:
        text = path.read_text()
        for name in ("deduct_credits", "refund_credits", "credit_balance", "check_if_team_has_enough_credits"):
            assert name not in text, (path.name, name)
