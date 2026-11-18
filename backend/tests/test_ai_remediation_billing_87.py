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
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

import backend.utilities.cbom_sources.billing  # noqa: E402,F401  (the ledger table, in create_all)

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
        elif cond is None:  # Mongo: {field: null} matches a null or a missing field
            if value is not _MISSING and value is not None:
                return False
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
    from backend.tests.support.rbac import stand_in_principal
    stand_in_principal(monkeypatch, user_id=1, email="u@example.test", role="member")  # F4 route policy
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
    # a refused finding is still refused at 0 credits (no cached copy exists); which two of the six win is up to the
    # race, so the one re-asked is one that was refused
    refused = next(oid for oid, r in zip(world.ids[:6], responses) if r.status_code == 402)
    assert _post_all([refused])[0].status_code == 402 and world.calls["generate"] == 2


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


# ------------------------------------------------------------------------------------------------ follow-up (#374, #382 reviews)
# A claim lineage carries one debit id; its charge and refund are ledger rows with unique keys (airem:<debit>:charge /
# :refund), each written with its balance change. Whoever drops the claim carrying a debit decides its fate once.
def _claim(world, oid, **claim):
    _doc(world, oid)["remediation_claim"] = {"at": time.time(), **claim}


def _ledger(world):
    from backend.utilities.cbom_sources.billing import CbomCreditEntry

    with Session(world.engine) as s:
        return sorted((r.idem_key, r.kind, r.amount_c) for r in s.exec(select(CbomCreditEntry)).all())


def _stale():
    from backend.utilities.ai import paid_remediation as PR

    return time.time() - PR.CLAIM_TTL_S - 1


def test_a_crash_after_the_charge_committed_is_recovered_without_a_second_charge(world):
    """The worker died after its charge committed: the retry finds the debit's ledger row and reuses it."""
    from backend.utilities.ai import paid_remediation as PR

    world.calls["delay"] = 0
    assert PR.charge(1, "dead") is True  # the dead worker's committed charge
    oid = world.ids[0]
    _claim(world, oid, token="dead", debit="dead", state="claimed", at=_stale())  # died before recording "charged"
    r = _post_all([oid])[0]
    assert r.status_code == 200 and r.json()["status"] == "completed", r.text
    assert _balance(world.engine) == pytest.approx(1.0 - COST)  # one charge in all
    assert _ledger(world) == [("airem:dead:charge", "charge", 5)]
    assert "remediation_claim" not in _doc(world, oid)


def test_a_crash_before_the_charge_committed_is_charged_once_by_the_retry(world):
    world.calls["delay"] = 0
    oid = world.ids[1]
    _claim(world, oid, token="dead", debit="dead", state="claimed", at=_stale())  # no ledger row: nothing was paid
    r = _post_all([oid])[0]
    assert r.status_code == 200 and r.json()["status"] == "completed"
    assert _balance(world.engine) == pytest.approx(1.0 - COST)
    assert _ledger(world) == [("airem:dead:charge", "charge", 5)]  # under the inherited debit id


@pytest.mark.parametrize("committed", [True, False])
def test_a_failed_retry_refunds_only_a_charge_that_committed_and_frees_the_finding(world, committed):
    """Review 5909721853 minor 1: a charge that never committed is never refunded (no credit is minted)."""
    from backend.utilities.ai import paid_remediation as PR

    world.calls["delay"] = 0
    world.calls["mode"] = "failed"
    if committed:
        PR.charge(1, "dead")
    oid = world.ids[2]
    _claim(world, oid, token="dead", debit="dead", state="charged" if committed else "claimed", at=_stale())
    r = _post_all([oid])[0]
    assert r.status_code == 200 and r.json()["status"] == "failed"
    assert _balance(world.engine) == pytest.approx(1.0)  # charged once (by the crash or the retry), refunded once
    assert _ledger(world) == [("airem:dead:charge", "charge", 5), ("airem:dead:refund", "refund", 5)]
    assert "remediation_claim" not in _doc(world, oid)  # the refund cleared the claim: no 600 s block
    world.calls["mode"] = "ok"
    again = _post_all([oid])[0]
    assert again.status_code == 200 and again.json()["status"] == "completed"
    assert _balance(world.engine) == pytest.approx(1.0 - COST)


def test_refunds_are_once_and_only_for_committed_charges(world):
    from backend.utilities.ai import paid_remediation as PR

    assert PR.refund(1, "never-charged") is False and _balance(world.engine) == pytest.approx(1.0)
    assert PR.charge(1, "d1") is True and PR.charge(1, "d1") is False  # a debit is charged once
    assert _balance(world.engine) == pytest.approx(1.0 - COST)
    assert PR.refund(1, "d1") is True and PR.refund(1, "d1") is False  # and refunded once
    assert _balance(world.engine) == pytest.approx(1.0)


def test_a_refund_whose_bookkeeping_raises_is_never_repeated(world, monkeypatch):
    """The refund commits, then something after it raises: the credits go back once, and a repeat is a no-op."""
    from backend.utilities.ai import paid_remediation as PR

    world.calls["delay"] = 0
    world.calls["mode"] = "failed"
    real = PR.refund

    def refund_then_raise(team_id, debit):
        real(team_id, debit)
        raise RuntimeError("read-back failed after the commit")

    monkeypatch.setattr(PR, "refund", refund_then_raise)
    r = _post_all([world.ids[3]])[0]
    assert r.status_code == 500
    assert _balance(world.engine) == pytest.approx(1.0)  # 1.0 - 0.05 + 0.05, not + 0.10
    assert "remediation_claim" not in _doc(world, world.ids[3])
    debit = next(k for k, kind, _ in _ledger(world) if kind == "charge").split(":")[1]
    assert real(1, debit) is False and _balance(world.engine) == pytest.approx(1.0)


@pytest.mark.parametrize("after_commit", [False, True])
def test_a_charge_that_raises_releases_the_claim_only_when_nothing_committed(world, monkeypatch, after_commit):
    """Review 5909721853 minor 2: a transient charge error that provably did not commit frees the finding at once
    (no 409 for 600 s); one that raised after its commit carries on as charged."""
    from backend.utilities.ai import paid_remediation as PR

    world.calls["delay"] = 0
    real = PR.charge
    state = {"n": 0}

    def flaky(team_id, debit):
        state["n"] += 1
        if state["n"] == 1:
            if after_commit:
                real(team_id, debit)
            raise RuntimeError("database connection reset")
        return real(team_id, debit)

    monkeypatch.setattr(PR, "charge", flaky)
    oid = world.ids[5]
    first = _post_all([oid])[0]
    if after_commit:
        assert first.status_code == 200 and first.json()["status"] == "completed"
        assert _balance(world.engine) == pytest.approx(1.0 - COST)
        return
    assert first.status_code == 500 and _balance(world.engine) == pytest.approx(1.0)
    assert "remediation_claim" not in _doc(world, oid)
    second = _post_all([oid])[0]  # straight away, not after the claim's lifetime
    assert second.status_code == 200 and second.json()["status"] == "completed"
    assert _balance(world.engine) == pytest.approx(1.0 - COST) and len(_ledger(world)) == 1


def test_a_takeover_never_overwrites_the_debit_of_a_holder_that_resumes(world):
    """Review 5909721853 major (its repro /tmp/rev382/race.py as a test): B reads A's stale claim while it is
    "claimed"; A then resumes, charges and moves on; B's compare-and-set must miss, so the finding is charged once and
    A can still store under its debit."""
    import asyncio

    from backend.utilities.ai import paid_remediation as PR

    oid = world.ids[6]
    _claim(world, oid, token="A", debit="A", state="claimed", at=_stale())
    coll = world.findings
    real_find = coll.find_one

    def read_then_a_resumes(flt):
        doc = real_find(flt)
        claim = doc["remediation_claim"]
        PR.charge(1, "A")  # A (stalled after its claim) resumes: charges its debit, records it, refreshes its claim
        assert coll.update_one({"_id": oid, "remediation_claim.token": "A"},
                               {"$set": {"remediation_claim": {**claim, "state": "charged", "at": time.time()}}}
                               ).modified_count
        coll.find_one = real_find
        return doc

    coll.find_one = read_then_a_resumes
    with pytest.raises(PR.RemediationBusy):
        asyncio.run(PR.remediate(coll, finding_id=oid, scan_id=7, team_id=1, finding_data={}, scan_type="sast",
                                 generate=lambda d, s: {"status": "completed", "fix": {"by": "B"}}))
    assert coll.docs[oid]["remediation_claim"]["token"] == "A"  # A's claim, with A's debit, untouched
    assert coll.update_one({"_id": oid, "remediation_claim.debit": "A", "remediation.status": {"$ne": "completed"}},
                           {"$set": {"remediation": {"status": "completed", "fix": {"by": "A"}}},
                            "$unset": {"remediation_claim": ""}}).modified_count == 1  # A can still store
    assert _balance(world.engine) == pytest.approx(1.0 - COST)
    assert _ledger(world) == [("airem:A:charge", "charge", 5)]


def test_a_legacy_claim_without_a_debit_is_taken_over_and_charged_once(world):
    world.calls["delay"] = 0
    oid = world.ids[7]
    _claim(world, oid, token="old", at=_stale())  # a claim written before debit ids existed
    assert _post_all([oid])[0].status_code == 200
    assert _balance(world.engine) == pytest.approx(1.0 - COST)


def _slow_then_fast(world, monkeypatch, second_mode="ok", a_first=False):
    """Request A generates slowly; after its claim's lifetime request B takes the finding over and finishes first
    (or, with ``a_first``, A finishes while B is still generating)."""
    from backend.utilities.ai import paid_remediation as PR
    from backend.utilities.ai import remediation as remediation_mod

    monkeypatch.setattr(PR, "CLAIM_TTL_S", 0.2)
    a_in, release, b_in, b_release = threading.Event(), threading.Event(), threading.Event(), threading.Event()
    n = {"calls": 0}

    def generate(finding_data, scan_type):
        n["calls"] += 1
        if n["calls"] == 1:
            a_in.set()
            release.wait(10)
            return {"generated_at": "a", "status": "completed", "fix": {"by": "A"}, "exploit_payload": {}, "diff": ""}
        if a_first:
            b_in.set()
            b_release.wait(10)
        if second_mode == "failed":
            return {"generated_at": "b", "status": "failed", "error": "model said no"}
        return {"generated_at": "b", "status": "completed", "fix": {"by": "B"}, "exploit_payload": {}, "diff": ""}

    monkeypatch.setattr(remediation_mod, "generate_remediation", generate)
    oid = world.ids[4]
    results = {}
    a = threading.Thread(target=lambda: results.setdefault("a", _post_all([oid])[0]))
    a.start()
    assert a_in.wait(10)
    time.sleep(0.3)  # A's claim is now stale
    if a_first:
        bt = threading.Thread(target=lambda: results.setdefault("b", _post_all([oid])[0]))
        bt.start()
        assert b_in.wait(10)
        release.set()
        a.join(20)
        b_release.set()
        bt.join(20)
    else:
        results["b"] = _post_all([oid])[0]
        release.set()
        a.join(20)
    return oid, results["a"], results["b"], n


def test_a_takeover_never_charges_twice(world, monkeypatch):
    oid, a, b, n = _slow_then_fast(world, monkeypatch)
    assert n["calls"] == 2
    assert b.status_code == 200 and b.json()["fix"] == {"by": "B"}  # B used A's charge (no debit of its own)
    assert a.status_code == 200 and a.json()["fix"] == {"by": "B"}  # A's result is not stored: the stored one
    assert _balance(world.engine) == pytest.approx(1.0 - COST)  # one charge in all
    assert _doc(world, oid)["remediation"]["fix"] == {"by": "B"} and "remediation_claim" not in _doc(world, oid)


def test_a_takeover_that_fails_refunds_once_and_the_slow_result_is_not_given_away(world, monkeypatch):
    oid, a, b, n = _slow_then_fast(world, monkeypatch, second_mode="failed")
    assert b.status_code == 200 and b.json()["status"] == "failed"
    assert a.status_code == 409  # its charge was refunded by the takeover: nothing paid, nothing stored
    assert _balance(world.engine) == pytest.approx(1.0)  # A's debit, refunded once
    assert (_doc(world, oid).get("remediation") or {}).get("status") == "failed"
    assert "remediation_claim" not in _doc(world, oid)


def test_a_takeover_where_the_slow_request_finishes_first_never_charges_twice(world, monkeypatch):
    """A's late store used to keep A's charge while B (which had debited again) stored over it: two charges."""
    oid, a, b, n = _slow_then_fast(world, monkeypatch, a_first=True)
    assert n["calls"] == 2 and a.status_code == 200 and b.status_code == 200
    assert a.json()["fix"] == {"by": "A"} and b.json()["fix"] == {"by": "A"}  # B serves what was stored
    assert _balance(world.engine) == pytest.approx(1.0 - COST)  # one charge in all
    assert _doc(world, oid)["remediation"]["fix"] == {"by": "A"} and "remediation_claim" not in _doc(world, oid)
