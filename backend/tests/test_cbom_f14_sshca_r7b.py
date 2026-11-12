"""F1.4 review round 7, second pass (PR #65 architecture re-review 5874161772 on e913f46).

* [major] keywrap.py: during a KMS outage the single flight became a queue (each waiter called KMS again after the
  previous one failed) and every waiting request held its pooled connection idle in a transaction.
* [nit] cbom_sshca_trust.py: a 304 still did all the database work (token lookups, the CA rows, the fetch row).
* [nit] retention.py: every cloud-worker replica purged at once.
Written before the fix and run red on e913f46 (log in $R6/f1-4/r7b/), green after.  PostgreSQL tests run when
``CBOM_TEST_PG_URL`` is set, as in CI.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import threading
import time

import pytest
from sqlalchemy import create_engine, event, text
from sqlmodel import Session, SQLModel, select

import test_cbom_f14_sshca as F
from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode, Team, TeamMembership, User
from backend.routers import cbom_node_sshca
from backend.utilities.cbom_sources import node_auth as NA
from backend.utilities.cbom_sources.sshca import certs as C
from backend.utilities.cbom_sources.sshca import keywrap as KW
from backend.utilities.cbom_sources.sshca import registry as R
from backend.utilities.cbom_sources.sshca.models import CbomSshCa, CbomSshCertIssued

world, api, ca_world = F.world, F.api, F.ca_world
BASE = F.BASE
TRUST = "/cbom/ssh-ca-trust"
ARN = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"
PG = os.environ.get("CBOM_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")


class OutageKms:
    """A KMS that wraps normally, and while ``down`` hangs ``hang`` seconds and then throttles every Decrypt."""

    def __init__(self, hang: float = 0.5):
        self.hang, self.down, self.calls = hang, False, 0
        self.ended: list[float] = []  # monotonic time each failed Decrypt returned
        self.during = None  # called inside a healthy Decrypt (something that happens while KMS answers)
        self.lock = threading.Lock()
        self.keys: dict[bytes, bytes] = {}

    def generate_data_key(self, KeyId, KeySpec, EncryptionContext):  # noqa: N803 - boto3's names
        plain, blob = os.urandom(32), os.urandom(16)
        self.keys[blob] = plain
        return {"Plaintext": plain, "CiphertextBlob": blob, "KeyId": KeyId}

    def decrypt(self, CiphertextBlob, KeyId, EncryptionContext):  # noqa: N803
        from botocore.exceptions import ClientError

        with self.lock:
            self.calls += 1
        if self.down:
            time.sleep(self.hang)
            with self.lock:
                self.ended.append(time.monotonic())
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}, "Decrypt")
        if self.during is not None:
            self.during()
        return {"Plaintext": self.keys[CiphertextBlob], "KeyId": KeyId}


@pytest.fixture(autouse=True)
def _fresh():
    from backend.utilities.cbom_sources.sshca import trust

    KW.forget()  # unwrapped keys and remembered failures
    trust.reset()
    yield
    KW.set_kms_client_factory(None)
    KW.forget()
    trust.reset()


def _kms_row(api, engine, monkeypatch, kms: OutageKms) -> CbomSshCa:
    monkeypatch.setenv(KW.KMS_ENV, ARN)
    KW.set_kms_client_factory(lambda region: kms)
    ca = F.create_ca(api, name="kms")
    with Session(engine) as session:
        row = session.get(CbomSshCa, ca["id"])
        session.expunge(row)
        return row


# ============================================================================ [major] the KMS outage queue
def test_a_failed_unwrap_is_shared_by_its_waiters_and_remembered(api, ca_world, monkeypatch):
    """8 cold callers during an outage: 1 Decrypt, every caller gets the same transient error at once, and the next
    caller within the negative-cache window fails fast without calling KMS."""
    engine, _ = ca_world
    kms = OutageKms(hang=0.4)
    row = _kms_row(api, engine, monkeypatch, kms)
    KW.forget()
    kms.down, kms.calls = True, 0
    outcomes: list[tuple[str, float]] = []
    lock = threading.Lock()

    def one():
        t = time.monotonic()
        try:
            KW.cached_private_key(row.id, 1, row.fingerprint, row.private_key_encrypted)
            got = "ok"
        except KW.WrapError as exc:
            got = "transient" if exc.transient else "error"
        with lock:
            outcomes.append((got, time.monotonic() - t))

    threads = [threading.Thread(target=one) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert kms.calls == 1, kms.calls
    assert [o for o, _t in outcomes] == ["transient"] * 8
    assert max(t for _o, t in outcomes) < 0.4 + 0.5, outcomes  # about one call's time, not 8 calls in a row
    t = time.monotonic()
    with pytest.raises(KW.WrapError) as err:  # inside the window: no call, at once
        KW.cached_private_key(row.id, 1, row.fingerprint, row.private_key_encrypted)
    assert err.value.transient and kms.calls == 1 and time.monotonic() - t < 0.1
    kms.down = False  # KMS is back; after the window the next caller unwraps
    real = time.monotonic
    monkeypatch.setattr(KW.time, "monotonic", lambda: real() + KW.NEGATIVE_CACHE_S + 1)
    assert KW.cached_private_key(row.id, 1, row.fingerprint, row.private_key_encrypted) is not None
    assert kms.calls == 2


def test_while_kms_is_asked_again_the_other_callers_do_not_wait(api, ca_world, monkeypatch):
    """After the 10 s window one caller asks KMS again; a failing call can take 16 s, so the others get the last error
    at once instead of queueing behind it (only one thread per CA and worker waits on KMS in an outage)."""
    engine, _ = ca_world
    kms = OutageKms(hang=0.5)
    row = _kms_row(api, engine, monkeypatch, kms)
    KW.forget()
    kms.down, kms.calls = True, 0
    with pytest.raises(KW.WrapError):
        KW.cached_private_key(row.id, 1, row.fingerprint, row.private_key_encrypted)
    real = time.monotonic
    monkeypatch.setattr(KW.time, "monotonic", lambda: real() + KW.NEGATIVE_CACHE_S + 1)  # the failure is not fresh
    asking = threading.Event()
    decrypt = kms.decrypt

    def slow_decrypt(**kw):
        asking.set()
        return decrypt(**kw)

    kms.decrypt = slow_decrypt
    retry = threading.Thread(target=lambda: pytest.raises(KW.WrapError, KW.cached_private_key, row.id, 1,
                                                          row.fingerprint, row.private_key_encrypted))
    retry.start()
    assert asking.wait(5)
    waits = []
    for _ in range(5):
        t = time.monotonic()
        with pytest.raises(KW.WrapError) as err:
            KW.cached_private_key(row.id, 1, row.fingerprint, row.private_key_encrypted)
        waits.append(time.monotonic() - t)
        assert err.value.transient
    retry.join()
    assert kms.calls == 2, kms.calls  # the first call and the one retry, nothing for the 5 others
    assert max(waits) < 0.1, waits


def _pg_kms_world(nodes: int, kms: OutageKms):
    """PostgreSQL: one team, one admin, one KMS-wrapped CA and ``nodes`` enrolled nodes, each with a claimed job of
    its own ssh_ca source.  Returns (engine, [{token, job, lease}], ca row)."""
    engine = create_engine(PG, pool_size=nodes + 4, max_overflow=4)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    now = F._utcnow()
    out = []
    with Session(engine) as s:
        s.add(Team(id=1, name="T", credit_balance=10.0))
        s.commit()
        user = User(email="a@t.test", password="x", first_name="a", last_name="b", profile_photo=None,
                    default_team_id=1)
        s.add(user)
        s.commit()
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))

        class Body:
            name, provider, key_alg, key_wrap, kms_key_ref, kms_key = "kms", "builtin", "ed25519", None, None, None
            vault_config, secrets, default_ttl_s = None, None, 300

        ca = R.create_ca(s, 1, user.id, Body(), now)
        s.commit()
        for i in range(nodes):
            token = "zsn_" + secrets.token_hex(20)  # generated at run time
            node = CbomScanNode(team_id=1, owner_user_id=user.id, name=f"n{i}", node_token_hash=NA.sha256_hex(token)
                                if hasattr(NA, "sha256_hex") else __import__("hashlib").sha256(token.encode()).hexdigest(),
                                ssh_public_key=F.node_key_line()[1], source_ips=["10.0.0.5"], enrolled_at=now)
            s.add(node)
            s.flush()
            src = CbomCollectionSource(team_id=1, owner_user_id=user.id, updated_by_user_id=user.id,
                                       kind="linux_servers", name=f"s{i}", name_lower=f"s{i}", node_id=node.id,
                                       config={"targets": ["10.20.0.5"], "credential_type": "ssh_ca", "ssh_ca_id": ca.id,
                                               "ssh_principals": ["zs-1-prod"]})
            s.add(src)
            s.flush()
            lease = f"lease-{i:08d}"
            job = CbomCollectionJob(team_id=1, source_id=src.id, node_id=node.id, kind="collect", status="claimed",
                                    lease_id=lease, claimed_at=now)
            s.add(job)
            s.commit()
            out.append({"token": token, "job": job.id, "lease": lease})
        s.refresh(ca)
        s.expunge(ca)
    return engine, out, ca


@needs_pg
def test_pg_a_kms_outage_neither_queues_nor_holds_pooled_connections(monkeypatch):
    """8 cold certificate requests of one CA while KMS hangs (0.5 s) then throttles: 1 Decrypt, every request answered
    (503 + Retry-After) within about one call's time, and no request's session in a transaction while it waits for
    the CA key (recorded per thread when the key lookup starts: re-review 5877293709 r7b:239).  The pg_stat_activity
    sample is printed as a second view only: on a busy box a request's own reads can sit idle for 300 ms too."""
    from fastapi import HTTPException

    monkeypatch.setenv("CBOM_SSH_CA", "1")
    monkeypatch.setenv(KW.KMS_ENV, ARN)
    kms = OutageKms(hang=0.5)
    KW.set_kms_client_factory(lambda region: kms)
    engine, nodes, _ca = _pg_kms_world(8, kms)
    monkeypatch.setattr(cbom_node_sshca, "get_db", lambda: engine)
    KW.forget()
    kms.down, kms.calls = True, 0
    idle: list[int] = []
    stop = threading.Event()

    def sample():
        with engine.connect() as c:
            while not stop.is_set():
                # a connection idle in a transaction for longer than a request's own reads take: one waiting on KMS
                # (between two statements of a request's reads a connection is idle in a transaction for a moment)
                idle.append(int(c.execute(text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = "
                    "'idle in transaction' AND clock_timestamp() - state_change > interval '300 milliseconds'")).scalar()))
                c.commit()
                time.sleep(0.02)

    results: list[tuple[int, str | None, float]] = []
    finished: list[float] = []
    in_unwrap: list[float] = []  # seconds each request spent getting the CA key (waiting for KMS or for the flight)
    in_tx: list[bool] = []  # was the request's own session in a transaction when it started waiting for the key
    sessions: dict[int, Session] = {}
    lock = threading.Lock()
    real_unwrap = KW.cached_private_key

    class Recording(Session):  # the route's session, per thread
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            sessions[threading.get_ident()] = self

    def timed_unwrap(*args, **kwargs):
        with lock:
            in_tx.append(sessions[threading.get_ident()].in_transaction())
        t = time.monotonic()
        try:
            return real_unwrap(*args, **kwargs)
        finally:
            with lock:
                in_unwrap.append(time.monotonic() - t)

    monkeypatch.setattr(KW, "cached_private_key", timed_unwrap)
    monkeypatch.setattr(cbom_node_sshca, "Session", Recording)

    def one(n: dict):
        path = f"/cbom/node/jobs/{n['job']}/ssh-cert"
        t = time.monotonic()
        try:
            cbom_node_sshca._issue(n["token"], n["job"], NA.NodeRequest(method="POST", path=path),
                                   json.dumps({"lease_id": n["lease"]}).encode())
            status, retry = 200, None
        except HTTPException as exc:
            status, retry = exc.status_code, (exc.headers or {}).get("Retry-After")
        with lock:
            results.append((status, retry, time.monotonic() - t))
            finished.append(time.monotonic())

    sampler = threading.Thread(target=sample)
    sampler.start()
    threads = [threading.Thread(target=one, args=(n,)) for n in nodes]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    stop.set()
    sampler.join()
    engine.dispose()
    # no queue: no request waits for the CA key as long as two KMS calls (a queue of waiters each calling KMS again
    # adds a whole call per waiter: 8 requests, up to 8 calls).  Measured around the key lookup, so the box's load
    # during the requests' own reads does not count; when the last answer came is printed, not asserted (load).
    after_call = max(finished) - min(kms.ended) if kms.ended else float("inf")
    print("kms outage:", {"decrypt_calls": kms.calls, "statuses": sorted(st for st, _r, _t in results),
                          "seconds": sorted(round(t, 2) for _s, _r, t in results),
                          "key_wait_s": sorted(round(t, 2) for t in in_unwrap),
                          "last_answer_after_first_call_s": round(after_call, 2), "idle_in_tx_max": max(idle or [0]),
                          "session_in_transaction_at_key_wait": in_tx})
    assert kms.calls == 1, kms.calls
    assert [s for s, _r, _t in results] == [503] * 8 and all(r for _s, r, _t in results), results
    assert len(in_unwrap) == 8 and max(in_unwrap) < 2 * kms.hang, in_unwrap
    assert in_tx == [False] * 8, in_tx


def _node_call(n: dict) -> int:
    from fastapi import HTTPException

    path = f"/cbom/node/jobs/{n['job']}/ssh-cert"
    try:
        cbom_node_sshca._issue(n["token"], n["job"], NA.NodeRequest(method="POST", path=path),
                               json.dumps({"lease_id": n["lease"]}).encode())
        return 200
    except HTTPException as exc:
        return exc.status_code


@needs_pg
def test_pg_a_lease_lost_while_kms_answers_gets_no_certificate(monkeypatch):
    """The reads are committed before KMS is called, so the lease is checked again once KMS answered: a job whose
    lease went meanwhile gets 409 and nothing is recorded; a cold key with the lease kept gets its certificate."""
    monkeypatch.setenv("CBOM_SSH_CA", "1")
    monkeypatch.setenv(KW.KMS_ENV, ARN)
    kms = OutageKms()
    KW.set_kms_client_factory(lambda region: kms)
    engine, nodes, _ca = _pg_kms_world(2, kms)
    monkeypatch.setattr(cbom_node_sshca, "get_db", lambda: engine)
    KW.forget()

    def lose_lease():
        with Session(engine) as s:
            job = s.get(CbomCollectionJob, nodes[0]["job"])
            job.lease_id = "another-lease-0"  # re-leased elsewhere while KMS answered
            s.add(job)
            s.commit()

    kms.during = lose_lease
    assert _node_call(nodes[0]) == 409
    kms.during = None
    KW.forget()  # cold again: the second node's request also calls KMS
    assert _node_call(nodes[1]) == 200
    with Session(engine) as s:
        jobs = [row.job_id for row in s.exec(select(CbomSshCertIssued)).all()]
    engine.dispose()
    assert jobs == [nodes[1]["job"]], jobs
    assert kms.calls == 2


def test_vault_signs_with_no_transaction_open_and_the_route_still_records_the_certificate(api, ca_world, monkeypatch):
    """Vault answers over the network too: the route's reads are committed before it is called (same rule as KMS)."""
    from backend.utilities.cbom_sources.sshca import vault as V
    from test_cbom_f14_sshca_r7 import _vault_token

    engine, _ = ca_world
    fake = F.FakeVault()
    sessions: list[Session] = []

    class Recording(Session):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            sessions.append(self)

    open_during_sign: list[bool] = []

    def call(cfg, method, path, **kw):
        if "/sign/" in path:
            open_during_sign.append(any(s.in_transaction() for s in sessions))
        return fake(cfg, method, path, **kw)

    monkeypatch.setattr(V, "call", call)
    monkeypatch.setattr(cbom_node_sshca, "Session", Recording)
    ca = api("POST", F.BASE, json={"name": "vault", "provider": "vault",
                                   "vault_config": {"addr": "https://vault.bank.example:8200", "role": "zs-cbom"},
                                   "secrets": {"token": _vault_token()}}).json()["ca"]
    node_id, token, _ = F.enroll(api)
    F.ssh_ca_source(api, node_id, ca["id"])
    p = F.claim(api, token)
    assert F.cert_route(api, token, p["job"]["id"], p["job"]["lease_id"]).status_code == 200
    assert open_during_sign == [False], open_during_sign
    with Session(engine) as s:
        assert len(s.exec(select(CbomSshCertIssued)).all()) == 1


# ============================================================================ re-review 5877293709 (8f0bbaf)
def test_callers_at_the_onset_of_an_outage_wait_at_most_flight_wait_s(api, ca_world, monkeypatch):
    """keywrap.py:315: before any failure is known, a caller waits for another thread's KMS call at most
    FLIGHT_WAIT_S, then gets a transient error (503 + Retry-After at the route); still one Decrypt."""
    engine, _ = ca_world
    kms = OutageKms(hang=1.5)
    row = _kms_row(api, engine, monkeypatch, kms)
    monkeypatch.setattr(KW, "FLIGHT_WAIT_S", 0.4, raising=False)
    KW.forget()
    kms.down, kms.calls = True, 0
    asking = threading.Event()
    decrypt = kms.decrypt

    def slow_decrypt(**kw):
        asking.set()
        return decrypt(**kw)

    kms.decrypt = slow_decrypt
    first = threading.Thread(target=lambda: pytest.raises(KW.WrapError, KW.cached_private_key, row.id, 1,
                                                          row.fingerprint, row.private_key_encrypted))
    first.start()
    assert asking.wait(5)
    waits: list[float] = []
    errors: list[tuple[bool, str]] = []
    lock = threading.Lock()

    def one():
        t = time.monotonic()
        try:
            KW.cached_private_key(row.id, 1, row.fingerprint, row.private_key_encrypted)
        except KW.WrapError as exc:
            with lock:
                errors.append((exc.transient, exc.code))
        with lock:
            waits.append(time.monotonic() - t)

    threads = [threading.Thread(target=one) for _ in range(6)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    first.join()
    assert kms.calls == 1, kms.calls
    assert errors == [(True, "kms_unavailable")] * 6, errors
    assert max(waits) < 0.4 + 0.2, waits


def _revoke_this_runs_certificate_while_kms_answers(engine, kms, cert_id):
    def revoke_it():
        kms.during = None
        with Session(engine) as ss:
            R.revoke_cert(ss, 1, cert_id, 1, "an admin revoked this run's certificate", F._utcnow())
            ss.commit()

    kms.during = revoke_it


def test_a_certificate_of_this_run_revoked_while_kms_answers_stops_the_job(api, ca_world, monkeypatch):
    """cbom_node_sshca.py:115: the check after KMS answered covers the third stop reason too (a certificate of this
    run revoked): 409, and the new certificate is not recorded."""
    engine, _ = ca_world
    kms = OutageKms()
    monkeypatch.setenv(KW.KMS_ENV, ARN)
    KW.set_kms_client_factory(lambda region: kms)
    s = F.setup_job(api)
    assert F.cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    with Session(engine) as ss:  # the job's certificate is inside its refresh window
        row = ss.exec(select(CbomSshCertIssued)).one()
        row.valid_before = F._utcnow() + dt.timedelta(seconds=100)
        ss.add(row)
        ss.commit()
        cert_id = row.id
    KW.forget()  # cold on this worker: the renewal calls KMS (release, then the checks again)
    _revoke_this_runs_certificate_while_kms_answers(engine, kms, cert_id)
    r = F.cert_route(api, s["token"], s["job_id"], s["lease"])
    with Session(engine) as ss:
        rows = [(x.serial, x.revoked_at is not None) for x in ss.exec(select(CbomSshCertIssued)).all()]
    assert r.status_code == 409 and "revoked its SSH certificate" in r.json()["detail"], r.json()
    assert rows == [(1, True)], rows


@needs_pg
def test_pg_a_certificate_of_this_run_revoked_while_kms_answers_stops_the_job(monkeypatch):
    monkeypatch.setenv("CBOM_SSH_CA", "1")
    monkeypatch.setenv(KW.KMS_ENV, ARN)
    kms = OutageKms()
    KW.set_kms_client_factory(lambda region: kms)
    engine, nodes, _ca = _pg_kms_world(1, kms)
    monkeypatch.setattr(cbom_node_sshca, "get_db", lambda: engine)
    KW.forget()
    assert _node_call(nodes[0]) == 200
    with Session(engine) as ss:
        row = ss.exec(select(CbomSshCertIssued)).one()
        row.valid_before = F._utcnow() + dt.timedelta(seconds=100)
        ss.add(row)
        ss.commit()
        cert_id = row.id
    KW.forget()
    _revoke_this_runs_certificate_while_kms_answers(engine, kms, cert_id)
    status = _node_call(nodes[0])
    with Session(engine) as ss:
        rows = sorted((x.serial, x.revoked_at is not None) for x in ss.exec(select(CbomSshCertIssued)).all())
    engine.dispose()
    assert status == 409 and rows == [(1, True)], (status, rows)


def test_a_remembered_access_denied_stays_a_refusal_not_a_retry(api, ca_world, monkeypatch):
    """RV1: the remembered failure keeps its kind: AccessDenied is not transient (400, no Retry-After) for the next
    caller either."""
    from botocore.exceptions import ClientError

    engine, _ = ca_world
    kms = OutageKms()
    row = _kms_row(api, engine, monkeypatch, kms)
    KW.forget()

    def denied(**kw):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "Decrypt")

    kms.decrypt = denied
    got = []
    for _ in range(2):  # the first caller, then one answered from the remembered failure
        with pytest.raises(KW.WrapError) as err:
            KW.cached_private_key(row.id, 1, row.fingerprint, row.private_key_encrypted)
        got.append((err.value.transient, err.value.code))
    assert got[0] == got[1] and got[0][0] is False, got


def _vault_job(api, monkeypatch, during=None, node="dc-1"):
    """A Vault CA, a node, an ssh_ca source and a claimed job; ``during()`` runs while Vault signs."""
    from backend.utilities.cbom_sources.sshca import vault as V
    from test_cbom_f14_sshca_r7 import _vault_token

    fake = F.FakeVault()

    def call(cfg, method, path, **kw):
        if "/sign/" in path and during is not None:
            during()
        return fake(cfg, method, path, **kw)

    monkeypatch.setattr(V, "call", call)
    ca = api("POST", F.BASE, json={"name": "vault", "provider": "vault",
                                   "vault_config": {"addr": "https://vault.bank.example:8200", "role": "zs-cbom"},
                                   "secrets": {"token": _vault_token()}}).json()["ca"]
    node_id, token, _ = F.enroll(api, name=node)
    F.ssh_ca_source(api, node_id, ca["id"], name=f"linux-ca-{node}")
    p = F.claim(api, token)
    return ca, token, p["job"]["id"], p["job"]["lease_id"], fake


def _cert_rows(engine) -> list:
    with Session(engine) as s:
        return s.exec(select(CbomSshCertIssued)).all()


def test_a_job_cancelled_while_vault_signs_gets_no_certificate(api, ca_world, monkeypatch):
    """RV3: the check after Vault answered applies _invalid_reason (cancelled, source changed): 409 "Stop this job"."""
    engine, _ = ca_world
    state: dict = {}

    def cancel():
        with Session(engine) as s:
            job = s.get(CbomCollectionJob, state["job"])
            job.cancel_requested_at = F._utcnow()
            job.cancel_reason = "Cancelled by an admin"
            s.add(job)
            s.commit()

    _ca, token, job_id, lease, _fake = _vault_job(api, monkeypatch, during=cancel)
    state["job"] = job_id
    r = F.cert_route(api, token, job_id, lease)
    assert r.status_code == 409 and r.json()["detail"].startswith("Stop this job"), r.json()
    assert _cert_rows(engine) == []


def test_a_lease_lost_while_vault_signs_leaves_one_refusal_audit_row(api, ca_world, monkeypatch):
    """RV4: the refusal after Vault answered is audited like every other one (AC 7)."""
    from backend.new_models import CbomCollectionAuditEvent

    engine, _ = ca_world
    state: dict = {}

    def lose():
        with Session(engine) as s:
            job = s.get(CbomCollectionJob, state["job"])
            job.lease_id = "another-lease-y"
            s.add(job)
            s.commit()

    _ca, token, job_id, lease, _fake = _vault_job(api, monkeypatch, during=lose)
    state["job"] = job_id
    assert F.cert_route(api, token, job_id, lease).status_code == 409
    with Session(engine) as s:
        rows = [e.changed_fields for e in s.exec(select(CbomCollectionAuditEvent)).all()
                if e.action == "sshca.cert.denied"]
    assert len(rows) == 1 and "reason:lease_lost" in rows[0], rows
    assert _cert_rows(engine) == []


def test_a_vault_ca_revoked_while_vault_signs_records_nothing(api, ca_world, monkeypatch):
    """RV11: the CA row is share-locked again after Vault answered (ca._Base docstring): a revoke committed while
    Vault signed stops the mint."""
    engine, _ = ca_world
    state: dict = {}

    def revoke():
        with Session(engine) as s:
            R.revoke(s, s.get(CbomSshCa, state["ca"]), 1, "revoked while Vault signs", F._utcnow())
            s.commit()

    ca, token, job_id, lease, _fake = _vault_job(api, monkeypatch, during=revoke)
    state["ca"] = ca["id"]
    r = F.cert_route(api, token, job_id, lease)
    assert r.status_code == 400 and "no longer active" in r.json()["detail"], r.json()
    assert _cert_rows(engine) == []


def test_two_retired_keys_leave_the_text_each_at_its_own_overlap_end(api, ca_world, monkeypatch):
    """RV5: the text is cached until the EARLIEST overlap end among its retired keys."""
    from backend.routers import cbom_sshca

    engine, _ = ca_world
    a = F.create_ca(api)
    n1 = api("POST", f"{F.BASE}/{a['id']}/rotate", json={}).json()["ca"]
    assert api("POST", f"{F.BASE}/{n1['id']}/promote", json={"force": True}).status_code == 200
    time.sleep(1.1)
    n2 = api("POST", f"{F.BASE}/{n1['id']}/rotate", json={}).json()["ca"]
    assert api("POST", f"{F.BASE}/{n2['id']}/promote", json={"force": True}).status_code == 200
    with Session(engine) as s:
        e1 = s.get(CbomSshCa, a["id"]).retired_at + R.OVERLAP
        e2 = s.get(CbomSshCa, n1["id"]).retired_at + R.OVERLAP
    assert e1 < e2
    monkeypatch.setattr(cbom_sshca, "utcnow", lambda: e1 - dt.timedelta(seconds=0.5))
    assert len(F._trusted(api)) == 3
    monkeypatch.setattr(cbom_sshca, "utcnow", lambda: e1 + dt.timedelta(seconds=0.5))
    assert len(F._trusted(api)) == 2
    monkeypatch.setattr(cbom_sshca, "utcnow", lambda: e2 + dt.timedelta(seconds=0.5))
    assert len(F._trusted(api)) == 1


def test_the_route_says_how_far_it_back_dated_the_certificate(api, ca_world, monkeypatch):
    """sshca.py:120 (node): the node's refusal names the clock tolerance the CA really gave.  Builtin: skew_s(TTL);
    Vault: its role's not_before_duration (FakeVault: 30 s), not TTL / 5."""
    from backend.utilities.cbom_sources.sshca import ca as CA

    s = F.setup_job(api)
    out = F.cert_route(api, s["token"], s["job_id"], s["lease"]).json()
    facts = C.read_cert(out["certificate"])
    assert out["backdated_s"] == CA.skew_s(300) == 60
    assert facts.valid_before - facts.valid_after == 300
    _ca, token, job_id, lease, fake = _vault_job(api, monkeypatch, node="dc-2")
    vout = F.cert_route(api, token, job_id, lease).json()
    assert abs(vout["backdated_s"] - fake.not_before) <= 2, vout["backdated_s"]


# ============================================================================ [nit] a 304 does no database work
def _count_statements(engine) -> list[str]:
    seen: list[str] = []

    @event.listens_for(engine, "before_cursor_execute")
    def _count(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
        seen.append(statement.split()[0].upper())

    return seen


def test_a_repeated_fetch_answers_304_with_one_query_and_the_token_is_cached(api, ca_world):
    engine, _ = ca_world
    F.create_ca(api)
    secret = api("POST", f"{BASE}/trust-tokens", json={"name": "fleet"}).json()["token"]
    headers = {"X-ZS-Trust-Token": secret, "X-ZS-Fetcher": "srv-01"}
    first = api("GET", TRUST + "/trusted-keys", None, headers=headers)
    krl = api("GET", TRUST + "/revoked", None, headers=headers)
    assert first.status_code == 200 and krl.status_code == 200
    seen = _count_statements(engine)
    again = api("GET", TRUST + "/trusted-keys", None, headers={**headers, "If-None-Match": first.headers["etag"]})
    assert again.status_code == 304
    tk_queries = list(seen)
    seen.clear()
    again = api("GET", TRUST + "/revoked", None, headers={**headers, "If-None-Match": krl.headers["etag"]})
    assert again.status_code == 304
    assert len(tk_queries) <= 1 and len(seen) <= 1, (tk_queries, seen)  # the generations, nothing else


def test_a_trust_token_revoked_here_is_refused_at_once_and_elsewhere_within_the_cache_time(api, ca_world, monkeypatch):
    engine, _ = ca_world
    F.create_ca(api)
    made = api("POST", f"{BASE}/trust-tokens", json={"name": "fleet"}).json()
    headers = {"X-ZS-Trust-Token": made["token"]}
    assert api("GET", TRUST + "/trusted-keys", None, headers=headers).status_code == 200
    with Session(engine) as session:  # another worker revoked it: this worker's cache does not know yet
        from backend.utilities.cbom_sources.sshca.models import CbomSshCaTrustToken

        row = session.get(CbomSshCaTrustToken, made["trust_token"]["id"])
        row.revoked_at = F._utcnow()
        session.add(row)
        session.commit()
    real = time.monotonic
    monkeypatch.setattr(KW.time, "monotonic", lambda: real() + 61)  # the per-worker token cache lives 60 s
    assert api("GET", TRUST + "/trusted-keys", None, headers=headers).status_code == 401
    other = api("POST", f"{BASE}/trust-tokens", json={"name": "second"}).json()
    h2 = {"X-ZS-Trust-Token": other["token"]}
    assert api("GET", TRUST + "/trusted-keys", None, headers=h2).status_code == 200
    assert api("POST", f"{BASE}/trust-tokens/{other['trust_token']['id']}/revoke", json={}).status_code == 200
    assert api("GET", TRUST + "/trusted-keys", None, headers=h2).status_code == 401  # this worker: at once


def test_a_stale_read_never_brings_a_revoked_token_back():
    """A request that read the token row just before a revoke committed caches its result after the revoke: the
    revoke wins (a revoke is final), so the token is not live again for the cache time."""
    from types import SimpleNamespace

    from backend.utilities.cbom_sources.sshca import trust as T

    secret = T.TOKEN_PREFIX + secrets.token_urlsafe(30)[:40]  # generated at run time
    live = T.TokenInfo(5, 1, False)
    assert T.token_for(secret, lambda digest: live) == live
    T.token_revoked(SimpleNamespace(token_hash=T.sha256_hex(secret), id=5, team_id=1))
    T._remember_token(T.sha256_hex(secret), live)  # the late write of the stale read
    assert T.token_for(secret, lambda digest: live) is None


# ============================================================================ [nit] one replica purges
@needs_pg
def test_pg_only_one_replica_runs_the_retention_purge(monkeypatch):
    from backend.utilities.cbom_sources.sshca import retention

    engine = create_engine(PG)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    lock_key = getattr(retention, "LOCK_KEY", None)
    assert lock_key is not None
    with engine.connect() as other:  # another replica is purging
        assert other.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": lock_key}).scalar() is True
        out = retention.purge(engine, F._utcnow())
        assert out.get("skipped") is True, out
        other.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": lock_key})
        other.commit()
    out = retention.purge(engine, F._utcnow())
    assert not out.get("skipped"), out
    engine.dispose()


@needs_pg
def test_pg_a_purge_whose_lock_connection_breaks_still_returns_and_frees_the_lock(monkeypatch):
    """Re-review 5877293709 (retention): the guard connection dies mid-run (PostgreSQL releases the lock with it).  The
    run's deletes committed, so the run returns its result instead of failing at the unlock, and the next run runs."""
    from backend.utilities.cbom_sources.sshca import retention

    engine = create_engine(PG)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    started, go = threading.Event(), threading.Event()
    real = retention._purge

    def slow_purge(*a, **k):
        started.set()
        go.wait(20)
        return real(*a, **k)

    monkeypatch.setattr(retention, "_purge", slow_purge)
    result: dict = {}

    def run():
        try:
            result["out"] = retention.purge(engine, F._utcnow())
        except Exception as exc:
            result["error"] = type(exc).__name__

    th = threading.Thread(target=run)
    th.start()
    assert started.wait(10)
    with engine.connect() as c:  # the lock's connection waits idle (not in a transaction) during the run; kill it
        pid, state = c.execute(text("SELECT l.pid, a.state FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
                                    "WHERE l.locktype = 'advisory' AND l.granted")).one()
        c.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})
        c.commit()
    assert state == "idle", state
    go.set()
    th.join(30)
    monkeypatch.setattr(retention, "_purge", real)
    again = retention.purge(engine, F._utcnow())
    engine.dispose()
    assert "error" not in result and not result["out"].get("skipped"), result
    assert not again.get("skipped"), again


@needs_pg
def test_pg_the_purge_releases_its_lock_so_the_next_run_is_not_skipped():
    """RV6: the session-level lock is released at the end of a run (the guard connection goes back to the pool, so a
    lock left on it would skip every later run on every replica)."""
    from backend.utilities.cbom_sources.sshca import retention

    engine, other = create_engine(PG), create_engine(PG)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    first = retention.purge(engine, F._utcnow())
    with other.connect() as c:
        held = c.execute(text("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted")).scalar()
    second = retention.purge(other, F._utcnow())  # another replica, an hour later
    again = retention.purge(engine, F._utcnow())  # the same replica, its pooled guard connection reused
    engine.dispose()
    other.dispose()
    assert held == 0 and not first.get("skipped") and not second.get("skipped") and not again.get("skipped")
