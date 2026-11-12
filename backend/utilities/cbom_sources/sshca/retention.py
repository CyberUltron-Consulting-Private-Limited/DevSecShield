"""Retention of the SSH CA audit (contract open question 8: certificates are kept 13 months; arch review of PR #65).

``purge`` deletes ``cbomsshcertissued`` rows issued more than ``RETENTION`` ago, team by team (the teams that have a
CA), in batches of ``batch`` rows through ``ix_cbomsshcertissued_team_issued``, each batch its own transaction so no
long lock is held; and trust-fetch rows not seen for 30 days.  ``purge_due`` runs it at most once an hour per process;
the CBOM scheduler tick calls it (``backend/workers/cbom_scheduler.py``).

One replica at a time (architecture re-review 5874161772): on PostgreSQL a run first takes the session-level advisory
lock ``LOCK_KEY`` with ``pg_try_advisory_lock`` on a connection of its own (committed at once, so that connection
waits idle, not in a transaction); a replica that does not get it skips the run (``{"skipped": True}``), and the
lock is released when the run ends (or with its connection).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import threading
import time

from sqlalchemy import delete, func
from sqlmodel import Session, select

from backend.utilities.cbom_sources.common import log
from backend.utilities.cbom_sources.sshca import trust as T
from backend.utilities.cbom_sources.sshca.models import CbomSshCa, CbomSshCertIssued

RETENTION = _dt.timedelta(days=396)  # 13 months
BATCH = 5_000
MAX_BATCHES = 200  # per run: at most 1M rows, the rest next hour
EVERY_S = 3600.0
# pg advisory lock key (bigint): fixed, derived from a name so no other feature picks the same number by chance
LOCK_KEY = int.from_bytes(hashlib.sha256(b"devsecshield.cbom.sshca.retention").digest()[:8], "big", signed=True)
_last = 0.0
_lock = threading.Lock()


def purge(engine, now: _dt.datetime, *, batch: int = BATCH, max_batches: int = MAX_BATCHES) -> dict[str, int]:
    if engine.dialect.name != "postgresql":
        return _purge(engine, now, batch, max_batches)  # SQLite (tests): one process
    with engine.connect() as guard:
        got = bool(guard.execute(select(func.pg_try_advisory_lock(LOCK_KEY))).scalar())
        guard.commit()  # the lock is the session's: it outlives the transaction
        if not got:
            log("ssh ca audit retention skipped: another replica is running it")
            return {"certificates": 0, "batches": 0, "fetchers": 0, "skipped": True}
        try:
            return _purge(engine, now, batch, max_batches)
        finally:
            guard.execute(select(func.pg_advisory_unlock(LOCK_KEY)))
            guard.commit()


def _purge(engine, now: _dt.datetime, batch: int, max_batches: int) -> dict[str, int]:
    cutoff = now - RETENTION
    out = {"certificates": 0, "batches": 0, "fetchers": 0}
    with Session(engine) as session:
        teams = sorted(set(session.exec(select(CbomSshCa.team_id)).all()))
    for team_id in teams:
        while out["batches"] < max_batches:
            with Session(engine) as session:
                ids = session.exec(select(CbomSshCertIssued.id).where(
                    CbomSshCertIssued.team_id == team_id, CbomSshCertIssued.issued_at < cutoff)
                    .order_by(CbomSshCertIssued.issued_at).limit(batch)).all()
                if not ids:
                    break
                session.exec(delete(CbomSshCertIssued).where(CbomSshCertIssued.id.in_(ids)))  # type: ignore[call-overload,union-attr]
                session.commit()
            out["certificates"] += len(ids)
            out["batches"] += 1
            if len(ids) < batch:
                break
    with Session(engine) as session:
        out["fetchers"] = T.purge_fetchers(session, now)
        session.commit()
    if out["certificates"] or out["fetchers"]:
        log("ssh ca audit retention", deleted=out["certificates"], batches=out["batches"], fetchers=out["fetchers"])
    return out


def purge_due(engine, now: _dt.datetime) -> dict[str, int] | None:
    """``purge`` when this process has not run it in the last hour, else None."""
    global _last
    with _lock:
        if time.monotonic() - _last < EVERY_S and _last:
            return None
        _last = time.monotonic()
    return purge(engine, now)
