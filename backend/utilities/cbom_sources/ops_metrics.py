"""CB-31 (GAP-MATRIX X1, R4 OBS-8): the platform's operational metrics in the Prometheus text format (version 0.0.4),
served admin-only by ``GET /cbom/ops/metrics`` (``routers/cbom_ops.py``).

What the plan lists, and nothing per tenant (aggregates only: no team, source or node names or ids):

* queue depth per job kind: ``cbom_jobs{kind,status}`` (pending, claimed) and ``cbom_jobs_oldest_pending_age_seconds``;
* lease expiries: ``cbom_job_lease_expiries_total{outcome}`` (requeued for another attempt, or failed after the last);
* ingest rejects: ``cbom_ingest_rejected_assets_total`` (assets a batch carried that the server refused);
* node heartbeat age: ``cbom_nodes{state}``, ``cbom_node_heartbeat_age_seconds_bucket{le}`` (registered nodes whose
  last heartbeat is at most ``le`` seconds old, cumulative), ``cbom_node_heartbeat_age_seconds_max`` and
  ``cbom_nodes_never_heartbeat``;
* integration backlog: ``cbom_integration_deliveries{status}`` and ``cbom_integration_oldest_pending_age_seconds``.

Every gauge is one indexed GROUP BY or one aggregate row computed in SQL (a scrape with 10,000 nodes stays in tens
of milliseconds); the two counters are rows of ``cbomopscounter``, incremented by ``bump`` in the transaction of
the event they count, so every API and worker process adds to the same number.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any, Iterable

from sqlalchemy import case, func
from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomOpsCounter, CbomScanNode, IntegrationDelivery

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
LEASE_EXPIRED = {"pending": "job_lease_expired_requeued", "failure": "job_lease_expired_failed"}
INGEST_REJECTED = "ingest_rejected_assets"
HEARTBEAT_BUCKETS = (60, 120, 300, 900, 3600, 21600, 86400)
QUEUE_STATUSES = ("pending", "claimed")
NODE_STATES = ("online", "offline", "pending_registration", "registration_expired")
DELIVERY_STATUSES = ("pending", "dead")


def bump(session: Session, name: str, amount: int = 1, now: _dt.datetime | None = None) -> None:
    """Add ``amount`` to counter ``name`` in the caller's transaction (one upsert; no read)."""
    if amount <= 0:
        return
    now = now or _dt.datetime.utcnow()
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    table = CbomOpsCounter.__table__
    stmt = dialect_insert(table).values(name=name, value=amount, updated_at=now)
    stmt = stmt.on_conflict_do_update(index_elements=["name"],
                                      set_={"value": table.c.value + amount, "updated_at": now})
    session.exec(stmt)  # type: ignore[call-overload]


def _age(now: _dt.datetime, then: Any) -> float | None:
    if then is None:
        return None
    if isinstance(then, str):  # SQLite returns MIN() over a DateTime column as text
        then = _dt.datetime.fromisoformat(then)
    return max(0.0, round((now - then).total_seconds(), 3))


def _value(v: float | int) -> str:
    return str(int(v)) if float(v).is_integer() else repr(float(v))


class _Out:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def family(self, name: str, kind: str, text: str, samples: Iterable[tuple[dict[str, str], float]]) -> None:
        self.lines += [f"# HELP {name} {text}", f"# TYPE {name} {kind}"]
        for labels, value in samples:
            label = ",".join(f'{k}="{v}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{label}}} {_value(value)}" if label else f"{name} {_value(value)}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def render(session: Session, now: _dt.datetime) -> str:
    out = _Out()
    _jobs(session, now, out)
    _counters(session, out)
    _nodes(session, now, out)
    _integrations(session, now, out)
    return out.text()


def _jobs(session: Session, now: _dt.datetime, out: _Out) -> None:
    depth: dict[tuple[str, str], int] = {}
    oldest: dict[str, float] = {}
    for kind, status, count, first in session.exec(
            select(CbomCollectionJob.kind, CbomCollectionJob.status, func.count(), func.min(CbomCollectionJob.created_at))
            .where(CbomCollectionJob.status.in_(QUEUE_STATUSES))  # type: ignore[attr-defined]
            .group_by(CbomCollectionJob.kind, CbomCollectionJob.status)).all():
        depth[(str(kind), str(status))] = int(count)
        if status == "pending" and (age := _age(now, first)) is not None:
            oldest[str(kind)] = age
    kinds = sorted({k for k, _s in depth} | {"collect", "test_connection", "discovery"})
    out.family("cbom_jobs", "gauge", "Jobs waiting for a node or worker (pending) and running (claimed), per kind.",
               [({"kind": k, "status": s}, depth.get((k, s), 0)) for k in kinds for s in QUEUE_STATUSES])
    out.family("cbom_jobs_oldest_pending_age_seconds", "gauge",
               "Age of the oldest pending job, per kind (0 when none is pending).",
               [({"kind": k}, oldest.get(k, 0)) for k in kinds])


def _counters(session: Session, out: _Out) -> None:
    values = {name: int(value) for name, value in session.exec(select(CbomOpsCounter.name, CbomOpsCounter.value)).all()}
    out.family("cbom_job_lease_expiries_total", "counter",
               "Job leases the reaper expired: requeued for another attempt, or failed after the last attempt.",
               [({"outcome": "requeued"}, values.get(LEASE_EXPIRED["pending"], 0)),
                ({"outcome": "failed"}, values.get(LEASE_EXPIRED["failure"], 0))])
    out.family("cbom_ingest_rejected_assets_total", "counter",
               "Assets in node or worker batches that the server refused (unknown type, no location).",
               [({}, values.get(INGEST_REJECTED, 0))])


def _nodes(session: Session, now: _dt.datetime, out: _Out) -> None:
    from backend.utilities.cbom_sources.planning import ONLINE_SECONDS

    N = CbomScanNode
    registered = N.node_token_hash.is_not(None)  # type: ignore[union-attr]
    beat = N.last_heartbeat_at
    cols = [
        func.sum(case((registered & (beat >= now - _dt.timedelta(seconds=ONLINE_SECONDS)), 1), else_=0)),
        func.sum(case((registered & ((beat.is_(None)) | (beat < now - _dt.timedelta(seconds=ONLINE_SECONDS))), 1),  # type: ignore[union-attr]
                      else_=0)),
        func.sum(case((~registered & ((N.registration_expires_at.is_(None))  # type: ignore[union-attr]
                                      | (N.registration_expires_at > now)), 1), else_=0)),
        func.sum(case((~registered & (N.registration_expires_at <= now), 1), else_=0)),
        func.sum(case((registered & beat.is_(None), 1), else_=0)),  # type: ignore[union-attr]
        func.sum(case((registered & beat.is_not(None), 1), else_=0)),  # type: ignore[union-attr]
        func.min(case((registered, beat), else_=None)),
        *[func.sum(case((registered & (beat >= now - _dt.timedelta(seconds=le)), 1), else_=0))
          for le in HEARTBEAT_BUCKETS],
    ]
    row = session.exec(select(*cols)).one()
    online, offline, pending, expired, never, beating = (int(v or 0) for v in row[:6])
    first = row[6]
    buckets = [int(v or 0) for v in row[7:]]
    out.family("cbom_nodes", "gauge", f"Scan nodes by state (online: a heartbeat within {ONLINE_SECONDS} s).",
               [({"state": s}, v) for s, v in zip(NODE_STATES, (online, offline, pending, expired))])
    out.family("cbom_node_heartbeat_age_seconds_bucket", "gauge",
               "Registered nodes whose last heartbeat is at most le seconds old (cumulative; +Inf: every node that "
               "has sent one).",
               [({"le": str(le)}, v) for le, v in zip(HEARTBEAT_BUCKETS, buckets)] + [({"le": "+Inf"}, beating)])
    out.family("cbom_node_heartbeat_age_seconds_max", "gauge",
               "Age of the oldest last heartbeat among registered nodes (0 when none has sent one).",
               [({}, _age(now, first) or 0)])
    out.family("cbom_nodes_never_heartbeat", "gauge", "Registered nodes that have not sent a heartbeat yet.",
               [({}, never)])


def _integrations(session: Session, now: _dt.datetime, out: _Out) -> None:
    counts: dict[str, int] = {}
    oldest = None
    for status, count, first in session.exec(
            select(IntegrationDelivery.status, func.count(), func.min(IntegrationDelivery.created_at))
            .where(IntegrationDelivery.status.in_(DELIVERY_STATUSES))  # type: ignore[attr-defined]
            .group_by(IntegrationDelivery.status)).all():
        counts[str(status)] = int(count)
        if status == "pending":
            oldest = _age(now, first)
    out.family("cbom_integration_deliveries", "gauge",
               "Integration backlog: deliveries waiting to be sent (pending) and dead-lettered (dead).",
               [({"status": s}, counts.get(s, 0)) for s in DELIVERY_STATUSES])
    out.family("cbom_integration_oldest_pending_age_seconds", "gauge",
               "Age of the oldest pending integration delivery (0 when none).", [({}, oldest or 0)])


__all__ = ["CONTENT_TYPE", "LEASE_EXPIRED", "INGEST_REJECTED", "bump", "render"]
