"""Delivering queued integration events: in order per destination, at least once, with back-off and a dead-letter list.

* One dispatcher at a time works on one integration (``lease_until`` compare-and-set), oldest event first, so a
  "finding resolved" never overtakes its "finding opened". Several dispatchers (threads in several cloud workers, or
  the standalone process) may run at once.
* Outcomes per event (``base.Outcome``): delivered; rejected for good (HTTP 400 for that event: dead-letter, the queue
  moves on); or "retry" (destination down, refused, throttled, TLS or credentials): the queue stops there and the
  integration backs off (30 s doubling to 30 min, Retry-After honoured up to an hour). Events still not delivered
  ``MAX_AGE`` after they were queued move to the dead-letter list at the next failed attempt.
* Dead-lettered events can be retried from Settings > Integrations (they keep their event id).
* Delivered and dead rows are deleted after ``RETENTION`` (the deliveries table is a log, not an archive).
"""
from __future__ import annotations

import datetime as _dt
import os
import random
import time
from typing import Any

from sqlalchemy import delete, func, update
from sqlmodel import Session, select

from backend.new_models import IntegrationDelivery, TeamIntegration
from backend.utilities.cbom_sources.common import log, utcnow
from backend.utilities.cbom_sources.crypto import decrypt_secrets
from backend.utilities.integrations.base import Context, Outcome
from backend.utilities.integrations.registry import SPECS, validate_config

LEASE = _dt.timedelta(seconds=300)  # > BUDGET_S + one slow event (ServiceNow: 3 requests x 20 s)
BUDGET_S = 45.0  # per integration per tick; well inside the lease
BACKOFF_BASE_S = 30.0
BACKOFF_MAX_S = 1800.0
RETENTION = _dt.timedelta(days=30)


def max_age() -> _dt.timedelta:
    try:
        hours = float(os.environ.get("INTEGRATION_MAX_AGE_HOURS", "24"))
    except ValueError:
        hours = 24.0
    return _dt.timedelta(hours=min(max(hours, 1.0), 24.0 * 14))


def backoff(failures: int, retry_after: float | None = None) -> float:
    wait = min(BACKOFF_BASE_S * (2 ** max(failures - 1, 0)), BACKOFF_MAX_S) * random.uniform(0.8, 1.2)
    if retry_after:
        wait = max(wait, min(retry_after, 3600.0))
    return wait


def _due_integrations(session: Session, now: _dt.datetime) -> list[int]:
    rows = session.exec(
        select(TeamIntegration.id).where(
            TeamIntegration.enabled == True,  # noqa: E712
            (TeamIntegration.next_attempt_at.is_(None)) | (TeamIntegration.next_attempt_at <= now),  # type: ignore[union-attr,operator]
            (TeamIntegration.lease_until.is_(None)) | (TeamIntegration.lease_until < now),  # type: ignore[union-attr,operator]
            TeamIntegration.id.in_(select(IntegrationDelivery.integration_id).where(  # type: ignore[union-attr]
                IntegrationDelivery.status == "pending")))
        .order_by(TeamIntegration.id)).all()
    return list(rows)


def _claim(session: Session, integration_id: int, now: _dt.datetime) -> bool:
    won = session.exec(update(TeamIntegration).where(
        TeamIntegration.id == integration_id, TeamIntegration.enabled == True,  # noqa: E712
        (TeamIntegration.lease_until.is_(None)) | (TeamIntegration.lease_until < now))  # type: ignore[union-attr,operator]
        .values(lease_until=now + LEASE)).rowcount == 1
    session.commit()
    return won


def context_for(integration: TeamIntegration, engine) -> Context:
    cfg = validate_config(integration.kind, integration.config or {})
    return Context(team_id=integration.team_id, config=cfg, secrets=decrypt_secrets(integration.secret_encrypted),
                   engine=engine, integration_id=integration.id)


def deliver_integration(engine, integration_id: int, now: _dt.datetime | None = None) -> dict[str, int]:
    """Deliver one integration's queue (caller holds nothing; this claims the lease). Returns counts."""
    now = now or utcnow()
    counts = {"delivered": 0, "dead": 0, "retry": 0}
    with Session(engine) as session:
        if not _claim(session, integration_id, now):
            return counts
    started = time.monotonic()
    try:
        while True:  # at least one batch per claim, then batches until the time budget is used
            with Session(engine) as session:
                integration = session.get(TeamIntegration, integration_id)
                if integration is None or not integration.enabled:
                    break
                spec = SPECS[integration.kind]
                batch = list(session.exec(select(IntegrationDelivery).where(
                    IntegrationDelivery.integration_id == integration_id, IntegrationDelivery.status == "pending")
                    .order_by(IntegrationDelivery.id).limit(spec.batch)).all())
                if not batch:
                    break
                try:
                    ctx = context_for(integration, engine)
                    ctx.deadline = started + BUDGET_S
                    outcomes = spec.send(ctx, [dict(d.payload or {}) for d in batch])
                except Exception as exc:  # a stored config the current rules reject, or a connector bug
                    outcomes = [Outcome("retry", f"the integration could not run ({type(exc).__name__}); check its settings")]
                current = now + _dt.timedelta(seconds=time.monotonic() - started)  # the caller's clock, advanced
                stop = _record(session, integration, batch, outcomes, current, counts)
                session.commit()
                if stop or time.monotonic() - started >= BUDGET_S:
                    break
    finally:
        with Session(engine) as session:
            session.exec(update(TeamIntegration).where(TeamIntegration.id == integration_id).values(lease_until=None))
            session.commit()
    if any(counts.values()):
        log("integration delivered", integration=integration_id, **counts)
    return counts


def _record(session: Session, integration: TeamIntegration, batch: list[IntegrationDelivery], outcomes: list[Outcome],
            now: _dt.datetime, counts: dict[str, int]) -> bool:
    """Apply outcomes in order. Returns True when the queue must stop (a retry, or nothing was attempted)."""
    if not outcomes:
        outcomes = [Outcome("retry", "nothing was sent")]
    for delivery, outcome in zip(batch, outcomes):
        delivery.attempts += 1
        delivery.last_attempt_at = now
        delivery.last_result = outcome.reason[:255]
        if outcome.ref:
            delivery.external_ref = outcome.ref[:64]
        if outcome.status == "ok":
            delivery.status, delivery.delivered_at = "delivered", now
            counts["delivered"] += 1
        elif outcome.status == "reject":
            delivery.status = "dead"
            counts["dead"] += 1
        else:
            counts["retry"] += 1
            integration.failures += 1
            wait = backoff(integration.failures, outcome.retry_after)
            integration.next_attempt_at = now + _dt.timedelta(seconds=wait)
            integration.last_error = outcome.reason[:255]
            session.add(delivery)
            expired = session.exec(update(IntegrationDelivery).where(
                IntegrationDelivery.integration_id == integration.id, IntegrationDelivery.status == "pending",
                IntegrationDelivery.created_at < now - max_age())
                .values(status="dead", last_result=f"not delivered within {int(max_age().total_seconds() // 3600)} h; "
                                                   f"last error: {outcome.reason}"[:255])).rowcount or 0
            counts["dead"] += int(expired)
            session.add(integration)
            log("integration delivery RETRY", integration=integration.id, kind=integration.kind,
                failures=integration.failures, wait_s=int(wait), expired=int(expired) or None)
            return True
        session.add(delivery)
    integration.failures, integration.next_attempt_at, integration.last_error = 0, None, None
    integration.last_delivery_at = now
    session.add(integration)
    return len(outcomes) < len(batch)  # a connector that stopped early without saying why: try again next tick


def prune(engine, now: _dt.datetime) -> int:
    with Session(engine) as session:
        gone = session.exec(delete(IntegrationDelivery).where(
            IntegrationDelivery.status.in_(("delivered", "dead")),  # type: ignore[attr-defined]
            IntegrationDelivery.created_at < now - RETENTION)).rowcount or 0
        session.commit()
    return int(gone)


def tick(engine, now: _dt.datetime | None = None) -> dict[str, Any]:
    """One dispatcher pass: queue new drift events, deliver every due integration, prune old log rows."""
    from backend.utilities.integrations.events import enqueue_drift

    now = now or utcnow()
    queued = enqueue_drift(engine, now)
    with Session(engine) as session:
        due = _due_integrations(session, now)
    totals = {"queued": queued, "integrations": len(due), "delivered": 0, "dead": 0, "retry": 0}
    for integration_id in due:
        try:
            counts = deliver_integration(engine, integration_id, now)
        except Exception as exc:  # one broken integration never stops the others
            log("integration dispatch FAILED", integration=integration_id, error=type(exc).__name__)
            continue
        for k, v in counts.items():
            totals[k] += v
    if now.minute == 0 and now.second < 15:
        prune(engine, now)
    return totals


def queue_counts(session: Session, team_id: int) -> dict[int, dict[str, int]]:
    rows = session.exec(select(IntegrationDelivery.integration_id, IntegrationDelivery.status, func.count())
                        .where(IntegrationDelivery.team_id == team_id)
                        .group_by(IntegrationDelivery.integration_id, IntegrationDelivery.status)).all()
    out: dict[int, dict[str, int]] = {}
    for integration_id, status, n in rows:
        out.setdefault(integration_id, {})[status] = int(n)
    return out
