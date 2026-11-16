"""Repository scheduler (F3): discovery syncs, policy schedules, and the bounded fair queue of repository scans.

    python -m backend.workers.repo_scheduler            # loop (its own process)
    python -m backend.workers.repo_scheduler --once     # one pass of each loop (tests, cron)

Two loops, so a sync of thousands of repositories (minutes, rate-limited) never delays a dispatch:

* sync loop (every ``SYNC_TICK_S``): connections whose sync was requested or whose ``next_sync_at`` passed are synced
  (``inventory.sync_connection``, one lease per connection);
* queue loop (every ``QUEUE_TICK_S``): due policy slots fire (``policies.fire_due``), in-flight scans are polled and
  closed (``queue.poll_tick``), and free slots are filled fairly (``queue.dispatch_tick``).

The cloud worker also starts both on daemon threads (``start_thread``; ``REPO_SCHEDULER=0`` turns that off when this
runs as its own service). Several schedulers may run at once: syncs take a lease, slots fire once, the dispatcher holds
a PostgreSQL advisory lock per tick and claims with compare-and-set.
"""
from __future__ import annotations

import argparse
import os
import signal
import threading
from typing import Any

from sqlalchemy import or_
from sqlmodel import Session, select

from backend.utilities.cbom_sources.common import new_ref, utcnow
from backend.utilities.scm.common import log

SYNC_TICK_S = 30
QUEUE_TICK_S = 5
SYNCS_PER_TICK = 4


def due_connections(engine, now) -> list[int]:
    from backend.utilities.scm.models import ScmConnection

    with Session(engine) as session:
        return list(session.exec(
            select(ScmConnection.id).where(
                ScmConnection.enabled == True,  # noqa: E712
                or_(ScmConnection.sync_requested_at != None, ScmConnection.next_sync_at == None,  # noqa: E711
                    ScmConnection.next_sync_at <= now),
                or_(ScmConnection.sync_lease_until == None, ScmConnection.sync_lease_until < now))  # noqa: E711
            .order_by(ScmConnection.sync_requested_at.desc().nulls_last(), ScmConnection.next_sync_at)  # type: ignore[union-attr]
            .limit(SYNCS_PER_TICK)).all())


def sync_tick(engine, now=None) -> list[dict[str, Any]]:
    from backend.utilities.scm.inventory import sync_connection

    now = now or utcnow()
    out = []
    for connection_id in due_connections(engine, now):
        out.append({"connection_id": connection_id, **sync_connection(engine, connection_id, now=now)})
    return out


def queue_tick(engine, now=None, **kw: Any) -> dict[str, Any]:
    from backend.utilities.scm import policies, queue

    now = now or utcnow()
    fired = policies.fire_due(engine, now)
    closed = queue.poll_tick(engine, now, status_reader=kw.pop("status_reader", None))
    sent = queue.dispatch_tick(engine, now, **kw)
    return {"fired": fired, "closed": closed, "dispatched": len(sent)}


def _loop(name: str, fn, period: float, engine, stop: threading.Event) -> None:
    log(f"{name} started", tick_s=period)
    while not stop.is_set():
        try:
            fn(engine)
        except Exception as exc:  # a database or broker hiccup: wait for the next tick
            log(f"{name} tick FAILED", ref=new_ref(), error=type(exc).__name__)
        stop.wait(period)
    log(f"{name} stopped")


def start_thread(engine) -> threading.Event | None:
    """Run both loops on daemon threads of this process (unless REPO_SCHEDULER=0)."""
    if os.environ.get("REPO_SCHEDULER", "1").strip() == "0":
        return None
    stop = threading.Event()
    threading.Thread(target=_loop, args=("repo sync", sync_tick, SYNC_TICK_S, engine, stop), name="scm-sync",
                     daemon=True).start()
    threading.Thread(target=_loop, args=("repo queue", queue_tick, QUEUE_TICK_S, engine, stop), name="scm-queue",
                     daemon=True).start()
    return stop


def main() -> None:
    from backend.get_db import get_db

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="run one pass of each loop and exit")
    args = parser.parse_args()
    engine = get_db()
    if args.once:
        synced = sync_tick(engine)
        out = queue_tick(engine)
        log("repo scheduler pass", synced=len(synced), fired=len(out["fired"]), dispatched=out["dispatched"])
        return
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    signal.signal(signal.SIGINT, lambda *_a: stop.set())
    threads = [threading.Thread(target=_loop, args=("repo sync", sync_tick, SYNC_TICK_S, engine, stop)),
               threading.Thread(target=_loop, args=("repo queue", queue_tick, QUEUE_TICK_S, engine, stop))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
