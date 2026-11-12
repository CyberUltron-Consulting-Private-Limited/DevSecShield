"""CBOM fleet worker: syncs the AWS inventory sources that are due (or queued from the API), and runs the team
evaluations and reconciles that writes asked for (``fleet/evaluate.py``).

    python -m backend.workers.cbom_inventory_sync           # loop (its own process)
    python -m backend.workers.cbom_inventory_sync --once    # one tick of each (tests, cron)

The cloud worker starts it on background threads (``start_thread``) while ``CBOM_FLEET_INVENTORY`` or
``CBOM_FLEET_POLICIES`` is on (set ``CBOM_INVENTORY_SYNC=0`` to turn the threads off when it runs as its own
service).  It never runs in the cloud worker's job loop: listing a large account takes minutes.

* **Syncs**: ``CBOM_INVENTORY_SYNC_WORKERS`` threads (default 2) take one due source at a time, fairest first
  (``sync.due_ids``: queued, then never synced, then the longest wait), and ask again after each, so no source starves.
  A source is claimed with a guarded UPDATE and a lease, so several threads or processes never sync it twice.
* **Evaluations**: one thread runs the teams whose state asks for an evaluation or a reconcile, every few seconds, so
  a large team's decisions follow a policy write within seconds and a deferred managed-source change is retried.
"""
from __future__ import annotations

import argparse
import os
import signal
import threading
from typing import Any

from backend.utilities.cbom_sources.common import log, new_ref, utcnow

TICK_S = 30
EVAL_TICK_S = 3
MAX_SYNCS_PER_TICK = 20


def tick(engine, now=None) -> list[dict[str, Any]]:
    """Sync due sources one at a time, asking which is due again after each (at most MAX_SYNCS_PER_TICK)."""
    from sqlmodel import Session

    from backend.utilities.cbom_sources.fleet.sync import due_ids, run_sync

    out: list[dict[str, Any]] = []
    tried: set[int] = set()
    for _ in range(MAX_SYNCS_PER_TICK):
        with Session(engine) as session:
            ids = [i for i in due_ids(session, now or utcnow(), limit=len(tried) + 1) if i not in tried]
        if not ids:
            break
        source_id = ids[0]
        tried.add(source_id)
        try:
            result = run_sync(engine, source_id)
        except Exception as exc:  # one source must not stop the others
            log("inventory sync tick FAILED", ref=new_ref(), source=source_id, error=type(exc).__name__)
            continue
        if result.get("status") != "busy":
            out.append({"source_id": source_id, **result})
    return out


def fleet_tick(engine, now=None) -> list[dict[str, Any]]:
    """Run the evaluations and reconciles teams asked for."""
    from backend.utilities.cbom_sources.fleet.evaluate import run_requested

    return run_requested(engine, now or utcnow())


def _loop(name: str, fn, engine, stop: threading.Event, every_s: int) -> None:
    log(f"{name} started", tick_s=every_s)
    while not stop.is_set():
        try:
            fn(engine)
        except Exception as exc:  # a database hiccup: wait for the next tick
            log(f"{name} loop FAILED", ref=new_ref(), error=type(exc).__name__)
        stop.wait(every_s)
    log(f"{name} stopped")


def loop(engine, stop: threading.Event) -> None:
    _loop("inventory sync", tick, engine, stop, TICK_S)


def _workers() -> int:
    try:
        return max(1, min(8, int(os.environ.get("CBOM_INVENTORY_SYNC_WORKERS", "2"))))
    except ValueError:
        return 2


def start_thread(engine) -> threading.Event | None:
    """Start the fleet threads in this process while inventory or policies are on, unless CBOM_INVENTORY_SYNC=0."""
    from backend.utilities.cbom_sources.fleet.flags import inventory_enabled, policies_enabled

    if os.environ.get("CBOM_INVENTORY_SYNC", "1").strip() == "0":
        return None
    if not (inventory_enabled() or policies_enabled()):
        return None
    stop = threading.Event()
    if inventory_enabled():
        for n in range(_workers()):
            threading.Thread(target=loop, args=(engine, stop), name=f"cbom-inventory-sync-{n}", daemon=True).start()
    threading.Thread(target=_loop, args=("fleet evaluation", fleet_tick, engine, stop, EVAL_TICK_S),
                     name="cbom-fleet-evaluation", daemon=True).start()
    return stop


def main() -> None:
    from backend.get_db import get_db

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="run one tick of each and exit")
    args = parser.parse_args()
    engine = get_db()
    if args.once:
        log("inventory sync tick", synced=len(tick(engine)), evaluated=len(fleet_tick(engine)))
        return
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    signal.signal(signal.SIGINT, lambda *_a: stop.set())
    threads = [threading.Thread(target=loop, args=(engine, stop), daemon=True) for _ in range(_workers())]
    threads.append(threading.Thread(target=_loop, args=("fleet evaluation", fleet_tick, engine, stop, EVAL_TICK_S),
                                    daemon=True))
    for t in threads:
        t.start()
    stop.wait()


if __name__ == "__main__":
    main()
