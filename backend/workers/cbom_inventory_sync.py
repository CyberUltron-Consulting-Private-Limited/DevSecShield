"""CBOM fleet inventory sync: lists AWS inventory sources that are due (or queued from the API) and saves what they hold.

    python -m backend.workers.cbom_inventory_sync           # loop (its own process)
    python -m backend.workers.cbom_inventory_sync --once    # one tick (tests, cron)

The cloud worker starts it on a background thread (``start_thread``) only while ``CBOM_FLEET_INVENTORY`` is on (set
``CBOM_INVENTORY_SYNC=0`` to turn the thread off when it runs as its own service).  It never runs in the cloud worker's
job loop: listing a large account takes minutes.  Several may run at once: a source is claimed with a guarded UPDATE
and a 30-minute lease, so each sync runs once.
"""
from __future__ import annotations

import argparse
import os
import signal
import threading
from typing import Any

from backend.utilities.cbom_sources.common import log, new_ref, utcnow

TICK_S = 30


def tick(engine, now=None) -> list[dict[str, Any]]:
    from sqlmodel import Session

    from backend.utilities.cbom_sources.fleet.sync import due_ids, run_sync

    now = now or utcnow()
    with Session(engine) as session:
        ids = due_ids(session, now)
    out = []
    for source_id in ids:
        try:
            out.append({"source_id": source_id, **run_sync(engine, source_id)})
        except Exception as exc:  # one source must not stop the others
            log("inventory sync tick FAILED", ref=new_ref(), source=source_id, error=type(exc).__name__)
    return out


def loop(engine, stop: threading.Event) -> None:
    log("inventory sync started", tick_s=TICK_S)
    while not stop.is_set():
        try:
            tick(engine)
        except Exception as exc:  # a database hiccup: wait for the next tick
            log("inventory sync loop FAILED", ref=new_ref(), error=type(exc).__name__)
        stop.wait(TICK_S)
    log("inventory sync stopped")


def start_thread(engine) -> threading.Event | None:
    """Run the sync on a daemon thread of this process: only with CBOM_FLEET_INVENTORY on, unless CBOM_INVENTORY_SYNC=0."""
    from backend.utilities.cbom_sources.fleet.flags import inventory_enabled

    if not inventory_enabled() or os.environ.get("CBOM_INVENTORY_SYNC", "1").strip() == "0":
        return None
    stop = threading.Event()
    threading.Thread(target=loop, args=(engine, stop), name="cbom-inventory-sync", daemon=True).start()
    return stop


def main() -> None:
    from backend.get_db import get_db

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="run one tick and exit")
    args = parser.parse_args()
    engine = get_db()
    if args.once:
        log("inventory sync tick", synced=len(tick(engine)))
        return
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    signal.signal(signal.SIGINT, lambda *_a: stop.set())
    loop(engine, stop)


if __name__ == "__main__":
    main()
