"""CBOM Sources scheduler: fires due collection schedules and records drift events of finished runs.

    python -m backend.workers.cbom_scheduler           # loop (its own process)
    python -m backend.workers.cbom_scheduler --once    # one tick (tests, cron)

The cloud worker also starts it on a background thread (``start_thread``; set ``CBOM_SCHEDULER=0`` to turn that off
when the scheduler runs as its own service). It never runs inside the cloud worker's job loop: an AWS collection can
hold that loop for hours, and schedules must fire on time. Several schedulers may run at once (replicas, a thread in
every cloud worker): a slot fires exactly once (see ``cbom_sources.schedules``) and drift is recorded once per run.
"""
from __future__ import annotations

import argparse
import os
import signal
import threading
from typing import Any

from backend.utilities.cbom_sources.common import log, new_ref, utcnow

TICK_S = 30


def tick(engine, now=None) -> dict[str, Any]:
    from backend.utilities.cbom_sources.drift import record_pending_drift
    from backend.utilities.cbom_sources.schedules import fire_due

    now = now or utcnow()
    fired = fire_due(engine, now)
    drift = record_pending_drift(engine, now)
    return {"fired": fired, "drift_runs": drift}


def loop(engine, stop: threading.Event) -> None:
    log("scheduler started", tick_s=TICK_S)
    while not stop.is_set():
        try:
            tick(engine)
        except Exception as exc:  # a database hiccup: wait for the next tick
            log("scheduler tick FAILED", ref=new_ref(), error=type(exc).__name__)
        stop.wait(TICK_S)
    log("scheduler stopped")


def start_thread(engine) -> threading.Event | None:
    """Run the scheduler on a daemon thread of this process (unless CBOM_SCHEDULER=0)."""
    if os.environ.get("CBOM_SCHEDULER", "1").strip() == "0":
        return None
    stop = threading.Event()
    threading.Thread(target=loop, args=(engine, stop), name="cbom-scheduler", daemon=True).start()
    return stop


def main() -> None:
    from backend.get_db import get_db

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="run one tick and exit")
    args = parser.parse_args()
    engine = get_db()
    if args.once:
        out = tick(engine)
        log("scheduler tick", fired=len(out["fired"]), drift_runs=out["drift_runs"])
        return
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    signal.signal(signal.SIGINT, lambda *_a: stop.set())
    loop(engine, stop)


if __name__ == "__main__":
    main()
