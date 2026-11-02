"""Integration dispatcher: forwards CBOM events to ServiceNow, syslog, Splunk HEC, signed webhooks and OSCAL push.

    python -m backend.workers.integration_dispatcher           # loop (its own process)
    python -m backend.workers.integration_dispatcher --once    # one pass (tests, cron)

The cloud worker also starts it on a background thread (``start_thread``; set ``INTEGRATION_DISPATCHER=0`` to turn
that off when it runs as its own service). It is separate from the CBOM scheduler on purpose: a slow or unreachable
destination (each request may take up to 20 s) must never delay a scheduled collection. Several dispatchers may run at
once; each integration's queue is delivered by one of them at a time (``dispatch.deliver_integration``).
"""
from __future__ import annotations

import argparse
import os
import signal
import threading

from backend.utilities.cbom_sources.common import log, new_ref

TICK_S = 10


def loop(engine, stop: threading.Event) -> None:
    from backend.utilities.integrations.dispatch import tick

    log("integration dispatcher started", tick_s=TICK_S)
    while not stop.is_set():
        try:
            tick(engine)
        except Exception as exc:  # a database hiccup: wait for the next tick
            log("integration dispatcher tick FAILED", ref=new_ref(), error=type(exc).__name__)
        stop.wait(TICK_S)
    log("integration dispatcher stopped")


def start_thread(engine) -> threading.Event | None:
    """Run the dispatcher on a daemon thread of this process (unless INTEGRATION_DISPATCHER=0)."""
    if os.environ.get("INTEGRATION_DISPATCHER", "1").strip() == "0":
        return None
    stop = threading.Event()
    threading.Thread(target=loop, args=(engine, stop), name="integration-dispatcher", daemon=True).start()
    return stop


def main() -> None:
    from backend.get_db import get_db
    from backend.utilities.integrations.dispatch import tick

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="run one pass and exit")
    args = parser.parse_args()
    engine = get_db()
    if args.once:
        log("integration dispatcher tick", **tick(engine))
        return
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    signal.signal(signal.SIGINT, lambda *_a: stop.set())
    loop(engine, stop)


if __name__ == "__main__":
    main()
