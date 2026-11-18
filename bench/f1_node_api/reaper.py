"""The job reaper the cloud worker runs, as a standalone loop for the bench (no AWS collection, no scheduler).

    PYTHONPATH=<src root> python bench/f1_node_api/reaper.py [--every 30]

Imports ``reap_all`` from the code under test (``backend.workers.cbom_cloud_worker``), so the dev baseline and the
branch each reap with their own code. Lease expiry of a dead node's job, and so its re-queue, depends on it.
"""
from __future__ import annotations

import argparse
import signal
import threading
import time


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--every", type=float, default=30.0)
    args = ap.parse_args()
    from backend.get_db import get_db
    from backend.workers.cbom_cloud_worker import reap_all

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    signal.signal(signal.SIGINT, lambda *_a: stop.set())
    engine = get_db()
    while not stop.is_set():
        t = time.monotonic()
        moved = reap_all(engine)
        print(f"reap moved={moved} ms={int((time.monotonic() - t) * 1000)}", flush=True)
        stop.wait(args.every)


if __name__ == "__main__":
    main()
