"""CBOM Sources scheduler: fires due collection schedules and records drift events of finished runs.

    python -m backend.workers.cbom_scheduler           # loop (its own process)
    python -m backend.workers.cbom_scheduler --once    # one tick (tests, cron)

The cloud worker also starts it on a background thread (``start_thread``; set ``CBOM_SCHEDULER=0`` to turn that off
when the scheduler runs as its own service). It never runs inside the cloud worker's job loop: an AWS collection can
hold that loop for hours, and schedules must fire on time. Several schedulers may run at once (replicas, a thread in
every cloud worker): a slot fires exactly once (see ``cbom_sources.schedules``), drift is recorded once per run and
a run's stored drift document is claimed by one scheduler (``drift.store_pending_summaries``). ``loop()`` stores those
documents on a thread of its own, so a long comparison never delays the next schedule check.
"""
from __future__ import annotations

import argparse
import atexit
import os
import signal
import threading
import time
from typing import Any

from backend.utilities.cbom_sources.common import log, new_ref, utcnow

TICK_S = 30


def tick(engine, now=None, *, summaries: bool = True) -> dict[str, Any]:
    """One scheduler pass. ``summaries``: also store pending drift documents, last and within the tick's budget
    (``--once`` and tests; ``loop()`` runs them on their own thread instead)."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources.schedules import fire_due

    started = time.monotonic()
    now = now or utcnow()
    fired = fire_due(engine, now)  # never waits for DRIFT.HEAVY: schedules fire on time
    out: dict[str, Any] = {"fired": fired}
    # the heavy steps (drift recording: a comparison per finished run; the estate repair) share DRIFT.HEAVY with the
    # summary thread's comparisons, so two never run at once in this process (review 6032466269 major 1). Busy: this
    # tick skips them (the next one runs them) and the summary pass yields before its next run.
    if DRIFT.HEAVY.acquire(blocking=False):
        try:
            DRIFT.TICK_WANTS_HEAVY.clear()
            out["drift_runs"] = DRIFT.record_pending_drift(engine, now)
            try:  # CB-20/CB-32: a store that missed a run (deferred by a request with a cold key index, or a failed write)
                from backend.utilities.cbom_sources.estate import repair_due

                out["estate_repair"] = repair_due(engine, now)
            except Exception as exc:
                log("estate repair FAILED", ref=new_ref(), error=type(exc).__name__)
        finally:
            DRIFT.HEAVY.release()
    else:
        DRIFT.TICK_WANTS_HEAVY.set()
        out["drift_runs"] = out["estate_repair"] = "busy"
        log("scheduler heavy steps deferred", reason="drift summary computing")
    try:  # CB-32: the trigger-kept summary tables, checked against their base tables once a day per process
        from backend.utilities.cbom_sources.estate_summary_ddl import check_due

        out["estate_summary_check"] = check_due(engine, now)
    except Exception as exc:  # noqa: BLE001 - one failed check must not stop the tick
        log("estate summary check FAILED", ref=new_ref(), error=type(exc).__name__)
    try:  # CB-23: the register's daily re-judge (day 366 evidence; deleted sources), at most hourly per process
        from backend.utilities.cbom_sources.q0register import tick_due

        out["q0_register"] = tick_due(engine, now)
    except Exception as exc:
        log("q0 register tick FAILED", ref=new_ref(), error=type(exc).__name__)
    try:  # CB-23 PR-B: background re-grade of the risk register after an inputs or model change (one batch a team)
        from backend.utilities.cbom_sources.risk_register import regrade_due

        out["risk_register"] = regrade_due(engine, now)
    except Exception as exc:
        log("risk register re-grade FAILED", ref=new_ref(), error=type(exc).__name__)
    try:  # F1.4: the SSH CA audit is kept 13 months (at most hourly; a failure never stops schedules)
        from backend.utilities.cbom_sources.sshca.retention import purge_due

        out["sshca_retention"] = purge_due(engine, now)
    except Exception as exc:
        log("ssh ca audit retention FAILED", ref=new_ref(), error=type(exc).__name__)
    if summaries:
        out["drift_summaries"] = _store_summaries(engine, now, started)
    return out


def _store_summaries(engine, now, started: float | None = None, stop: threading.Event | None = None) -> int | None:
    """S4 (review #486 minor 8): the drift document of recently recorded runs, stored once for report and pack."""
    try:
        from backend.utilities.cbom_sources.drift import store_pending_summaries

        return store_pending_summaries(engine, now, started=started, stop=stop)
    except Exception as exc:  # noqa: BLE001 - a download computes the document instead
        log("drift summaries FAILED", ref=new_ref(), error=type(exc).__name__)
        return None


SHUTDOWN_WAIT_S = 20.0  # a stop waits this long for a running comparison; then its claim is released (no try counted)
_SUMMARY_THREADS: list[tuple[threading.Thread, Any]] = []
_SUMMARY_THREADS_LOCK = threading.Lock()


def _summary_loop(engine, stop: threading.Event) -> None:
    """The drift-summary pass of ``loop()``, every TICK_S on its own thread: a comparison of a large run (seconds at
    50k assets) never holds the scheduling thread, so schedules fire on time (review 6030475121 minor A). It runs its
    comparisons under DRIFT.HEAVY, never beside the tick's heavy steps (review 6032466269 major 1)."""
    while not stop.is_set():
        _store_summaries(engine, utcnow(), stop=stop)
        stop.wait(TICK_S)


def shutdown_summaries(timeout: float | None = None) -> None:
    """Wait (up to ``timeout``) for the summary threads to finish their comparison, then release any claim still held,
    so a restart costs no try (review 6032466269 minor 4). Called by ``loop()`` on stop and at interpreter exit (the
    cloud worker sets the stop event and exits without joining the scheduler thread)."""
    from backend.utilities.cbom_sources import drift as DRIFT

    timeout = SHUTDOWN_WAIT_S if timeout is None else timeout
    deadline = time.monotonic() + timeout
    with _SUMMARY_THREADS_LOCK:
        threads = list(_SUMMARY_THREADS)
    for thread, engine in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            log("drift summary thread still computing at shutdown", waited_s=round(timeout, 1))
        DRIFT.release_claims(engine)
        if not thread.is_alive():
            with _SUMMARY_THREADS_LOCK:
                if (thread, engine) in _SUMMARY_THREADS:
                    _SUMMARY_THREADS.remove((thread, engine))
    DRIFT.TICK_WANTS_HEAVY.clear()  # no tick follows a shutdown: a pass run after it (``--once``, tests) must not yield


atexit.register(shutdown_summaries)


def loop(engine, stop: threading.Event) -> None:
    log("scheduler started", tick_s=TICK_S)
    summaries = threading.Thread(target=_summary_loop, args=(engine, stop), name="cbom-drift-summaries", daemon=True)
    with _SUMMARY_THREADS_LOCK:
        _SUMMARY_THREADS.append((summaries, engine))
    summaries.start()
    while not stop.is_set():
        try:
            tick(engine, summaries=False)
        except Exception as exc:  # a database hiccup: wait for the next tick
            log("scheduler tick FAILED", ref=new_ref(), error=type(exc).__name__)
        stop.wait(TICK_S)
    shutdown_summaries()
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
