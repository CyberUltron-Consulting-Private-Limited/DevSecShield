"""
Stopping a code scan the customer cancelled (backend utilities/scan/cancel_scan.py).

The backend marks a cancelled task in the Celery result backend's Mongo database (collection ``scan_cancellations``,
``_id`` = task id) -- the one store this worker can reach -- and also revokes it. Here:

* ``cancellable`` wraps a scan task: a task picked up after its cancel never runs (revoke alone is forgotten when a
  worker restarts), and a running one is watched by a thread that polls the mark every few seconds.
* On a cancel the watcher kills the process group of every tool started through ``run_tool`` (semgrep, syft, grype,
  cdxgen, cbomkit): each runs in its own session, so its children die with it.
* The scan stops at its next safe point: right after a tool returns, or at its next progress write
  (``StateUpdateWriter``), by raising ``ScanCancelled``. It derives from BaseException so the agents' broad
  ``except Exception`` blocks cannot swallow it; ``cancellable`` turns it into Celery's REVOKED state and the task's
  own ``finally`` still deletes the upload.

No results are delivered for a cancelled scan: the backend never stores them (the scan row is already cancelled).
"""
from __future__ import annotations

import functools
import os
import signal
import subprocess
import threading
import time
from typing import Callable

CANCEL_COLLECTION = "scan_cancellations"
POLL_SECONDS = float(os.getenv("SCAN_CANCEL_POLL_SECONDS", "3"))
KILL_GRACE_SECONDS = 3.0


class ScanCancelled(BaseException):
    """The customer cancelled this scan. BaseException on purpose: see the module docstring."""


def kill_process_group(proc: subprocess.Popen, grace: float = KILL_GRACE_SECONDS) -> None:
    """SIGTERM the tool's whole process group, then SIGKILL whatever is left after ``grace`` seconds."""
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        return
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 0)):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            return
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        try:
            os.killpg(pgid, 0)  # anyone left in the group?
        except (ProcessLookupError, PermissionError, OSError):
            return


class CancelWatch:
    """Polls ``is_cancelled`` in a thread; on a cancel, kills the registered tool process groups."""

    def __init__(self, is_cancelled: Callable[[], bool], interval: float = POLL_SECONDS):
        self._is_cancelled = is_cancelled
        self._interval = interval
        self._cancelled = threading.Event()
        self._stop = threading.Event()
        self._procs: set[subprocess.Popen] = set()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def poll(self) -> bool:
        if not self._cancelled.is_set():
            try:
                hit = bool(self._is_cancelled())
            except Exception:  # Mongo unreachable: keep scanning (the backend never stores a cancelled scan's results)
                hit = False
            if hit:
                self._cancelled.set()
                self.kill_tools()
        return self._cancelled.is_set()

    def check(self) -> None:
        """Raise ScanCancelled when the scan was cancelled (cheap: reads the flag the watcher thread sets)."""
        if self._cancelled.is_set():
            raise ScanCancelled()

    def register(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs.add(proc)
        if self._cancelled.is_set():
            kill_process_group(proc)

    def unregister(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs.discard(proc)

    def kill_tools(self) -> None:
        with self._lock:
            procs = list(self._procs)
        for proc in procs:
            kill_process_group(proc)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            if self.poll():
                return

    def start(self) -> "CancelWatch":
        self._thread = threading.Thread(target=self._run, name="scan-cancel-watch", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 1)


# The scan worker runs with ``-P threads`` (several scans in one process, one thread each): the watch of the scan
# running in this thread, for run_tool and the progress writer.
_local = threading.local()


def current_watch() -> CancelWatch | None:
    return getattr(_local, "watch", None)


def check_cancelled() -> None:
    watch = current_watch()
    if watch is not None:
        watch.check()


def run_tool(cmd, *, timeout: float | None = None, check: bool = False, input=None, capture_output: bool = False,
             **popen_kwargs) -> subprocess.CompletedProcess:
    """``subprocess.run`` for scan tools: the tool gets its own process group, which is killed as a whole on a
    timeout, on any error, and when the scan is cancelled (then ScanCancelled is raised once the tool has died)."""
    if capture_output:
        popen_kwargs["stdout"] = subprocess.PIPE
        popen_kwargs["stderr"] = subprocess.PIPE
    if input is not None:
        popen_kwargs["stdin"] = subprocess.PIPE
    watch = current_watch()
    if watch is not None:
        watch.check()
    with subprocess.Popen(cmd, start_new_session=True, **popen_kwargs) as proc:
        if watch is not None:
            watch.register(proc)
        try:
            stdout, stderr = proc.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            kill_process_group(proc, grace=0.5)
            out, err = proc.communicate()
            raise subprocess.TimeoutExpired(proc.args, timeout, output=out, stderr=err) from exc
        except BaseException:
            kill_process_group(proc, grace=0.5)
            raise
        finally:
            if watch is not None:
                watch.unregister(proc)
        retcode = proc.poll()
    if watch is not None:
        watch.check()  # a cancelled scan stops here, not in the parser of a killed tool's output
    if check and retcode:
        raise subprocess.CalledProcessError(retcode, proc.args, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(proc.args, retcode, stdout, stderr)


def mongo_cancel_lookup(task) -> Callable[[], bool]:
    """Reads the backend's mark through the task's own result backend (the Mongo database the backend writes)."""
    task_id = task.request.id

    def lookup() -> bool:
        if not task_id:
            return False
        return task.backend.database[CANCEL_COLLECTION].find_one({"_id": task_id}, {"_id": 1}) is not None

    return lookup


def cancellable(fn=None, *, lookup_factory: Callable = mongo_cancel_lookup, on_skip: Callable | None = None):
    """Decorator for a bound scan task (``bind=True``): see the module docstring. ``on_skip(kwargs)`` cleans up a
    task that is never run (its upload)."""

    def wrap(func):
        @functools.wraps(func)
        def run(self, *args, **kwargs):
            from celery.exceptions import Ignore

            lookup = lookup_factory(self)
            watch = CancelWatch(lookup)
            if watch.poll():  # cancelled while queued: never start it
                if on_skip is not None:
                    on_skip(kwargs)
                _mark_revoked(self)
                raise Ignore()
            _local.watch = watch.start()
            try:
                return func(self, *args, **kwargs)
            except ScanCancelled:
                watch.kill_tools()
                _mark_revoked(self)
                raise Ignore()
            finally:
                watch.stop()
                _local.watch = None

        return run

    return wrap(fn) if fn is not None else wrap


def _mark_revoked(task) -> None:
    try:
        task.backend.mark_as_revoked(task.request.id, "cancelled by the customer", request=task.request)
    except Exception:
        pass  # the backend already shows the scan as cancelled; this only tidies Celery's own record
