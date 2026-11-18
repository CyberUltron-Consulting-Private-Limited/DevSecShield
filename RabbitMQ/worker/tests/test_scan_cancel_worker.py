"""Cancelled code scans in the worker (C1; helpers/context/cancellation.py).

* a task picked up after its cancel is never run, and its upload is deleted;
* a running scan stops at its next progress write / when its tool dies, and the tool's whole process group
  (a fake long-running tool with a child and a grandchild) is killed;
* the five code-scan tasks and the MCP and LLM runs are wired to it, and a tool timeout still kills the tool's
  children.

Run: /tmp/claude-0/wvenv/bin/python -m pytest -q RabbitMQ/worker/tests/test_scan_cancel_worker.py
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER))

from celery.exceptions import Ignore  # noqa: E402

from helpers.context import cancellation  # noqa: E402
from helpers.context.cancellation import CancelWatch, ScanCancelled, cancellable, run_tool  # noqa: E402
from helpers.context.progress_writer import StateUpdateWriter  # noqa: E402

# A tool that never ends and has a child and a grandchild, all printing their pids first.
TOOL = [sys.executable, "-c", (
    "import subprocess, sys, time\n"
    "child = subprocess.Popen([sys.executable, '-c', "
    "'import subprocess,sys,time; g=subprocess.Popen([\"sleep\",\"300\"]); print(g.pid, flush=True); time.sleep(300)'],"
    " stdout=sys.stdout)\n"
    "print(child.pid, flush=True)\n"
    "time.sleep(300)\n"
)]


def _group(pgid: int) -> list[int]:
    rows = (line.split() for line in os.popen("ps -eo pid=,pgid=").read().splitlines())
    return [int(pid) for pid, group in rows if int(group) == pgid]


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split()[2] != "Z"  # a zombie is dead
    except FileNotFoundError:
        return False


class FakeTask:
    def __init__(self):
        self.request = types.SimpleNamespace(id="task-1")
        self.revoked = []
        self.states = []
        self.backend = types.SimpleNamespace(
            mark_as_revoked=lambda task_id, reason, request=None: self.revoked.append((task_id, reason)))

    def update_state(self, state, meta):
        self.states.append((state, meta))


class Mark:
    """The backend's cancel mark: flipped by the test."""

    def __init__(self, cancelled=False):
        self.cancelled = cancelled

    def factory(self, _task):
        return lambda: self.cancelled


@pytest.fixture(autouse=True)
def _fast_poll(monkeypatch):
    monkeypatch.setattr(cancellation, "POLL_SECONDS", 0.1)
    real_init = CancelWatch.__init__

    def init(self, is_cancelled, interval=0.1):
        real_init(self, is_cancelled, interval)

    monkeypatch.setattr(CancelWatch, "__init__", init)


def test_a_task_cancelled_while_queued_is_never_run_and_its_upload_is_deleted():
    mark, skipped, ran = Mark(cancelled=True), [], []

    @cancellable(lookup_factory=mark.factory, on_skip=skipped.append)
    def scan(self, zip_dict_context=None):
        ran.append(1)

    task = FakeTask()
    with pytest.raises(Ignore):
        scan(task, zip_dict_context={"bucket_name": "b", "object_name": "o"})
    assert ran == [] and skipped == [{"zip_dict_context": {"bucket_name": "b", "object_name": "o"}}]
    assert task.revoked == [("task-1", "cancelled by the customer")]


def test_a_running_scan_stops_at_its_next_stage():
    mark, stages, cleaned = Mark(), [], []

    @cancellable(lookup_factory=mark.factory)
    def scan(self):
        writer = StateUpdateWriter(self)
        try:
            for stage in range(5):
                writer.write_progress_percentage(stage * 20)
                stages.append(stage)
                if stage == 1:
                    mark.cancelled = True  # the customer cancels during stage 1
                    time.sleep(0.4)  # the watcher sees it
                try:
                    pass
                except Exception:  # an agent's broad handler must not swallow the cancel
                    pass
            return "results"
        finally:
            cleaned.append(1)  # the task's own finally (deleting the upload) still runs

    task = FakeTask()
    with pytest.raises(Ignore):
        scan(task)
    assert stages == [0, 1] and cleaned == [1]
    assert task.revoked == [("task-1", "cancelled by the customer")]
    assert [m["current"] for _s, m in task.states] == [0, 20]  # no progress written after the cancel
    assert cancellation.current_watch() is None


def test_a_cancel_kills_the_running_tool_and_its_children_and_stops_the_scan():
    mark, pids, after_tool = Mark(), [], []

    @cancellable(lookup_factory=mark.factory)
    def scan(self):
        threading.Timer(1.0, lambda: setattr(mark, "cancelled", True)).start()
        try:
            run_tool(TOOL, capture_output=True, text=True, timeout=120)
        except Exception:  # a tool failure is often tolerated by the agents: the cancel is not
            pass
        after_tool.append(1)

    task = FakeTask()
    started = time.monotonic()
    # capture the tool's pids while it runs
    real_popen = subprocess.Popen

    class Spy(real_popen):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            pids.append(self.pid)

    cancellation.subprocess.Popen = Spy
    try:
        with pytest.raises(Ignore):
            scan(task)
    finally:
        cancellation.subprocess.Popen = real_popen
    elapsed = time.monotonic() - started
    assert after_tool == [] and elapsed < 10, elapsed
    tool_pid = pids[0]
    assert os.getpgid(os.getpid()) != tool_pid  # the tool ran in its own process group
    time.sleep(0.3)
    survivors = _group(tool_pid)
    assert [p for p in survivors if _alive(p)] == [], survivors
    assert not _alive(tool_pid)


def test_two_scans_in_one_worker_process_cancel_independently():
    """The scan worker runs ``-P threads``: cancelling one scan must not stop another running beside it."""
    marks = {"a": Mark(), "b": Mark()}
    done, stopped = [], []

    def make(key):
        @cancellable(lookup_factory=marks[key].factory)
        def scan(self):
            writer = StateUpdateWriter(self)
            for stage in range(8):
                writer.write_progress_percentage(stage)
                time.sleep(0.1)
            done.append(key)
        return scan

    def run(key):
        try:
            make(key)(FakeTask())
        except Ignore:
            stopped.append(key)

    threads = [threading.Thread(target=run, args=(k,)) for k in ("a", "b")]
    for t in threads:
        t.start()
    time.sleep(0.25)
    marks["a"].cancelled = True
    for t in threads:
        t.join(10)
    assert stopped == ["a"] and done == ["b"]


def test_a_scan_that_is_not_cancelled_returns_its_result():
    mark = Mark()

    @cancellable(lookup_factory=mark.factory)
    def scan(self, value):
        StateUpdateWriter(self).write_progress_percentage(50)
        out = run_tool([sys.executable, "-c", "print('ok')"], capture_output=True, text=True, timeout=30)
        return value, out.stdout.strip(), out.returncode

    assert scan(FakeTask(), 7) == (7, "ok", 0)
    assert cancellation.current_watch() is None


def test_a_tool_timeout_kills_its_children_too():
    pids = []
    real_popen = subprocess.Popen

    class Spy(real_popen):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            pids.append(self.pid)

    cancellation.subprocess.Popen = Spy
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_tool(TOOL, capture_output=True, text=True, timeout=1.5)
    finally:
        cancellation.subprocess.Popen = real_popen
    time.sleep(0.3)
    left = _group(pids[0])
    assert [p for p in left if _alive(p)] == [], left


def test_run_tool_keeps_subprocess_run_semantics():
    with pytest.raises(subprocess.CalledProcessError):
        run_tool([sys.executable, "-c", "raise SystemExit(3)"], check=True)
    out = run_tool([sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"], input="abc",
                   capture_output=True, text=True)
    assert out.stdout.strip() == "ABC" and out.returncode == 0


def test_a_mongo_outage_never_stops_a_scan():
    def broken():
        raise RuntimeError("mongo down")

    watch = CancelWatch(broken, interval=0.05)
    assert watch.poll() is False
    watch.check()  # does not raise


def test_every_scan_task_is_cancellable_and_tools_run_through_run_tool():
    """The five code scans (cancel) and the MCP and LLM runs (a reinitialize withdraws the queued run it replaces;
    backend tests/test_reinitialize_withdraws_every_type.py checks every type the backend sends)."""
    tree = ast.parse((WORKER / "scan_worker.py").read_text())
    decorated = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        and any(isinstance(d, ast.Name) and d.id == "cancellable" for d in node.decorator_list)
    }
    assert decorated == {"sast", "sbom_sca", "iac", "cbom", "ai_bom", "mcp_scan", "llm_benchmark_scan"}
    for rel in ("helpers/tools/sast_agent/semgrep_util.py", "helpers/tools/sca_sbom_agent/syft.py",
                "helpers/tools/sca_sbom_agent/grype.py", "helpers/tools/sca_sbom_agent/cdxgen_run.py",
                "helpers/tools/cbom_agent/binary_scanner.py"):
        src = (WORKER / rel).read_text()
        assert "subprocess.run(" not in src and "run_tool(" in src, rel
    assert issubclass(ScanCancelled, BaseException) and not issubclass(ScanCancelled, Exception)
