"""Every scan run the backend can withdraw honours the withdrawal mark (#57 review: security major, AC 8).

A reinitialize withdraws the queued run it replaces with ``tell_workers`` (utilities/scan/cancel_scan.py): a Celery
``revoke`` and a mark in the result backend's Mongo database (``scan_cancellations``, ``_id`` = task id). A revoke lives
only in a running worker's memory: it is lost when no worker is up (the "stuck in the queue" case reinitialize exists
for), on a worker restart, and after 3 hours (celery REVOKE_EXPIRES). So the run is only really withdrawn when its task
reads the mark before it starts. On e13e24f the MCP, LLM and DAST tasks did not, and their replaced runs still ran.

* For EVERY scan type a reinitialize can send (``start_scan.SCAN_TASKS``), the worker source defines that task with a
  decorator that reads the mark: ``cancellable`` (scan worker, helpers/context/cancellation.py) or ``skip_if_withdrawn``
  (DAST worker, helpers/cancel_mark.py), imported from those modules. A new type added without it fails here.
* Both decorators, loaded from the worker trees, skip a marked task (Celery ``Ignore``, the body never runs, the task
  recorded as revoked) and run an unmarked one; they read the collection the backend writes.
* ``tell_workers`` writes that mark for every run a scan's task id stands for (a reinitialize claim stands for two).

The real-broker proof (RabbitMQ + Mongo + the worker images, workers down during the reinitialize): round6/t2/r7/broker.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import types
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.scan import cancel_scan  # noqa: E402
from backend.utilities.scan.start_scan import SCAN_TASKS  # noqa: E402

# The worker module a task name's prefix is registered from (``celery -A <module>``), and the mark-honouring
# decorator each module must apply, with the module the decorator has to come from.
WORKERS = {
    "scan_worker": (_REPO_ROOT / "RabbitMQ/worker/scan_worker.py", "cancellable", "helpers.context.cancellation"),
    "dast_worker": (_REPO_ROOT / "RabbitMQ/dast_worker/dast_worker.py", "skip_if_withdrawn", "helpers.cancel_mark"),
}
CANCELLATION = _REPO_ROOT / "RabbitMQ/worker/helpers/context/cancellation.py"
CANCEL_MARK = _REPO_ROOT / "RabbitMQ/dast_worker/helpers/cancel_mark.py"


def _celery_tasks(path: Path) -> dict[str, list[str]]:
    """{function name: names of its decorators} for every function decorated with ``app.task(...)``."""
    tasks = {}
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.FunctionDef):
            continue
        names = []
        is_task = False
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(target, ast.Attribute) and target.attr == "task":
                is_task = True
            elif isinstance(target, ast.Name):
                names.append(target.id)
        if is_task:
            tasks[node.name] = names
    return tasks


def _decorator_source(path: Path, name: str) -> str | None:
    """Where ``name`` comes from in the worker module: the module it is imported from (directly, or through a module
    level ``name = imported(...)``)."""
    tree = ast.parse(path.read_text())
    imported = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = node.module
    if name in imported:
        return imported[name]
    for node in tree.body:
        if (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
                and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)):
            return imported.get(node.value.func.id)
    return None


@pytest.mark.parametrize("scan_type", sorted(SCAN_TASKS))
def test_every_reinitializable_type_runs_a_task_that_honours_the_withdrawal_mark(scan_type):
    task_name, _queue = SCAN_TASKS[scan_type]
    module, _sep, function = task_name.partition(".")
    assert module in WORKERS, f"{scan_type}: {task_name} is in no known worker; add it to WORKERS with its mark check"
    path, decorator, source = WORKERS[module]
    tasks = _celery_tasks(path)
    assert function in tasks, f"{scan_type}: {path.name} defines no Celery task {function!r}"
    assert decorator in tasks[function], (
        f"{scan_type}: {task_name} ignores the withdrawal mark (decorators {tasks[function]}): a reinitialize's "
        f"replaced run would still run when the revoke is lost. Decorate it with @{decorator}.")
    assert _decorator_source(path, decorator) == source, f"{decorator} in {path.name} must come from {source}"


def test_the_reinitialize_route_only_sends_the_types_checked_here():
    from backend.utilities.scan import reinitialize

    assert reinitialize.SCAN_TASKS is SCAN_TASKS


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class _Collection:
    def __init__(self, ids):
        self.ids, self.asked = set(ids), []

    def find_one(self, flt, _projection=None):
        self.asked.append(flt["_id"])
        return {"_id": flt["_id"]} if flt["_id"] in self.ids else None


class _Task:
    """A bound Celery task as the decorators see it: request.id, and the result backend (Mongo database + revoke)."""

    def __init__(self, task_id, marked):
        self.request = types.SimpleNamespace(id=task_id)
        self.marks = _Collection(marked)
        self.revoked = []
        self.backend = types.SimpleNamespace(
            database={cancel_scan.CANCEL_COLLECTION: self.marks},
            mark_as_revoked=lambda tid, reason, request=None: self.revoked.append(tid))


def _decorators():
    canc = _load(CANCELLATION, "zs_worker_cancellation")
    mark = _load(CANCEL_MARK, "zs_dast_cancel_mark")
    assert canc.CANCEL_COLLECTION == mark.CANCEL_COLLECTION == cancel_scan.CANCEL_COLLECTION
    return {"cancellable": canc.cancellable(on_skip=lambda _kw: None), "skip_if_withdrawn": mark.skip_if_withdrawn}


@pytest.mark.parametrize("decorator", ["cancellable", "skip_if_withdrawn"])
def test_a_marked_run_never_starts_and_an_unmarked_one_runs(decorator):
    from celery.exceptions import Ignore

    wrap = _decorators()[decorator]
    ran = []

    @wrap
    def scan(self, **kwargs):
        ran.append(self.request.id)
        return {"results": []}

    withdrawn = _Task("old-run", marked={"old-run"})
    with pytest.raises(Ignore):
        scan(withdrawn, mcp_dict_context={})
    assert ran == [] and withdrawn.revoked == ["old-run"] and withdrawn.marks.asked[:1] == ["old-run"]

    fresh = _Task("new-run", marked={"old-run"})
    assert scan(fresh, mcp_dict_context={}) == {"results": []}
    assert ran == ["new-run"] and fresh.revoked == []


def test_withdrawing_a_claim_marks_both_of_its_runs(monkeypatch):
    from backend.utilities.celery import celery_connection
    from backend.utilities.scan import claim_token

    marks, revoked = {}, []
    app = types.SimpleNamespace(
        control=types.SimpleNamespace(revoke=lambda tid, **_k: revoked.append(tid)),
        backend=types.SimpleNamespace(database={cancel_scan.CANCEL_COLLECTION: types.SimpleNamespace(
            update_one=lambda flt, _upd, upsert=False: marks.setdefault(flt["_id"], upsert))}))
    monkeypatch.setattr(celery_connection, "get_celery_app", lambda: app)
    cancel_scan.tell_workers(claim_token.make("new-run", "old-run"))
    assert revoked == ["new-run", "old-run"] and marks == {"new-run": True, "old-run": True}
    cancel_scan.tell_workers("plain-run")
    assert revoked[-1] == "plain-run" and "plain-run" in marks
