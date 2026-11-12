"""A DAST run the backend withdrew while it was queued is never started (helpers/cancel_mark.py).

The backend withdraws the queued run a reinitialize replaces with a revoke AND a mark in the result backend's Mongo
database (``scan_cancellations``, ``_id`` = task id). A revoke is lost when no worker is up, on a restart and after
3 h; on e13e24f the DAST task ignored the mark, so a withdrawn run still ran once a worker picked it up.
"""
from __future__ import annotations

import ast
import types
from pathlib import Path

import pytest
from celery.exceptions import Ignore

from helpers.cancel_mark import CANCEL_COLLECTION, skip_if_withdrawn, withdrawn

WORKER = Path(__file__).resolve().parents[2]


class _Marks:
    def __init__(self, ids=(), broken=False):
        self.ids, self.broken = set(ids), broken

    def find_one(self, flt, _projection=None):
        if self.broken:
            raise RuntimeError("mongo down")
        return {"_id": flt["_id"]} if flt["_id"] in self.ids else None


class _Task:
    def __init__(self, task_id, marks):
        self.request = types.SimpleNamespace(id=task_id)
        self.revoked = []
        self.backend = types.SimpleNamespace(
            database={CANCEL_COLLECTION: marks},
            mark_as_revoked=lambda tid, reason, request=None: self.revoked.append((tid, reason)))


def test_a_withdrawn_run_is_never_started_and_is_recorded_as_revoked():
    ran = []

    @skip_if_withdrawn
    def dast(self, dast_dict_context):
        ran.append(self.request.id)

    task = _Task("old-run", _Marks({"old-run"}))
    with pytest.raises(Ignore):
        dast(task, dast_dict_context={"target_url": "https://app.example/"})
    assert ran == [] and task.revoked == [("old-run", "withdrawn by the backend")]


def test_a_run_that_was_not_withdrawn_runs_and_returns_its_result():
    @skip_if_withdrawn
    def dast(self, dast_dict_context):
        return {"results": [], "target": dast_dict_context["target_url"]}

    task = _Task("new-run", _Marks({"old-run"}))
    assert dast(task, dast_dict_context={"target_url": "https://app.example/"})["target"] == "https://app.example/"
    assert task.revoked == []


def test_a_mongo_outage_lets_the_scan_run():
    assert withdrawn(_Task("any", _Marks(broken=True))) is False
    assert withdrawn(_Task(None, _Marks({"x"}))) is False


def test_the_dast_task_is_wired_to_it():
    tree = ast.parse((WORKER / "dast_worker.py").read_text())
    (dast,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "dast"]
    names = [d.id for d in dast.decorator_list if isinstance(d, ast.Name)]
    assert names == ["skip_if_withdrawn"]
    assert any(isinstance(n, ast.ImportFrom) and n.module == "helpers.cancel_mark"
               and any(a.name == "skip_if_withdrawn" for a in n.names) for n in tree.body)
