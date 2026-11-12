"""Floors: the lane's pass/fail rule.

* `non-regression`: today's numbers. Observed below the floor = FAIL.
* `target`: what a product track (CB-27, CB-28, CB-29) must reach; recorded as expected-fail. A target that is not
  met is EXPECTED-FAIL (fine). A target that is met is UNEXPECTED-PASS and fails the lane until the PR that met it
  turns the row into a non-regression floor (so the floors rise with the product and never silently lag).
* A floor whose metric cannot be computed (empty slice, bench not run, OSV not answered) is NOT-RUN and fails,
  unless the row says `not_run_ok` with a reason.
* Floors only rise (floorcheck.py, `d1.py check-floors`): a loosening carries a `lowered` record on its row, a floor
  that goes without a replacement a `removed` entry, each `{"reason", "pr"}`; report.md prints them.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import SCHEMA_FLOORS
from .judge import metrics, select
from .labels import LaneError

NUMERIC = ("recall", "precision", "specificity", "tp", "fp", "fn", "tn")
OPS = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, "==": lambda a, b: a == b,
       "superset": lambda a, b: set(a) >= set(b), "subset": lambda a, b: set(a) <= set(b)}


def load(path: Path) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("schema") != SCHEMA_FLOORS:
        raise LaneError(f"{path}: schema {doc.get('schema')!r}")
    ids = [f["id"] for f in doc["floors"]]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise LaneError(f"duplicate floor ids: {dup}")
    for f in doc["floors"]:
        if f["kind"] not in ("non-regression", "target") or f["op"] not in OPS:
            raise LaneError(f"floor {f['id']}: kind {f['kind']!r} / op {f['op']!r}")
        if f["kind"] == "target" and not f.get("owner"):
            raise LaneError(f"target floor {f['id']} names no owning track")
        if "lowered" in f and not _record_ok(f["lowered"]):
            raise LaneError(f"floor {f['id']}: lowered must be {{\"reason\": ..., \"pr\": ...}}, got {f['lowered']!r}")
    for r in doc.get("removed", []):
        if not (_record_ok(r) and isinstance(r.get("id"), str) and r["id"].strip()):
            raise LaneError(f"removed entries must be {{\"id\", \"reason\", \"pr\"}}, got {r!r}")
    return doc


def _record_ok(rec: object) -> bool:
    return isinstance(rec, dict) and all(isinstance(rec.get(k), str) and rec[k].strip() for k in ("reason", "pr"))


def observe(floor: dict, results: dict[str, list[dict]], extras: dict[str, list]) -> object:
    bench = floor["bench"]
    if bench not in results:
        return None
    rows = [r for r in select(results[bench], floor.get("where", {})) if r["vulnerable"] is not None]
    metric, mode = floor["metric"], floor.get("mode", "matched")
    if metric in NUMERIC:
        return metrics(rows, mode)[metric] if rows else None
    if metric == "flagged_ids":
        return sorted(r["case_id"] for r in rows if r[f"flagged_{mode}"]) if rows else None
    if metric == "fp_ids":
        return sorted(r["case_id"] for r in rows if not r["vulnerable"] and r[f"flagged_{mode}"]) if rows else None
    if metric == "extras":
        return sorted("|".join(str(x) for x in e) for e in extras.get(bench, [])) if bench in extras else None
    raise LaneError(f"floor {floor['id']}: unknown metric {metric!r}")


def evaluate(doc: dict, results: dict[str, list[dict]], extras: dict[str, list]) -> list[dict]:
    out = []
    for f in doc["floors"]:
        observed = observe(f, results, extras)
        if observed is None:
            status = "not-run-ok" if f.get("not_run_ok") else "not-run"
        else:
            met = OPS[f["op"]](observed, f["value"])
            if f["kind"] == "non-regression":
                status = "pass" if met else "fail"
            else:
                status = "unexpected-pass" if met else "expected-fail"
        out.append({**f, "observed": observed, "status": status})
    return out


def verdict(evaluated: list[dict]) -> str:
    return "fail" if any(e["status"] in ("fail", "unexpected-pass", "not-run") for e in evaluated) else "pass"
