"""Exit row F of CB-05: two gate runs on the same SHA must give identical verdicts.

    python3 -m harness.gate compare RUN_A RUN_B      exit 0 identical, 1 different, 2 error

Each run is a new customer, so the product's ids (team, run, job, asset, node, source) differ between runs. Check ids
are normalised to stable keys before comparing, using only the run's own evidence:
  * asset ids  -> "<type>@<location>" (api/assets-run<k>.json);
  * job ids    -> "<source name>" (api/assets-run<k>.json "targets", and the jobs' source names);
  * any other number that is a known id of the run (team, run, node) -> "<team>", "<run>", "<node>".
Two checks that normalise to the same id are compared as a sorted list of verdicts. The verdict compared is the
judged one (after the ledger: PASS, FAIL, KNOWN-FAIL(row), NOT-RUN, NOT-JUDGED); the ledger row statuses too.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .rundir import read_json

_NUM = re.compile(r"(?<![\w.])(\d+)(?![\w.])")


def id_maps(run: Path) -> dict[str, dict[str, str]]:
    run = Path(run)
    assets: dict[str, str] = {}
    jobs: dict[str, str] = {}
    for doc_path in sorted((run / "api").glob("assets-run*.json")):
        doc = read_json(doc_path) or {}
        for item in doc.get("items") or []:
            assets[str(item.get("id"))] = f"{item.get('type')}@{item.get('location')}"
        for job in doc.get("targets") or []:
            jobs[str(job.get("job_id"))] = f"job:{job.get('source_name')}"
    man = read_json(run / "MANIFEST.json", {}) or {}
    state = read_json(run / "flow-state.json", {}) or {}
    other: dict[str, str] = {}
    for key, team in (man.get("teams") or state.get("teams") or {}).items():
        other[str(team)] = f"team:{key}"
    for k, rid in enumerate(state.get("runs") or [], 1):
        other[str(rid)] = f"run:{k}"
    if (state.get("node") or {}).get("id"):
        other[str(state["node"]["id"])] = "node"
    return {"asset": assets, "job": jobs, "other": other}


def normalise(check_id: str, maps: dict[str, dict[str, str]]) -> str:
    out = re.sub(r"/asset/(\d+)/", lambda m: f"/asset/{maps['asset'].get(m.group(1), 'asset?')}/", check_id)
    out = re.sub(r"/extra/(\d+)$", lambda m: f"/extra/{maps['asset'].get(m.group(1), 'asset?')}", out)
    out = re.sub(r"job_(\d+)", lambda m: maps["job"].get(m.group(1), "job?"), out)
    out = re.sub(r"_(\d+)_skipped$", lambda m: f"_{maps['job'].get(m.group(1), 'job?')}_skipped", out)
    return _NUM.sub(lambda m: maps["other"].get(m.group(1), m.group(1)), out)


def verdicts(run: Path) -> tuple[dict[str, list[str]], dict[str, str]]:
    report = read_json(Path(run) / "report.json")
    if report is None:
        raise FileNotFoundError(f"{run}/report.json (judge the run first)")
    maps = id_maps(run)
    out: dict[str, list[str]] = defaultdict(list)
    for c in report.get("checks") or []:
        v = c["verdict"] + (f"({c['ledger_row']})" if c.get("ledger_row") and c["verdict"] == "KNOWN-FAIL" else "")
        out[normalise(c["id"], maps)].append(v)
    for k in out:
        out[k].sort()
    ledger = {r["row"]: r["status"] for r in report.get("ledger") or []}
    return dict(out), ledger


def compare(run_a: Path, run_b: Path) -> dict[str, Any]:
    va, la = verdicts(run_a)
    vb, lb = verdicts(run_b)
    diffs = []
    for key in sorted(set(va) | set(vb)):
        if va.get(key) != vb.get(key):
            diffs.append({"check": key, "a": va.get(key), "b": vb.get(key)})
    ledger_diffs = [{"row": r, "a": la.get(r), "b": lb.get(r)} for r in sorted(set(la) | set(lb)) if la.get(r) != lb.get(r)]
    ra = read_json(Path(run_a) / "report.json") or {}
    rb = read_json(Path(run_b) / "report.json") or {}
    return {"schema": "zs-cbom-compare/1", "a": Path(run_a).name, "b": Path(run_b).name,
            "identical": not diffs and not ledger_diffs and ra.get("passed") == rb.get("passed"),
            "passed": {"a": ra.get("passed"), "b": rb.get("passed")},
            "checks": {"a": sum(len(v) for v in va.values()), "b": sum(len(v) for v in vb.values()), "keys": len(set(va) | set(vb))},
            "differences": diffs, "ledger_differences": ledger_diffs}
