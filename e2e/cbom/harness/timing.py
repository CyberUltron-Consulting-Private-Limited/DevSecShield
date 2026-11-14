"""O-10 (judgement day) and the run's timestamps (m2).

The window is the customer's own clock: from G9 "Start scan" (``steps/G9/step.json`` ``started``) to the end of the
last step that read the run (G12, else G11, else G10), plus ``SLACK`` for clock offset between the host and the stack;
run 2 (G13 "Run again", CB-05) uses the G13 step's own start and end.
* every asset row the DB stored for the run was created inside [G9 start, G10 end + slack] (no row for the run is
  NOT-RUN, never a silent pass);
* the run's own record (API ``run-<id>.json``, DB ``runs.csv``) and its jobs (``jobs.csv``) were created, claimed and
  finished inside the same window: the customer reads those dates in Review & Run;
* the export's ``metadata.timestamp`` and every ``zs:collected_at`` (CB-06) fall inside the window, on G9's UTC day;
* the export's ``serialNumber`` is an RFC 4122 UUID URN, not the nil UUID, and differs between the runs of the gate
  run and from every other BOM of the same team in the sibling bundles (CycloneDX: unique per BOM);
* ``zs:judged_on`` (a date-based rule changed a verdict since the run) is absent, or each component carrying
  ``zs:run_impact`` agrees with the DB's stored impact (the run's own verdict).
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any

from . import fieldmap as F
from .checks import Checks
from .rundir import parse_ts, read_csv, read_json

SLACK = dt.timedelta(seconds=120)
UUID_URN = re.compile(r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
NIL_URN = "urn:uuid:00000000-0000-0000-0000-000000000000"


def _step_time(run: Path, step: str, key: str) -> dt.datetime | None:
    doc = read_json(Path(run) / "steps" / step / "step.json") or {}
    return parse_ts(doc.get(key))


def window(run: Path, k: str = "1") -> tuple[dt.datetime | None, dt.datetime | None]:
    """Run 1: G9 Start .. the last step that read it. Run 2 (CB-05's G13 "Run again"): the G13 step itself."""
    if str(k) != "1":
        return _step_time(run, "G13", "started"), _step_time(run, "G13", "ended")
    start = _step_time(run, "G9", "started")
    end = next((t for t in (_step_time(run, s, "ended") for s in ("G12", "G11", "G10")) if t), None)
    return start, end


def _product_run_id(run: Path, k: str) -> str | None:
    api = read_json(Path(run) / "api" / f"assets-run{k}.json") or {}
    if api.get("run_id") is not None:
        return str(api["run_id"])
    runs = (read_json(Path(run) / "flow-state.json") or {}).get("runs") or []
    return str(runs[int(k) - 1]) if 0 < int(k) <= len(runs) else None


def _record_times(run: Path, run_id: str | None) -> dict[str, dt.datetime | None]:
    """The run's own dates as the product serves (API) and stores (DB) them, and its jobs' dates (DB)."""
    out: dict[str, dt.datetime | None] = {}
    if run_id is None:
        return out
    doc = (read_json(Path(run) / "api" / f"run-{run_id}.json") or {}).get("run") or {}
    for key in ("created_at", "finished_at"):
        if key in doc:
            out[f"api.run.{key}"] = parse_ts(doc[key])
    for row in read_csv(Path(run) / "db" / "runs.csv"):
        if str(row.get("id")) == run_id:
            for key in ("created_at", "finished_at"):
                out[f"db.runs.{key}"] = parse_ts(row.get(key))
    for row in read_csv(Path(run) / "db" / "jobs.csv"):
        if str(row.get("run_id")) == run_id:
            for key in ("created_at", "claimed_at", "finished_at"):
                if row.get(key):
                    out[f"db.jobs.{row.get('id')}.{key}"] = parse_ts(row.get(key))
    return out


def _sibling_serials(run: Path, teams: set[str], run_id: str | None) -> dict[str, str]:
    """serialNumber -> bundle name, for the other gate bundles next to this one that judged a run of the same team."""
    out: dict[str, str] = {}
    for man_path in sorted(Path(run).parent.glob("*/MANIFEST.json")):
        if man_path.parent.resolve() == Path(run).resolve():
            continue
        man = read_json(man_path, {}) or {}
        if not teams & {str(t) for t in (man.get("teams") or {}).values()}:
            continue
        their_runs = [str(r) for r in man.get("runs") or []]
        for i, serial in (man.get("serialNumbers") or {}).items():
            rid = their_runs[int(i) - 1] if str(i).isdigit() and 0 < int(i) <= len(their_runs) else None
            if rid != run_id:  # the same product run downloaded again is the same BOM
                out[str(serial)] = man_path.parent.name
    return out


def judge(run: Path, k: str, checks: Checks) -> dict[str, Any]:
    run = Path(run)
    start, end = window(run, k)
    out: dict[str, Any] = {"start": start and start.isoformat(), "end": end and end.isoformat()}
    if start is None or end is None:
        checks.not_run(f"G12/timestamps/run{k}", "G12", "timing", "no G9 start or flow end recorded",
                       {"check": "timestamps", "run": k})
        return out
    lo, hi = start - SLACK, end + SLACK
    run_id = _product_run_id(run, k)
    rows = [r for r in read_csv(run / "db" / "assets.csv") if run_id is None or str(r.get("run_id")) == str(run_id)]
    created = [parse_ts(r.get("created_at")) for r in rows]
    stored_by = ((_step_time(run, "G10", "ended") or end) if str(k) == "1" else end) + SLACK
    bad = sorted({r["id"] for r, t in zip(rows, created) if t is None or not lo <= t <= stored_by})
    if rows:
        checks.verdict(f"G11/db_created_in_run_window/run{k}", "G11", "timing", not bad, "outside-run-window",
                       {"check": "db_created_in_run_window", "run": k},
                       expected=f"created_at in [{lo.isoformat()}, G10 end]", observed={"asset_ids": bad[:20]})
    else:
        checks.not_run(f"G11/db_created_in_run_window/run{k}", "G11", "timing",
                       "no DB asset row for the run (db/assets.csv absent or empty)",
                       {"check": "db_created_in_run_window", "run": k})
    record = _record_times(run, run_id)
    if record:
        outside_rec = sorted(name for name, t in record.items() if t is None or not lo <= t <= stored_by)
        checks.verdict(f"G11/run_record_in_run_window/run{k}", "G11", "timing", not outside_rec, "outside-run-window",
                       {"check": "run_record_in_run_window", "run": k},
                       expected=f"run and job created/claimed/finished in [{lo.isoformat()}, {stored_by.isoformat()}]",
                       observed={name: (record[name].isoformat() if record[name] else None) for name in outside_rec})
    else:
        checks.not_run(f"G11/run_record_in_run_window/run{k}", "G11", "timing",
                       "no run record captured (api/run-<id>.json, db/runs.csv, db/jobs.csv)",
                       {"check": "run_record_in_run_window", "run": k})
    doc = read_json(run / "exports" / f"run{k}.cdx.json")
    if doc is None:
        checks.not_run(f"G12/timestamps_on_run_day/run{k}", "G12", "timing", "no export captured",
                       {"check": "timestamps_on_run_day", "run": k})
        return out
    meta_ts = parse_ts((doc.get("metadata") or {}).get("timestamp"))
    collected = []
    for comp in doc.get("components") or []:
        for value in F.props(comp).get("zs:collected_at", []):
            collected.append((comp.get("bom-ref"), parse_ts(value)))
    outside = [ref for ref, t in collected if t is None or not lo <= t <= hi or t.date() != start.date()]
    ok_meta = meta_ts is not None and lo <= meta_ts <= hi and meta_ts.date() == start.date()
    checks.verdict(f"G12/timestamps_on_run_day/run{k}", "G12", "timing", ok_meta and not outside,
                   "outside-run-window", {"check": "timestamps_on_run_day", "run": k},
                   expected=f"metadata.timestamp and zs:collected_at in [{lo.isoformat()}, {hi.isoformat()}] "
                            f"on {start.date().isoformat()} (O-10)",
                   observed={"metadata.timestamp": (doc.get("metadata") or {}).get("timestamp"),
                             "collected_at_outside": outside[:10], "collected_at_seen": len(collected)})
    serial = str(doc.get("serialNumber") or "")
    others = {kk: str((read_json(run / "exports" / f"run{kk}.cdx.json") or {}).get("serialNumber") or "")
              for kk in _other_runs(run, k)}
    teams = {str(t) for t in ((read_json(run / "MANIFEST.json", {}) or {}).get("teams") or {}).values()}
    siblings = _sibling_serials(run, teams, run_id) if teams else {}
    problems = []
    if not UUID_URN.match(serial.lower()):
        problems.append("not an RFC 4122 urn:uuid")
    if serial.lower() == NIL_URN:
        problems.append("the nil UUID (one constant serial in every BOM)")
    problems += [f"same as run {kk}'s export" for kk, s in others.items() if s and s == serial]
    if serial in siblings:
        problems.append(f"same as a BOM of this team in bundle {siblings[serial]}")
    reason = "serial-missing" if not serial else "serial-not-unique" if any(p.startswith("same as") for p in problems) \
        else "serial-invalid"
    checks.verdict(f"G12/serial_number/run{k}", "G12", "timing", not problems, reason, {"check": "serial_number", "run": k},
                   expected="urn:uuid:<RFC 4122 UUID>, not nil, unique per BOM", observed={"serial": serial,
                                                                                         "problems": problems})
    out["serialNumber"] = serial
    # zs:judged_on: the export re-judged a date rule since the run; its zs:run_impact must be the DB's stored verdict
    db_impact = {str(r["id"]): (r.get("impact") or None) for r in rows}
    disagree = []
    for comp in doc.get("components") or []:
        p = F.props(comp)
        if "zs:run_impact" not in p:
            continue
        aid = str(comp.get("bom-ref", "")).rsplit("-", 1)[-1]
        if F.view_eq("impact", p["zs:run_impact"][0]) != F.view_eq("impact", db_impact.get(aid)):
            disagree.append(aid)
    checks.verdict(f"G12/run_verdict_eq_db/run{k}", "G12", "timing", not disagree, "mismatch",
                   {"check": "run_verdict_eq_db", "run": k},
                   expected="zs:run_impact == DB impact wherever zs:judged_on re-judged a row", observed=disagree)
    return out


def _other_runs(run: Path, k: str) -> list[str]:
    return sorted(p.name[len("run"):-len(".cdx.json")] for p in (Path(run) / "exports").glob("run*.cdx.json")
                  if p.name != f"run{k}.cdx.json")
