"""O-10 (judgement day) and the run's timestamps (m2).

The window is the customer's own clock: from G9 "Start scan" (``steps/G9/step.json`` ``started``) to the end of the
last step that read the run (G12, else G11, else G10), plus ``SLACK`` for clock offset between the host and the stack.
* every asset row the DB stored for the run was created inside [G9 start, G10 end + slack];
* the export's ``metadata.timestamp`` and every ``zs:collected_at`` (CB-06) fall inside the window, on G9's UTC day;
* ``zs:judged_on`` (a date-based rule changed a verdict since the run) is absent, or each component carrying
  ``zs:run_impact`` agrees with the DB's stored impact (the run's own verdict).
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from . import fieldmap as F
from .checks import Checks
from .rundir import parse_ts, read_csv, read_json

SLACK = dt.timedelta(seconds=120)


def _step_time(run: Path, step: str, key: str) -> dt.datetime | None:
    doc = read_json(Path(run) / "steps" / step / "step.json") or {}
    return parse_ts(doc.get(key))


def window(run: Path) -> tuple[dt.datetime | None, dt.datetime | None]:
    start = _step_time(run, "G9", "started")
    end = next((t for t in (_step_time(run, s, "ended") for s in ("G12", "G11", "G10")) if t), None)
    return start, end


def judge(run: Path, k: str, checks: Checks) -> dict[str, Any]:
    run = Path(run)
    start, end = window(run)
    out: dict[str, Any] = {"start": start and start.isoformat(), "end": end and end.isoformat()}
    if start is None or end is None:
        checks.not_run(f"G12/timestamps/run{k}", "G12", "timing", "no G9 start or flow end recorded",
                       {"check": "timestamps", "run": k})
        return out
    lo, hi = start - SLACK, end + SLACK
    api = read_json(run / "api" / f"assets-run{k}.json") or {}
    run_id = api.get("run_id")
    rows = [r for r in read_csv(run / "db" / "assets.csv") if run_id is None or str(r.get("run_id")) == str(run_id)]
    created = [parse_ts(r.get("created_at")) for r in rows]
    bad = sorted({r["id"] for r, t in zip(rows, created) if t is None or not lo <= t <= (
        (_step_time(run, "G10", "ended") or end) + SLACK)})
    if rows:
        checks.verdict(f"G11/db_created_in_run_window/run{k}", "G11", "timing", not bad, "outside-run-window",
                       {"check": "db_created_in_run_window", "run": k},
                       expected=f"created_at in [{lo.isoformat()}, G10 end]", observed={"asset_ids": bad[:20]})
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
    checks.verdict(f"G12/serial_number/run{k}", "G12", "timing", serial.startswith("urn:uuid:") and len(serial) == 45,
                   "serial-missing", {"check": "serial_number", "run": k}, expected="urn:uuid:<uuid>", observed=serial)
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
