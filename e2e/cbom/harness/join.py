"""Per-row join keyed by the product's asset id: UI DOM <-> API <-> DB <-> export (G11, O-7).

Product self-consistency is necessary, never sufficient (O-1): oracle.py judges correctness separately. Here:
  * every asset id must be present in every view that was captured (``missing-in-<view>`` / ``extra-in-<view>``);
  * every field of the field map must agree between the API (the reference) and each other view;
  * a field the export does not carry at all while the API has a value is ``FAIL(export-missing)``, never a skip;
  * the provenance properties and ``zs:pqc_class`` must be present on every exported component.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import fieldmap as F
from .checks import Checks
from .rundir import read_csv, read_json, write_csv

GATE = "G11"
REF = re.compile(r"^zs-asset-(\d+)$")


def load_views(run: Path, k: str) -> dict[str, dict[int, dict[str, Any]] | None]:
    """The four views of run ``k`` keyed by asset id; a view that was not captured is None."""
    run = Path(run)
    api_doc = read_json(run / "api" / f"assets-run{k}.json")
    api = None if api_doc is None else {int(a["id"]): a for a in api_doc.get("items", [])}
    run_id = None if api_doc is None else api_doc.get("run_id")
    db_rows = read_csv(run / "db" / "assets.csv") if (run / "db" / "assets.csv").is_file() else None
    db = None
    if db_rows is not None:
        db = {int(r["id"]): r for r in db_rows if run_id is None or str(r.get("run_id")) == str(run_id)}
    exp_doc = read_json(run / "exports" / f"run{k}.cdx.json")
    export = None
    if exp_doc is not None:
        export = {}
        for comp in exp_doc.get("components") or []:
            m = REF.match(str(comp.get("bom-ref", "")))
            if m:
                export[int(m.group(1))] = comp
    ui_doc = read_json(run / "ui" / f"assets-run{k}.json")
    ui = None if ui_doc is None else {int(r["id"]): r for r in ui_doc.get("rows", [])}
    return {"api": api, "db": db, "export": export, "ui": ui}


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _show(value: Any) -> Any:
    if value is F.MISSING:
        return "<absent>"
    return value


def join(run: Path, k: str, checks: Checks) -> list[dict[str, Any]]:
    """Judge run ``k``; return the long-format diff rows (one per asset x field) written to diff/assets-run<k>.csv."""
    views = load_views(run, k)
    api = views["api"]
    diff: list[dict[str, Any]] = []
    prefix = f"{GATE}/join/run{k}"
    if api is None:
        checks.not_run(f"{prefix}/api", GATE, "join", "api/assets-run%s.json not captured" % k,
                       {"run": k, "view": "api"})
        return diff
    for view in ("db", "export", "ui"):
        if views[view] is None:
            checks.not_run(f"{prefix}/{view}", GATE, "join", f"view {view} not captured", {"run": k, "view": view})

    # presence: the same ids in every captured view
    for view in ("db", "export", "ui"):
        other = views[view]
        if other is None:
            continue
        missing = sorted(set(api) - set(other))
        extra = sorted(set(other) - set(api))
        for aid in missing:
            checks.fail(f"{prefix}/asset/{aid}/presence/{view}", GATE, "join", f"missing-in-{view}",
                        _subject(k, aid, api[aid], "presence", view), expected="present", observed="absent")
        for aid in extra:
            checks.fail(f"{prefix}/asset/{aid}/presence/{view}", GATE, "join", f"extra-in-{view}",
                        {"kind": "join", "run": k, "asset_id": aid, "field": "presence", "view": view},
                        expected="absent (not served by the API)", observed="present")
        checks.verdict(f"{prefix}/count/{view}", GATE, "join", not missing and not extra, "count-mismatch",
                       {"run": k, "field": "count", "view": view}, expected=len(api), observed=len(other))

    for aid, item in sorted(api.items()):
        row_diff: dict[str, dict[str, Any]] = {}
        for field, readers in F.FIELDS.items():
            if "api" not in readers:
                continue
            for view in ("db", "export"):
                other = (views[view] or {}).get(aid)
                if other is None or view not in readers:
                    continue
                a = F.run_verdict(item, field) if (view == "db" and field in F.RUN_VERDICT_FIELDS) else \
                    F.view_value(field, "api", item)
                o = F.view_value(field, view, other)
                row_diff.setdefault(field, {"api": a})[view] = _show(o)
                cid = f"{prefix}/asset/{aid}/{field}/{view}"
                subject = _subject(k, aid, item, field, view)
                if o is F.MISSING:
                    if view == "export" and not _is_empty(a):
                        checks.fail(cid, GATE, "join", "export-missing", subject, expected=a, observed="<absent>")
                    continue
                if field == "protocol" and view == "export":
                    a_cmp, o_cmp = F.protocol_family(a), (None if _is_empty(o) else str(o))
                else:
                    a_cmp, o_cmp = F.view_eq(field, a), F.view_eq(field, o)
                checks.verdict(cid, GATE, "join", a_cmp == o_cmp, "mismatch", subject, expected=a, observed=o)
        comp = (views["export"] or {}).get(aid)
        if comp is not None:
            p = F.props(comp)
            for field, prop in F.EXPORT_ALWAYS.items():
                cid = f"{prefix}/asset/{aid}/{field}/export"
                checks.verdict(cid, GATE, "join", prop in p, "export-missing", _subject(k, aid, item, field, "export"),
                               expected=f"{prop} present", observed=p.get(prop, "<absent>"))
                row_diff.setdefault(field, {"api": None})["export"] = p.get(prop, ["<absent>"])[0]
            absent = [name for name in F.PROVENANCE_PROPS if name not in p]
            checks.verdict(f"{prefix}/asset/{aid}/provenance/export", GATE, "join", not absent, "export-missing",
                           _subject(k, aid, item, "provenance", "export"), expected=list(F.PROVENANCE_PROPS),
                           observed={"absent": absent})
            row_diff.setdefault("provenance", {"api": item.get("job_id")})["export"] = (
                "absent: " + ",".join(absent)) if absent else "present"
        ui_row = (views["ui"] or {}).get(aid)
        if ui_row is not None:
            for field in F.UI_FIELDS:
                want, got = F.ui_expected(field, item), F.ui_observed(field, ui_row)
                row_diff.setdefault(f"ui:{field}", {"api": want})["ui"] = _show(got)
                checks.verdict(f"{prefix}/asset/{aid}/{field}/ui", GATE, "join", want == got, "mismatch",
                               _subject(k, aid, item, field, "ui"), expected=want, observed=_show(got))
        for field, cells in row_diff.items():
            diff.append({"asset_id": aid, "asset_type": item.get("type"), "location": item.get("location"),
                         "field": field, "api": _cell(cells.get("api")), "db": _cell(cells.get("db")),
                         "export": _cell(cells.get("export")), "ui": _cell(cells.get("ui"))})
    write_csv(Path(run) / "diff" / f"assets-run{k}.csv", diff,
              ["asset_id", "asset_type", "location", "field", "api", "db", "export", "ui"])
    return diff


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _subject(k: str, aid: int, item: dict[str, Any], field: str, view: str) -> dict[str, Any]:
    return {"kind": "join", "run": k, "asset_id": aid, "asset_type": item.get("type"),
            "location": item.get("location"), "field": field, "view": view}
