"""The never-scan verdict re-derived from the sealed evidence (review 5878413538, minor on gate.mjs G10).

The flow counts listener lines once, right after the jobs end (steps/G10/step.json). The listeners keep logging until
the lab goes down, so a late connection (a retry, a re-probe, a job still running during G11-G14) reaches the sealed
bundle after that count. The judge therefore recounts over the whole sealed file, with the flow's own rules (O-8,
INTERFACES v7 §A.4): a listener is in scope when an address range the customer configured contains it
(flow-state ``scope.ranges``); only lines whose peer is the node (flow-state ``node.addresses``) and whose time is at
or after G9 "Start scan" (flow-state ``g9_start``) are the node's.

  G10/sealed/canary_accepts/<name>   0 node lines in the whole file (the never-scan zero assertion)
  G10/sealed/control_accepts/<name>  >= 1 node line (its positive control: the node scanned the range)
  G10/sealed/canary_log_path/<name>  >= 1 line from another peer after Start (the harness's probe: the log path works)
A missing listener log is FAIL(listener-log-missing), never zero.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

from .checks import Checks
from .rundir import parse_ts, read_json

GATE = "G10"


def _lines(path: Path) -> list[dict[str, Any]] | None:
    if not path.is_file():
        return None
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if isinstance(doc, dict):
            out.append(doc)
    return out


def _in(address: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def judge(run: Path, checks: Checks) -> dict[str, Any]:
    run = Path(run)
    lab = read_json(run / "lab" / "lab.json") or {}
    state = read_json(run / "flow-state.json") or {}
    out: dict[str, Any] = {}
    ranges = list((state.get("scope") or {}).get("ranges") or [])
    node_ips = {str(a) for a in ((state.get("node") or {}).get("addresses") or [])}
    start = parse_ts(state.get("g9_start"))
    listeners = [x for x in lab.get("listeners") or [] if x.get("role") in ("canary", "control") and _in(x.get("address"), ranges)]
    if not listeners:
        return out
    if start is None or not node_ips:
        checks.not_run(f"{GATE}/sealed", GATE, "neverscan", "no G9 start or node address in flow-state.json",
                       {"check": "sealed_listener_counts"})
        return out
    for lst in listeners:
        name, role = str(lst.get("name")), lst.get("role")
        rel = lst.get("log") or f"lab/listeners/{name}.jsonl"
        lines = _lines(run / rel)
        after = [x for x in (lines or []) if (parse_ts(x.get("ts")) or start) >= start]
        node = [x for x in after if str(x.get("peer", "")).rsplit(":", 1)[0] in node_ips]
        other = [x for x in after if x not in node]
        out[name] = {"lines": None if lines is None else len(lines), "node_after_start": len(node),
                     "other_after_start": len(other)}
        subject = {"kind": "neverscan", "listener": name, "role": role}
        missing = lines is None
        if role == "canary":
            checks.verdict(f"{GATE}/sealed/canary_accepts/{name}", GATE, "neverscan", not missing and not node,
                           "listener-log-missing" if missing else "never-scan-reached",
                           {**subject, "check": "sealed_canary_accepts"},
                           expected="0 connections from the node after Start, over the whole sealed log",
                           observed={"from_node": None if missing else [x.get("ts") for x in node][:20]},
                           evidence=[rel])
            checks.verdict(f"{GATE}/sealed/canary_log_path/{name}", GATE, "neverscan", not missing and bool(other),
                           "listener-log-missing" if missing else "log-path",
                           {**subject, "check": "sealed_canary_log_path"},
                           expected=">= 1 line from the harness's probe after Start (the log path works, O-8)",
                           observed={"other_peers_after_start": None if missing else len(other)}, evidence=[rel])
        else:
            checks.verdict(f"{GATE}/sealed/control_accepts/{name}", GATE, "neverscan", not missing and bool(node),
                           "listener-log-missing" if missing else "control-not-reached",
                           {**subject, "check": "sealed_control_accepts"},
                           expected=">= 1 connection from the node after Start (positive control)",
                           observed={"from_node": None if missing else len(node)}, evidence=[rel])
    return out
