"""Derived numbers (O-6): recomputed from the oracle, never taken from another product view.

Two layers:
  * facets   the counts the run page shows (total, by type, by impact, quantum-vulnerable) recomputed from the rows the
             API served; a facet that does not add up is a product bug even before any oracle is consulted;
  * oracle   for closed-world targets, the number of assets by type and the quantum-vulnerable count recomputed from
             the oracle and compared with what the product stored for those targets.
Posture numbers (readiness %, HNDL, Mosca, heat-map, calendar) need the oracle's PQC classes and the signed Q-grade
formula (OA-10a); until CB-05/CB-18 define them they are NOT-RUN (and ledgered).
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from . import fieldmap as F
from .checks import Checks
from .oracle import belongs, in_scope, load_oracle
from .rundir import read_json, write_json

GATE = "G11"


def judge(run: Path, k: str, checks: Checks, pairs: dict[str, int] | None = None,
          scope: dict[str, Any] | None = None) -> dict[str, Any]:
    prefix = f"{GATE}/derived/run{k}"
    doc = read_json(Path(run) / "api" / f"assets-run{k}.json")
    out: dict[str, Any] = {}
    if doc is None:
        checks.not_run(prefix, GATE, "derived", "api assets not captured", {"run": k})
        return out
    items = doc.get("items") or []
    facets = doc.get("facets") or {}
    by_type = Counter(i.get("type") for i in items)
    by_impact = Counter(i.get("impact") or "none" for i in items)
    quantum = sum(1 for i in items if i.get("quantum_vulnerable") is True)
    out["facets_recomputed"] = {"total": len(items), "type": dict(by_type), "impact": dict(by_impact),
                                "quantum_vulnerable": quantum}
    out["facets_served"] = {"total": doc.get("all_total"), **facets}
    s = {"kind": "derived", "run": k}
    checks.verdict(f"{prefix}/total", GATE, "derived", doc.get("all_total") == len(items), "mismatch",
                   {**s, "field": "total"}, expected=len(items), observed=doc.get("all_total"))
    checks.verdict(f"{prefix}/by_type", GATE, "derived", dict(by_type) == dict(facets.get("type") or {}), "mismatch",
                   {**s, "field": "type"}, expected=dict(by_type), observed=facets.get("type"))
    checks.verdict(f"{prefix}/by_impact", GATE, "derived", dict(by_impact) == dict(facets.get("impact") or {}),
                   "mismatch", {**s, "field": "impact"}, expected=dict(by_impact), observed=facets.get("impact"))
    checks.verdict(f"{prefix}/quantum", GATE, "derived", quantum == facets.get("quantum_vulnerable"), "mismatch",
                   {**s, "field": "quantum_vulnerable"}, expected=quantum, observed=facets.get("quantum_vulnerable"))

    oracle = load_oracle(run, k)
    if oracle is None:
        checks.not_run(f"{prefix}/oracle", GATE, "derived", "no oracle", {**s, "field": "oracle"})
    else:
        # closed-world targets in this run's scope: assets by type, from the oracle vs what the product stored there;
        # quantum-vulnerable count over the oracle assets that state it vs their matched product assets
        want_type: Counter = Counter()
        got_type: Counter = Counter()
        want_q = got_q = 0
        by_id = {i.get("id"): i for i in items}
        for target in oracle.get("targets") or []:
            if target.get("world", "closed") != "closed" or not in_scope(target, scope):
                continue
            for asset in target.get("assets") or []:
                want_type[asset.get("asset_type")] += 1
                qv = F.norm_bool((asset.get("expect") or {}).get("quantum_vulnerable"))
                if qv is True:
                    want_q += 1
                    matched = by_id.get((pairs or {}).get(asset.get("oracle_id")))
                    got_q += 1 if matched and matched.get("quantum_vulnerable") is True else 0
            for item in items:
                if belongs(item, target):
                    got_type[item.get("type")] += 1
        out["closed_world"] = {"oracle": {"type": dict(want_type), "quantum_vulnerable": want_q},
                               "product": {"type": dict(got_type), "quantum_vulnerable": got_q}}
        checks.verdict(f"{prefix}/oracle/by_type", GATE, "derived", dict(want_type) == dict(got_type), "mismatch",
                       {**s, "field": "closed_world_type"}, expected=dict(want_type), observed=dict(got_type))
        checks.verdict(f"{prefix}/oracle/quantum", GATE, "derived", want_q == got_q, "mismatch",
                       {**s, "field": "closed_world_quantum"}, expected=want_q, observed=got_q)
    checks.not_run(f"{prefix}/posture", GATE, "derived",
                   "posture numbers (readiness, HNDL, Mosca, heat-map, calendar, Q distribution) need oracle PQC "
                   "classes and the OA-10a formula", {**s, "field": "posture"})
    write_json(Path(run) / "diff" / f"derived-run{k}.json", out)
    return out
