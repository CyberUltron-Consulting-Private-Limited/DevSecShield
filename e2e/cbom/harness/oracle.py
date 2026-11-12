"""Oracle matching (O-3, O-4): the product's assets against the lab's expected CBOM, per target.

* closed world: exact, one-to-one. Every product asset at the target's address must consume exactly one oracle asset;
  an oracle asset nothing consumed is ``missing``; a product asset that consumed nothing is ``extra``.
* open world: superset. Every oracle asset must be found; extras are listed and must stay within ``extras_ceiling``.
* a target whose independent self-check disagreed (lab/selfcheck.json) is NOT-JUDGED(lab), never a pass.
* product correctness is judged on the API value (O-7); the export's completeness is the join's business.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from . import fieldmap as F
from .checks import Checks
from .rundir import read_json, write_csv

GATE = "G11"
ORACLE_SCHEMA = "zs-cbom-oracle/1"


def _location_key(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _address_of(location: str) -> str:
    loc = str(location or "").strip()
    if loc.startswith("["):  # [v6]:port
        return loc[1:].split("]", 1)[0].lower()
    host = loc.split("/", 1)[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.lower()


def belongs(item: dict[str, Any], target: dict[str, Any]) -> bool:
    """Is this product asset about this lab target (its address or one of its names)?"""
    keys = {str(target.get("address", "")).lower(), *[str(n).lower() for n in target.get("names") or []]}
    keys.discard("")
    return _address_of(item.get("location")) in keys or str(item.get("target") or "").lower() in keys


def product_value(key: str, item: dict[str, Any], component: dict[str, Any] | None) -> Any:
    """The product's value for an oracle ``expect`` key: the API value; for keys only the export carries
    (pqc_class), the export's."""
    if key in F.FIELDS and "api" in F.FIELDS[key]:
        return F.view_value(key, "api", item)
    if key in F.EXPORT_ALWAYS:
        if component is None:
            return F.MISSING
        values = F.props(component).get(F.EXPORT_ALWAYS[key])
        return F.MISSING if values is None else values[0]
    if key == "serial":
        return (item.get("facts") or {}).get("serial")
    if key == "fingerprint_sha256":
        return (item.get("facts") or {}).get("fingerprint_sha256")
    if key == "format":
        return (item.get("facts") or {}).get("format")
    if key == "path":
        return item.get("location")
    return F.MISSING


def load_oracle(run: Path, k: str) -> dict[str, Any] | None:
    doc = read_json(Path(run) / "oracle" / f"run{k}.json")
    if doc is not None and doc.get("schema") != ORACLE_SCHEMA:
        raise ValueError(f"oracle/run{k}.json: schema {doc.get('schema')!r}, expected {ORACLE_SCHEMA}")
    return doc


def selfcheck_disagreements(run: Path) -> dict[str, list[str]]:
    doc = read_json(Path(run) / "lab" / "selfcheck.json") or {}
    out: dict[str, list[str]] = {}
    for target in doc.get("targets") or []:
        if not target.get("agree", False):
            out[str(target.get("target_id"))] = [f"{c.get('oracle_id')}:{c.get('key')}"
                                                for c in target.get("checks") or [] if not c.get("agree", False)]
    return out


def match(run: Path, k: str, checks: Checks, api_items: dict[int, dict[str, Any]] | None,
          components: dict[int, dict[str, Any]] | None) -> list[dict[str, Any]]:
    prefix = f"{GATE}/oracle/run{k}"
    oracle = load_oracle(run, k)
    if oracle is None:
        checks.not_run(f"{prefix}", GATE, "oracle", f"oracle/run{k}.json not written (lab not run)", {"run": k})
        return []
    if api_items is None:
        checks.not_run(f"{prefix}/api", GATE, "oracle", "no API assets to judge", {"run": k})
        return []
    if not (Path(run) / "lab" / "selfcheck.json").is_file():
        checks.fail(f"{prefix}/selfcheck", GATE, "oracle", "selfcheck-missing", {"run": k},
                    expected="lab/selfcheck.json (O-3)", observed="absent")
    lab_bugs = selfcheck_disagreements(run)
    components = components or {}
    rows: list[dict[str, Any]] = []
    for target in oracle.get("targets") or []:
        tid = str(target["target_id"])
        world = target.get("world", "closed")
        tsubject = {"kind": "oracle", "run": k, "target_id": tid, "world": world}
        mine = {aid: item for aid, item in api_items.items() if belongs(item, target)}
        if tid in lab_bugs:
            for asset in target.get("assets") or []:
                checks.not_judged(f"{prefix}/{asset['oracle_id']}", GATE, "oracle",
                                  "lab self-check disagreed: " + ", ".join(lab_bugs[tid]),
                                  {**tsubject, "oracle_id": asset["oracle_id"]})
            continue
        consumed: dict[int, str] = {}
        for asset in target.get("assets") or []:
            oid = asset["oracle_id"]
            subject = {**tsubject, "oracle_id": oid, "asset_type": asset.get("asset_type"),
                       "location": asset.get("location")}
            candidates = [aid for aid, item in sorted(mine.items())
                          if aid not in consumed and item.get("type") == asset.get("asset_type")
                          and _location_key(item.get("location")) == _location_key(asset.get("location"))]
            if not candidates:
                checks.fail(f"{prefix}/{oid}/present", GATE, "oracle", "missing", subject,
                            expected=f"{asset.get('asset_type')} at {asset.get('location')}", observed="no such asset")
                rows.append({"oracle_id": oid, "asset_id": "", "key": "present", "expected": "yes", "product": "no",
                             "verdict": "FAIL"})
                continue
            aid = candidates[0]
            consumed[aid] = oid
            if world == "closed" and len(candidates) > 1:
                checks.fail(f"{prefix}/{oid}/unique", GATE, "oracle", "duplicate", {**subject, "asset_id": aid},
                            expected=1, observed=len(candidates))
            else:
                checks.ok(f"{prefix}/{oid}/present", GATE, "oracle", {**subject, "asset_id": aid})
            item, comp = api_items[aid], components.get(aid)
            for key, want_raw in (asset.get("expect") or {}).items():
                norm = F.ORACLE_NORMALISERS.get(key)
                if norm is None:
                    checks.fail(f"{prefix}/{oid}/{key}", GATE, "oracle", "unknown-expect-key",
                                {**subject, "asset_id": aid, "field": key}, expected=want_raw)
                    continue
                got_raw = product_value(key, item, comp)
                want = norm(want_raw)
                got = None if got_raw is F.MISSING else norm(got_raw)
                reason = "export-missing" if got_raw is F.MISSING else "wrong-value"
                ok = got_raw is not F.MISSING and got == want
                checks.verdict(f"{prefix}/{oid}/{key}", GATE, "oracle", ok, reason,
                               {**subject, "asset_id": aid, "field": key}, expected=want_raw,
                               observed="<absent>" if got_raw is F.MISSING else got_raw)
                rows.append({"oracle_id": oid, "asset_id": aid, "key": key, "expected": want_raw,
                             "product": "<absent>" if got_raw is F.MISSING else got_raw,
                             "verdict": "PASS" if ok else "FAIL"})
            codes = set(F.norm_codes(item.get("finding_codes")))
            for code in asset.get("codes_include") or []:
                checks.verdict(f"{prefix}/{oid}/code/{code}", GATE, "oracle", code in codes, "code-missing",
                               {**subject, "asset_id": aid, "field": "finding_codes", "code": code},
                               expected=f"includes {code}", observed=sorted(codes))
            for code in asset.get("codes_exclude") or []:
                checks.verdict(f"{prefix}/{oid}/no-code/{code}", GATE, "oracle", code not in codes, "code-unexpected",
                               {**subject, "asset_id": aid, "field": "finding_codes", "code": code},
                               expected=f"excludes {code}", observed=sorted(codes))
            if asset.get("impact_max"):
                got = item.get("impact") or "Info"
                checks.verdict(f"{prefix}/{oid}/impact_max", GATE, "oracle",
                               F.IMPACT_RANK.get(got, 4) >= F.IMPACT_RANK.get(asset["impact_max"], 4), "impact-too-high",
                               {**subject, "asset_id": aid, "field": "impact"},
                               expected=f"<= {asset['impact_max']}", observed=got)
        extras = sorted(aid for aid in mine if aid not in consumed)
        if world == "closed":
            for aid in extras:
                checks.fail(f"{prefix}/{tid}/extra/{aid}", GATE, "oracle", "extra",
                            {**tsubject, "asset_id": aid, "asset_type": mine[aid].get("type"),
                             "location": mine[aid].get("location")},
                            expected="no asset beyond the oracle (closed world)",
                            observed=f"{mine[aid].get('type')} at {mine[aid].get('location')}")
        else:
            ceiling = int(target.get("extras_ceiling", 0))
            checks.verdict(f"{prefix}/{tid}/extras", GATE, "oracle", len(extras) <= ceiling, "too-many-extras",
                           tsubject, expected=f"<= {ceiling}",
                           observed=[f"{mine[a].get('type')} {mine[a].get('location')}" for a in extras])
        for i, banned in enumerate(target.get("must_not_appear") or []):
            hits = [aid for aid, item in api_items.items()
                    if item.get("type") == banned.get("asset_type")
                    and _location_key(item.get("location")) == _location_key(banned.get("location"))]
            checks.verdict(f"{prefix}/{tid}/must-not-appear/{i}", GATE, "oracle", not hits, "fabricated",
                           {**tsubject, "asset_type": banned.get("asset_type"), "location": banned.get("location")},
                           expected="absent", observed=hits)
    write_csv(Path(run) / "diff" / f"oracle-run{k}.csv", rows,
              ["oracle_id", "asset_id", "key", "expected", "product", "verdict"])
    return rows


def closed_world_ids(run: Path, k: str, api_items: dict[int, dict[str, Any]]) -> set[int]:
    oracle = load_oracle(run, k) or {}
    out: set[int] = set()
    for target in oracle.get("targets") or []:
        if target.get("world", "closed") == "closed":
            out |= {aid for aid, item in api_items.items() if belongs(item, target)}
    return out


def in_lab(address: str, subnet: str = "10.231.0.0/24") -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(subnet)
    except ValueError:
        return False
