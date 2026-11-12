"""CMDB import: a CSV upload or a ServiceNow CMDB pull becomes server and network-range sources with their metadata.

Preview, then confirm. The preview is computed from the rows and the team's current sources; confirming recomputes it
and refuses (409) when the result differs from what was previewed (``digest``), so nothing changes behind the user.

* A row names a host by FQDN, host name or IP (several identity columns are tried in order) or a network by CIDR.
* A row whose host is already a target of a Linux / Windows server source (exact match of the normalised target) or
  whose CIDR is a network-range source updates THAT source's metadata: owner, application, business criticality,
  exposure, data classification, environment. Metadata never changes how a source connects, so running and queued
  jobs and the connection test are kept (the WP9 connection-version split). A blank cell leaves the stored value.
* Several rows that land on the same source with different values for a field are a conflict: that field is left
  alone and listed.
* Hosts not found anywhere become NEW Linux server sources (scan-node key login, trust on first use) on the chosen
  scan node, grouped by identical metadata (one source per group, at most 1000 targets each); CIDRs become network
  ranges. Windows hosts are not created (a WinRM login is required): they are listed for the Servers tab.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources import agents as AG
from backend.utilities.cbom_sources.limits import max_sources
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.common import NAME_RE, audit, log, utcnow
from backend.utilities.cbom_sources.kinds import KINDS, _metadata_text

MAX_ROWS = 5000
MAX_CSV_BYTES = 2 * 1024 * 1024
# the team's source cap is limits.max_sources() (CBOM_MAX_SOURCES), the same one the Sources API applies
SERVER_KINDS = ("linux_servers", "windows_servers")
FIELDS = ("owner", "application", "criticality", "exposure", "data_classification", "environment")
CONFIG_FIELD = {"owner": "owner", "application": "application", "criticality": "business_criticality",
                "exposure": "exposure", "data_classification": "data_classification", "environment": "environment"}
HOST_COLUMNS = ("fqdn", "hostname", "host_name", "host", "name", "ip", "ip_address", "address", "target", "cidr",
                "network")
ALIASES = {
    "owner": ("owner", "owned_by", "owner_group", "support_group"),
    "application": ("application", "app", "u_application", "business_service", "service"),
    "criticality": ("criticality", "business_criticality", "busines_criticality"),
    "exposure": ("exposure", "internet_facing", "zone"),
    "data_classification": ("data_classification", "classification", "data_class"),
    "environment": ("environment", "env", "used_for"),
    "os": ("os", "os_type", "operating_system", "sys_class_name", "class"),
}


class ImportError_(ValueError):
    """A problem with the whole input (safe to show)."""


# ----------------------------------------------------------------------------- values
def norm_criticality(value: str) -> str | None:
    """Words, or ServiceNow's ``1 - most critical`` ... ``4 - not critical`` choices (qualified phrases first)."""
    v = value.strip().lower()
    for phrase, out in (("not critical", "low"), ("less critical", "medium"), ("somewhat critical", "high"),
                        ("most critical", "critical"), ("very high", "critical")):
        if phrase in v:
            return out
    number = re.match(r"^\s*([1-5])\s*(-|$)", v)
    if number:
        return {"1": "critical", "2": "high", "3": "medium", "4": "low", "5": "low"}[number.group(1)]
    for word, out in (("critical", "critical"), ("high", "high"), ("medium", "medium"), ("moderate", "medium"),
                      ("low", "low")):
        if word in v:
            return out
    return None


def norm_exposure(value: str) -> str | None:
    v = value.strip().lower()
    if v in ("internet", "internet-facing", "internet facing", "external", "public", "dmz", "yes", "true", "1"):
        return "internet"
    if v in ("internal", "private", "intranet", "no", "false", "0"):
        return "internal"
    if v in ("unknown", "-"):
        return "unknown"
    return None


def norm_classification(value: str) -> str | None:
    v = value.strip().lower()
    if v in ("public", "open"):
        return "public"
    if v in ("internal", "internal use", "internal only"):
        return "internal"
    if v in ("confidential", "sensitive"):
        return "confidential"
    if v in ("restricted", "secret", "highly confidential", "strictly confidential", "top secret"):
        return "restricted"
    return None


def norm_field(name: str, value: Any) -> tuple[str | None, str | None]:
    """(normalised value or None, problem or None)."""
    text = _metadata_text(str(value)) if value not in (None, "") else None
    if text is None:
        return None, None
    if name == "criticality":
        out = norm_criticality(text)
    elif name == "exposure":
        out = norm_exposure(text)
    elif name == "data_classification":
        out = norm_classification(text)
    elif name == "environment":
        out = text.lower()[:32]
    else:
        out = text[:128]
    return out, (None if out is not None else f"{name}: {text[:40]!r} is not a known value; ignored")


# ----------------------------------------------------------------------------- rows
def parse_csv(text: str) -> list[dict[str, Any]]:
    """CSV with a header row -> import rows ``{line, hosts, os, owner, ...}``. Raises ImportError_."""
    if len(text.encode("utf-8")) > MAX_CSV_BYTES:
        raise ImportError_("the CSV is larger than 2 MB")
    text = text.lstrip("﻿")
    try:
        sample = text[:4096]
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t") if sample.strip() else csv.excel
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    try:
        return _read_rows(reader)
    except csv.Error as exc:
        # a cell over the csv module's field limit (128 KB), a quote never closed ...: the file, not the server
        raise ImportError_(f"the CSV could not be read near line {reader.line_num}: {str(exc)[:120]}") from None


def _read_rows(reader: Any) -> list[dict[str, Any]]:
    try:
        header = next(reader)
    except StopIteration:
        raise ImportError_("the CSV is empty") from None
    names = [re.sub(r"[^a-z0-9]+", "_", h.strip().lower()).strip("_") for h in header]
    host_cols = [names.index(c) for c in HOST_COLUMNS if c in names]
    if not host_cols:
        raise ImportError_("no host column: name one column host, hostname, fqdn, ip or cidr")
    cols = {k: next((names.index(a) for a in aliases if a in names), None) for k, aliases in ALIASES.items()}
    rows: list[dict[str, Any]] = []
    for line, record in enumerate(reader, start=2):
        if not any(cell.strip() for cell in record):
            continue
        if len(rows) >= MAX_ROWS:
            raise ImportError_(f"more than {MAX_ROWS} rows; split the file")

        def cell(i: int | None) -> str | None:
            return record[i].strip() if i is not None and i < len(record) and record[i].strip() else None

        rows.append({"line": line, "hosts": [h for h in (cell(i) for i in host_cols) if h],
                     **{k: cell(i) for k, i in cols.items()}})
    return rows


_WINDOWS = re.compile(r"\bwin|windows|cmdb_ci_win")  # Windows, Win2019, cmdb_ci_win_server; never Darwin


def _os_kind(os_value: str | None) -> str:
    return "windows_servers" if os_value and _WINDOWS.search(os_value.lower()) else "linux_servers"


@dataclass
class Plan:
    creates: list[dict[str, Any]] = field(default_factory=list)
    updates: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    unchanged: int = 0
    rows: int = 0

    def digest(self) -> str:
        blob = json.dumps({"c": self.creates, "u": self.updates}, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:32]

    def public(self, limit: int = 500) -> dict[str, Any]:
        return {"rows": self.rows, "digest": self.digest(), "unchanged": self.unchanged,
                "counts": {"create": len(self.creates), "update": len(self.updates), "conflict": len(self.conflicts),
                           "skipped": len(self.skipped),
                           "new_targets": sum(len(c.get("targets") or [c.get("cidr")]) for c in self.creates)},
                "creates": self.creates[:limit], "updates": self.updates[:limit], "conflicts": self.conflicts[:limit],
                "skipped": self.skipped[:limit], "truncated": max(len(self.creates), len(self.updates),
                                                                  len(self.conflicts), len(self.skipped)) > limit}


def _identities(row: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    """(family 'server' | 'network', canonical identities, problems)."""
    family, out, problems = None, [], []
    for raw in row.get("hosts") or []:
        try:
            kind, _value, canonical = T.parse_line(str(raw).strip())
        except T.TargetError as exc:
            problems.append(str(exc)[:120])
            continue
        is_net = kind == "net" and ("/" in canonical or "-" in canonical)
        this = "network" if is_net else "server"
        if family is None:
            family = this
        if this == family and canonical not in out:
            out.append(canonical)
    return family or "server", out, problems


def _index(sources: list[CbomCollectionSource]) -> dict[tuple[str, str], set[int]]:
    index: dict[tuple[str, str], set[int]] = {}
    for s in sources:
        cfg = s.config or {}
        if s.kind in SERVER_KINDS:
            for target in cfg.get("targets") or []:
                index.setdefault(("server", str(target).lower()), set()).add(s.id)  # type: ignore[arg-type]
        elif s.kind == "network_range" and cfg.get("cidr"):
            index.setdefault(("network", str(cfg["cidr"]).lower()), set()).add(s.id)  # type: ignore[arg-type]
    return index


def _name(base: str, taken: set[str]) -> str:
    clean = re.sub(r"[^A-Za-z0-9 ._-]+", "-", base).strip(" -._") or "CMDB"
    if not clean[0].isalnum():
        clean = "CMDB " + clean
    clean = clean[:56].rstrip(" -._")
    name, n = clean, 2
    while name.lower() in taken:
        name, n = f"{clean} {n}", n + 1
    taken.add(name.lower())
    assert NAME_RE.match(name)
    return name


def build_plan(session: Session, team_id: int, rows: list[dict[str, Any]], *, create_missing: bool = True) -> Plan:
    plan = Plan(rows=len(rows))
    sources = list(session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id,
        CbomCollectionSource.kind.in_(SERVER_KINDS + ("network_range",)))  # type: ignore[attr-defined]
        .order_by(CbomCollectionSource.id)).all())
    by_id = {s.id: s for s in sources}
    index = _index(sources)
    proposals: dict[int, dict[str, dict[Any, list[int]]]] = {}  # source -> field -> value -> lines
    groups: dict[tuple, dict[str, Any]] = {}
    for n, row in enumerate(rows, start=1):
        line = row.get("line") or n
        label = row.get("label")
        family, ids, problems = _identities(row)
        if not ids:
            plan.skipped.append({"line": line, "ref": row.get("ref"), "label": label,
                                 "reason": problems[0] if problems else "no host, IP address or CIDR"})
            continue
        values: dict[str, str] = {}
        notes = []
        for name in FIELDS:
            value, problem = norm_field(name, row.get(name))
            if value is not None:
                values[name] = value
            if problem:
                notes.append(problem)
        matched = sorted({sid for i in ids for sid in index.get((family, i.lower()), set())})
        if matched:
            for sid in matched:
                slot = proposals.setdefault(sid, {})
                for name, value in values.items():
                    slot.setdefault(name, {}).setdefault(value, []).append(line)
            if notes:
                plan.skipped.append({"line": line, "label": label, "reason": "; ".join(notes)[:300], "partial": True})
            continue
        if not create_missing:
            plan.skipped.append({"line": line, "label": label, "reason": "not a target of any source (creating is off)"})
            continue
        kind = "network_range" if family == "network" else _os_kind(row.get("os"))
        if kind == "windows_servers":
            plan.skipped.append({"line": line, "label": label or ids[0],
                                 "reason": "Windows server not in any source: add it in the Servers tab (a WinRM login "
                                           "is needed), then import again to set its metadata"})
            continue
        key = (kind, ids[0] if kind == "network_range" else "", *(values.get(f) for f in FIELDS))
        group = groups.setdefault(key, {"kind": kind, "targets": [], "metadata": values, "lines": []})
        group["targets"].append(ids[0])
        group["lines"].append(line)
    # updates and conflicts
    for sid in sorted(proposals):
        source = by_id[sid]
        cfg = source.config or {}
        changes: dict[str, list[Any]] = {}
        for name, options in sorted(proposals[sid].items()):
            if len(options) > 1:
                plan.conflicts.append({"source_id": sid, "source": source.name, "field": name,
                                       "values": {str(v): lines[:20] for v, lines in options.items()}})
                continue
            (value,) = options
            key = CONFIG_FIELD[name]
            if cfg.get(key) != value:
                changes[key] = [cfg.get(key), value]
        if changes:
            plan.updates.append({"source_id": sid, "source": source.name, "kind": source.kind, "changes": changes})
        else:
            plan.unchanged += 1
    # creates
    taken = {(s.kind, s.name_lower) for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    names: dict[str, set[str]] = {}
    for key in sorted(groups, key=lambda k: tuple(str(x) for x in k)):
        group = groups[key]
        kind, meta = group["kind"], group["metadata"]
        used = names.setdefault(kind, {n for k, n in taken if k == kind})
        config_meta = {CONFIG_FIELD[f]: v for f, v in sorted(meta.items())}
        if kind == "network_range":
            cidr = group["targets"][0]
            plan.creates.append({"kind": kind, "name": _name(f"CMDB net {cidr.replace('/', '-')}", used), "cidr": cidr,
                                 "metadata": config_meta, "lines": group["lines"][:50]})
            continue
        targets = sorted(set(group["targets"]))
        base = "CMDB " + " ".join(x for x in (meta.get("application") or "servers", meta.get("environment")) if x)
        for start in range(0, len(targets), T.MAX_LINES):
            plan.creates.append({"kind": kind, "name": _name(base, used), "targets": targets[start:start + T.MAX_LINES],
                                 "metadata": config_meta, "lines": group["lines"][:50]})
    return plan


# ----------------------------------------------------------------------------- apply
def apply_plan(session: Session, team_id: int, user_id: int, plan: Plan, *, node_id: int | None) -> dict[str, Any]:
    """Apply in the caller's transaction (the caller commits). Raises ValueError (safe to show)."""
    now = utcnow()
    node = None
    if plan.creates:
        node = session.get(CbomScanNode, node_id) if node_id else None
        if node is None or node.team_id != team_id:
            raise ValueError("node_id: choose the scan node that reaches the new hosts")
        # the source form's rule (agents.check_node_for_kind): an agent node collects only its own host
        for kind in sorted({item["kind"] for item in plan.creates}):
            problem = AG.kind_problem(node, kind)
            if problem:
                raise ValueError(f"node_id: {problem}")
        total = len(session.exec(select(CbomCollectionSource.id).where(CbomCollectionSource.team_id == team_id)).all())
        if total + len(plan.creates) > (cap := max_sources()):
            raise ValueError(f"this import would create {len(plan.creates)} sources; a team can have at most "
                             f"{cap} (it has {total})")
    updated = created = 0
    for item in plan.updates:
        source = session.get(CbomCollectionSource, item["source_id"])
        if source is None or source.team_id != team_id:
            continue
        cfg = {**(source.config or {}), **{k: v[1] for k, v in item["changes"].items()}}
        validated = KINDS[source.kind].model.model_validate(cfg)
        source.config = validated.model_dump(mode="json")
        source.row_version += 1  # edit version only: the connection version (what jobs check) is unchanged
        source.updated_by_user_id, source.last_updated = user_id, now
        session.add(source)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="source.cmdb_update",
              object_type="source", object_id=source.id, changed_fields=[f"config.{k}" for k in item["changes"]])
        updated += 1
    for item in plan.creates:
        spec = KINDS[item["kind"]]
        if item["kind"] == "network_range":
            cfg = spec.model.model_validate({"cidr": item["cidr"], **item["metadata"]})
        else:
            cfg = spec.model.model_validate({"targets": item["targets"], "credential_type": "node_key",
                                             "host_key_policy": "tofu", **item["metadata"]})
        source = CbomCollectionSource(
            team_id=team_id, owner_user_id=user_id, updated_by_user_id=user_id, kind=item["kind"], name=item["name"],
            name_lower=item["name"].lower(), node_id=node.id if node else None, enabled=True,
            config=cfg.model_dump(mode="json"), secret_encrypted=None, secret_fields=[], created_at=now,
            last_updated=now, last_test_status="never")
        session.add(source)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="source.cmdb_create",
              object_type="source", object_id=source.id, changed_fields=["kind", "name", "config", "node_id"])
        created += 1
    log("cmdb import applied", team=team_id, by=user_id, created=created, updated=updated,
        conflicts=len(plan.conflicts) or None, skipped=len(plan.skipped) or None)
    return {"created": created, "updated": updated, "conflicts": len(plan.conflicts), "skipped": len(plan.skipped)}
