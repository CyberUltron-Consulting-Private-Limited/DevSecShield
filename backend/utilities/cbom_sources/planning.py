"""Node status, per-source target counts, and the one function that decides what a run will do.

``plan_run`` is used by the overview ("Will be skipped"), by ``/estimate`` and by ``POST /runs``, so
the three can never disagree.  Credits are integers in hundredths (centi-credits) and are only turned
into a float for display.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionSettings, CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.kinds import KINDS
from backend.utilities.cbom_sources.settings import team_exclusions

ONLINE_SECONDS = 120

# Rates chosen by product (per target): server 0.2, cluster 2, database 1, cloud account 4, network 1 per /24.
RATES_C = {"server": 20, "kubernetes": 200, "database": 100, "cloud_account": 400, "network_block": 100}


def credits(centi: int) -> float:
    return round(centi / 100, 2)


def node_status(node: CbomScanNode | None, now: _dt.datetime) -> str:
    if node is None:
        return "missing"
    if node.node_token_hash is None:
        if node.registration_expires_at is not None and node.registration_expires_at <= now:
            return "registration_expired"
        return "pending_registration"
    if node.last_heartbeat_at is not None and (now - node.last_heartbeat_at).total_seconds() <= ONLINE_SECONDS:
        return "online"
    return "offline"


def source_targets(source: CbomCollectionSource, settings: CbomCollectionSettings) -> dict[str, Any]:
    """Units the source covers after the team's never-scan list (and its own, for servers)."""
    cfg = source.config or {}
    spec = KINDS.get(source.kind)
    group = spec.group if spec else "other"
    if group == "servers":
        try:
            parsed = T.parse_targets(cfg.get("targets") or [], allow_empty=True)
            own = T.parse_exclusions(cfg.get("exclusions") or [])
            team = team_exclusions(settings)
            excl = T.ParsedTargets(
                intervals=T.merge(own.intervals + team.intervals),
                hostnames=sorted(set(own.hostnames) | set(team.hostnames)),
            )
            count = T.count_in_scope(parsed, excl)
        except T.TargetError:
            count = 0
        return {"units": count, "unit": "targets"}
    if group == "network":
        try:
            kind, interval, _canonical = T.parse_line(cfg.get("cidr", ""))
            intervals = T.subtract([interval], team_exclusions(settings).intervals) if kind == "net" else []
        except T.TargetError:
            intervals = []
        return {"units": T.size(intervals), "unit": "addresses", "blocks": T.count_blocks(intervals),
                "intervals": intervals}
    if group == "cloud" and source.kind == "aws_account" and cfg.get("scope") == "organization":
        members = (source.last_test_result or {}).get("member_accounts")
        return {"units": int(members) if isinstance(members, int) and members > 0 else 1, "unit": "accounts"}
    return {"units": 1, "unit": {"kubernetes": "clusters", "databases": "databases", "cloud": "accounts"}.get(group, "sources")}


@dataclass
class PlanItem:
    source_id: int
    name: str
    kind: str
    group: str
    node_id: int | None
    node_name: str | None
    units: int
    unit: str
    credits_c: int
    status: str  # queued | skipped
    reason: str | None = None
    waiting: bool = False

    def public(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id, "name": self.name, "kind": self.kind, "group": self.group,
            "node_id": self.node_id, "node_name": self.node_name, "units": self.units, "unit": self.unit,
            "credits": credits(self.credits_c), "status": self.status, "reason": self.reason,
            "waiting_for_node": self.waiting,
        }


@dataclass
class Plan:
    items: list[PlanItem] = field(default_factory=list)

    @property
    def total_c(self) -> int:
        return sum(i.credits_c for i in self.items if i.status == "queued")

    def groups(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for item in self.items:
            g = out.setdefault(item.group, {"credits_c": 0, "queued": 0, "skipped": 0, "units": 0})
            if item.status == "queued":
                g["credits_c"] += item.credits_c
                g["queued"] += 1
                g["units"] += item.units
            else:
                g["skipped"] += 1
        return {k: {**v, "credits": credits(v.pop("credits_c"))} for k, v in out.items()}

    def public(self) -> dict[str, Any]:
        return {
            "total_credits": credits(self.total_c),
            "groups": self.groups(),
            "items": [i.public() for i in self.items],
            "skipped": [i.public() for i in self.items if i.status == "skipped"],
        }


def plan_run(
    session: Session,
    team_id: int,
    settings: CbomCollectionSettings,
    now: _dt.datetime,
    include: dict[str, bool] | None = None,
    source_ids: list[int] | None = None,
) -> Plan:
    include = include or {}
    sources = session.exec(
        select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id).order_by(CbomCollectionSource.id)
    ).all()
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    active = {
        row.source_id: row.run_id
        for row in session.exec(
            select(CbomCollectionJob).where(
                CbomCollectionJob.team_id == team_id,
                CbomCollectionJob.kind == "collect",
                CbomCollectionJob.status.in_(["pending", "claimed"]),  # type: ignore[attr-defined]
            )
        ).all()
    }
    wanted = set(source_ids) if source_ids else None
    plan = Plan()
    counted_blocks: list[T.Interval] = []
    for source in sources:
        spec = KINDS.get(source.kind)
        if spec is None:
            continue
        group = spec.group
        include_key = "cloud" if group in ("cloud", "identity") else group
        if include and not include.get(include_key, False):
            continue
        if wanted is not None and source.id not in wanted:
            continue
        node = nodes.get(source.node_id) if source.node_id else None
        info = source_targets(source, settings)
        units = int(info["units"])
        item = PlanItem(source.id, source.name, source.kind, group, source.node_id, node.name if node else None,
                        units, info["unit"], 0, "skipped")
        try:
            cfg_model = spec.model.model_validate(source.config or {})
        except Exception:
            cfg_model = None
        needs_node = bool(cfg_model is not None and spec.needs_node(cfg_model))
        collectable = bool(cfg_model is not None and spec.collectable(cfg_model))
        status = node_status(node, now) if needs_node else "n/a"
        if not source.enabled:
            item.reason = "Disabled"
        elif cfg_model is None:
            item.reason = "Configuration is no longer valid; edit and save it again"
        elif not collectable:
            item.reason = ("Cloud collection is not available yet" if group == "cloud"
                           else "Collection for this connector is not available yet")
        elif needs_node and node is None:
            item.reason = "No scan node assigned"
        elif needs_node and status in ("pending_registration", "registration_expired"):
            item.reason = f"Scan node {node.name} has not registered yet"
        elif source.last_test_status == "failed":
            item.reason = "Last connection test failed; fix it and test again"
        elif units <= 0:
            item.reason = "0 targets left after the never-scan list"
        elif group == "network" and settings.stop_all_network:
            item.reason = "Network scanning is stopped"
        elif source.id in active:
            item.reason = f"Already queued in run #{active[source.id]}"
        else:
            item.status = "queued"
            item.waiting = status == "offline"
            if group == "servers":
                item.credits_c = RATES_C["server"] * units
            elif group == "kubernetes":
                item.credits_c = RATES_C["kubernetes"]
            elif group == "databases":
                item.credits_c = RATES_C["database"]
            elif group == "network":
                # each /24 is charged once, even when ranges overlap or sit on two nodes
                blocks_before = T.count_blocks(counted_blocks)
                counted_blocks = T.merge(counted_blocks + (info.get("intervals") or []))
                item.credits_c = RATES_C["network_block"] * max(T.count_blocks(counted_blocks) - blocks_before, 0)
            else:
                item.credits_c = 0
        plan.items.append(item)
    return plan
