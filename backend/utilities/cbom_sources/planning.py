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
from backend.utilities.cbom_sources.agents import kind_problem
from backend.utilities.cbom_sources.kinds import KINDS
from backend.utilities.cbom_sources.settings import team_exclusions

ONLINE_SECONDS = 120

# Rates chosen by product (per target): server 0.2, cluster 2, database 1, cloud account 4, network 1 per /24.
RATES_C = {"server": 20, "kubernetes": 200, "database": 100, "cloud_account": 400, "network_block": 100}
# WP8b: a host agent is charged like one server; a registry image like one code scan (1 credit, decision D3).
RATES_C["image"] = 100
# CT discovery: each domain searched is charged like one server target (0.2 credits; owner question CT-2).
RATES_C["ct_domain"] = 20


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
    if source.kind == "host_agent":  # the node's own host
        return {"units": 1, "unit": "hosts"}
    if source.kind == "container_images":
        return {"units": len(cfg.get("images") or []), "unit": "images"}
    if source.kind == "ct_logs":  # the names actually searched: a subdomain of a listed domain is in its answer
        from backend.utilities.cbom_sources.ct_domains import query_set

        domains = [d for d in cfg.get("domains") or [] if isinstance(d, str)]
        return {"units": len(query_set(domains, bool(cfg.get("include_subdomains", True)))), "unit": "domains"}
    if group == "servers" or source.kind == "appliance":  # appliances list devices like servers do
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
            kind, interval, canonical = T.parse_line(cfg.get("cidr", ""))
            scanned = T.scanned_interval(interval, canonical) if kind == "net" else None  # what the sweep visits
            intervals = T.in_scope(T.ParsedTargets(intervals=[scanned]), team_exclusions(settings))[0] if scanned else []
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
    status: str  # queued | skipped | covered (read by another source in this plan: an AWS Private CA connector)
    reason: str | None = None
    waiting: bool = False
    # a scan-node job waits for its scan window (the team's, or a server source's own; jobs.job_waiting_reason):
    # window_applies says the source has one; window_starts_at is when a run queued now may start (None: now)
    window_applies: bool = False
    window_starts_at: _dt.datetime | None = None

    def public(self) -> dict[str, Any]:
        starts = self.window_starts_at
        return {
            "source_id": self.source_id, "name": self.name, "kind": self.kind, "group": self.group,
            "node_id": self.node_id, "node_name": self.node_name, "units": self.units, "unit": self.unit,
            "credits": credits(self.credits_c), "status": self.status, "reason": self.reason,
            "waiting_for_node": self.waiting, "window_applies": self.window_applies,
            "window_starts_at": starts.strftime("%Y-%m-%dT%H:%M:%SZ") if starts else None,
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
            elif item.status == "skipped":  # "covered": read by another source of the plan, nothing to fix
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
                           else _AWS_PCA if getattr(cfg_model, "provider", None) == "aws_private_ca"
                           else "Certificate Transparency discovery is not enabled on this server"
                           if source.kind == "ct_logs" else "Collection for this connector is not available yet")
        elif needs_node and node is None:
            item.reason = "No scan node assigned"
        elif needs_node and status in ("pending_registration", "registration_expired"):
            item.reason = f"Scan node {node.name} has not registered yet"
        elif needs_node and kind_problem(node, source.kind):
            item.reason = kind_problem(node, source.kind)
        elif source.kind == "aws_account" and source.last_test_status != "passed":
            item.reason = "Validate the AWS role first; only a role that passed validation is scanned"
        elif source.last_test_status == "failed":
            item.reason = "Last connection test failed; fix it and test again"
        elif units <= 0:
            item.reason = "0 targets left after the never-scan list"
        elif group == "network" and source.kind != "appliance" and settings.stop_all_network:  # a config read, not a sweep
            item.reason = "Network scanning is stopped"
        elif source.id in active:
            item.reason = f"Already queued in run #{active[source.id]}"
        else:
            item.status = "queued"
            item.waiting = status == "offline"
            if needs_node:  # node jobs wait for their scan window; cloud jobs do not (jobs.job_waiting_reason)
                from backend.utilities.cbom_sources.jobs import _job_window
                from backend.utilities.cbom_sources.settings import _grid, next_window_start, window_allows

                grid = _job_window(source, settings)
                item.window_applies = _grid(grid) is not None
                if not window_allows(grid, settings.window_timezone, now):
                    item.window_starts_at = next_window_start(grid, settings.window_timezone, now)
                    if item.window_starts_at is None:  # an empty grid: the job would never start
                        item.reason = "Its scan window allows no hour; the run would never start"
                        item.status = "skipped"
                        plan.items.append(item)
                        continue
            if source.kind == "container_images":
                item.credits_c = RATES_C["image"] * units
            elif source.kind == "ct_logs":
                item.credits_c = RATES_C["ct_domain"] * units
            elif group == "servers" or source.kind == "appliance":
                item.credits_c = RATES_C["server"] * units
            elif group == "kubernetes":
                item.credits_c = RATES_C["kubernetes"]
            elif group == "databases":
                item.credits_c = RATES_C["database"]
            elif group == "cloud":
                item.credits_c = RATES_C["cloud_account"] * max(units, 1)
            elif group == "network":
                # each /24 is charged once, even when ranges overlap or sit on two nodes
                blocks_before = T.count_blocks(counted_blocks)
                counted_blocks = T.merge(counted_blocks + (info.get("intervals") or []))
                item.credits_c = RATES_C["network_block"] * max(T.count_blocks(counted_blocks) - blocks_before, 0)
            else:
                item.credits_c = 0
        plan.items.append(item)
    _aws_private_ca(plan, sources)
    return plan


_AWS_PCA = "Read by its AWS account source; nothing separate to collect"


def _aws_private_ca(plan: Plan, sources: list[CbomCollectionSource]) -> None:
    """An AWS Private CA connector is read by the AWS account source it names (aws_collect reads acm-pca with that
    account's role), so its item says what this plan does with that source (CB-08, review 5876424957)."""
    by_id = {s.id: s for s in sources}
    items = {i.source_id: i for i in plan.items}
    for item in plan.items:
        if item.reason != _AWS_PCA:
            continue
        aws_id = (by_id[item.source_id].config or {}).get("aws_source_id")
        aws = by_id.get(aws_id) if isinstance(aws_id, int) else None
        aws_item = items.get(aws.id) if aws is not None and aws.kind == "aws_account" else None
        if aws is None or aws.kind != "aws_account":
            item.reason = "Not read: its AWS account was removed"
        elif aws_item is None:
            item.reason = f"Not read in this run: AWS account {aws.name} is not in this run"
        elif aws_item.status != "queued":
            item.reason = f"Not read in this run: AWS account {aws.name} is skipped ({aws_item.reason})"
        else:
            item.status = "covered"
