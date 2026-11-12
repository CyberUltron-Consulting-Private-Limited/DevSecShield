"""Materializer: turn ``collect`` decisions into managed collection sources and one managed schedule per policy
(F1 contract, section 3).  Runs only while ``CBOM_FLEET_MATERIALIZE`` is on.

* A target with a ``collect`` decision becomes a target line of a managed source: kind ``linux_servers`` for SSH (the
  F1.3 kinds ``awx_hosts`` / ``salt_hosts`` / ``ssm_hosts`` once they exist), config built through the kind's model with
  the credential's non-secret fields and checked with ``credential_target_problem``, node or segment from the decision.
* Targets are batched (at most the policy's ``batch_size``) per key (policy, transport, transport or credential, node
  or segment, kind).  **Assignment is sticky**: a target keeps its managed source while its key is unchanged.
* **Taking targets out is never deferred**: when a target leaves a managed source (never scan, deleted, another
  policy, unmanaged), the source is edited at once, and an open job on it is cancelled (it was created for the old
  target list).  A source left empty is removed like a hand-deleted one (``removal.remove_source``: open jobs end,
  runs and assets stay, unlinked).
* **Adding** targets to a source with an open job is deferred (editing it would cancel the job): the targets keep
  ``pending_since`` and the team asks for another reconcile, which the fleet worker retries until it is applied.
* Managed sources and schedules have their own cap (``CBOM_MAX_MANAGED_SOURCES``, default 2,000) and do not count
  toward the hand-made limits.  Credits are unchanged: runs still go through ``runs.queue_run``.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError
from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionSchedule, CbomCollectionSource
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources import schedules as SCHED
from backend.utilities.cbom_sources.common import audit, log
from backend.utilities.cbom_sources.fleet import store
from backend.utilities.cbom_sources.fleet.models import CbomCredential, CbomFleetPolicy
from backend.utilities.cbom_sources.fleet.policy import Decision
from backend.utilities.cbom_sources.kinds import KINDS, credential_target_problem
from backend.utilities.cbom_sources.removal import remove_source
from backend.utilities.cbom_sources.settings import get_or_create_settings

KIND_FOR_TRANSPORT = {"ssh": "linux_servers", "awx": "awx_hosts", "salt": "salt_hosts", "ssm": "ssm_hosts"}
OPEN = ("pending", "claimed")


def max_managed_sources() -> int:
    try:
        return max(1, int(os.environ.get("CBOM_MAX_MANAGED_SOURCES", "2000")))
    except ValueError:
        return 2000


@dataclass
class ReconcileResult:
    sources_created: int = 0
    sources_updated: int = 0
    sources_removed: int = 0
    deferred: int = 0
    targets_assigned: int = 0
    targets_unassigned: int = 0
    schedules_created: int = 0
    schedules_updated: int = 0
    schedules_removed: int = 0
    decisions_changed: int = 0
    problems: list[str] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        out = dict(self.__dict__)
        out["problems"] = self.problems[:50]
        return out


def batch_key(d: Decision, kind: str) -> str:
    """The sticky batch key: policy, transport, transport or credential, node or segment, kind."""
    parts = (d.policy_id, d.transport, d.transport_id or d.credential_id,
             d.node_id if d.node_id is not None else f"seg:{d.node_segment}", kind)
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def _line(view: Any) -> str:
    return str(view.address or view.hostname)


def _config(kind: str, d: Decision, lines: list[str], handles: dict[str, str], cred: CbomCredential | None,
            addresses: dict[str, list[str]] | None = None) -> Any:
    """The validated config model of a managed source, or raises ValueError (a problem to report)."""
    spec = KINDS.get(kind)
    if spec is None:
        raise ValueError(f"{kind} sources are not available in this version")
    if kind == "linux_servers":
        if cred is None:
            raise ValueError("the credential was not found")
        c = dict(cred.config or {})
        raw: dict[str, Any] = {"targets": lines, "port": c.get("port", 22), "login_user": c.get("login_user") or "zs-cbom",
                               "host_key_policy": c.get("host_key_policy") or "tofu", "known_hosts": c.get("known_hosts"),
                               "credential_type": cred.credential_type, "vault": c.get("vault"), "tier": d.tier}
        if cred.credential_type == "ssh_ca":
            raw["ssh_ca_id"], raw["ssh_principals"] = c.get("ssh_ca_id"), c.get("ssh_principals") or []
    else:  # F1.3 fleet kinds (FleetHostsConfig): every address of each line, for the never-scan check at dispatch
        raw = {"transport_id": d.transport_id, "targets": lines, "handles": handles, "tier": d.tier}
        if "addresses" in getattr(spec.model, "model_fields", {}):
            raw["addresses"] = addresses
    try:
        cfg = spec.model.model_validate(raw)
    except ValidationError as exc:
        first = (exc.errors() or [{}])[0]
        raise ValueError(str(first.get("msg", "invalid configuration")).removeprefix("Value error, ")) from None
    secrets = {"password": "set"} if cred is not None and cred.credential_type == "password" else {}
    problem = credential_target_problem(kind, cfg, secrets)
    if problem:
        raise ValueError(problem)
    return cfg


def _open_sources(session: Session, team_id: int) -> set[int]:
    return {sid for sid in session.exec(select(CbomCollectionJob.source_id).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.status.in_(OPEN))).all() if sid}  # type: ignore[attr-defined]


def _drop_source(session: Session, source: CbomCollectionSource, team_id: int, actor_id: int | None,
                 now: _dt.datetime) -> None:
    """Remove a managed source no policy needs: exactly as a person's delete (``removal.remove_source``)."""
    remove_source(session, source, team_id, now, actor_type="system", actor_id=actor_id, action="fleet.source.remove",
                  reason="A fleet policy no longer collects these targets")


def _free_name(taken: set[str], policy_id: int) -> str:
    n = 1
    while f"fleet-{policy_id}-{n}" in taken:
        n += 1
    name = f"fleet-{policy_id}-{n}"
    taken.add(name)
    return name


def reconcile(session: Session, team_id: int, now: _dt.datetime, *, actor_id: int | None) -> ReconcileResult:
    """Evaluate every target and bring managed sources, assignments and managed schedules in line (not committed)."""
    from backend.utilities.cbom_sources.fleet.evaluate import evaluate_team, inputs, state

    out = ReconcileResult()
    settings = get_or_create_settings(session, team_id)
    current = inputs(session, team_id, now)
    by_policy = {p.id: p for p in current.policies}
    refreshed = evaluate_team(session, team_id, now, keep_collect=True, current=current)
    out.decisions_changed = refreshed.changed
    decisions: dict[int, Decision] = refreshed.collect
    credentials = {c.id: c for c in session.exec(select(CbomCredential).where(CbomCredential.team_id == team_id)).all()}
    managed = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id, CbomCollectionSource.managed_by_policy_id.is_not(None))).all()}  # type: ignore[union-attr]
    busy = _open_sources(session, team_id)
    taken = {s.name for s in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)).all()}

    groups: dict[str, dict[str, Any]] = {}
    views = list(store.iter_views(session, team_id))
    for view in views:
        d = decisions.get(view.id)
        if d is None:
            continue
        kind = KIND_FOR_TRANSPORT[d.transport or "ssh"]
        key = batch_key(d, kind)
        group = groups.setdefault(key, {"decision": d, "kind": kind, "views": []})
        group["views"].append(view)

    assignment: dict[int, int | None] = {}  # target id -> managed source id
    planned: dict[int, list[Any]] = {}  # managed source id (or negative placeholder) -> views
    new_sources: dict[int, tuple[str, dict[str, Any]]] = {}
    placeholder = 0
    for key, group in sorted(groups.items()):
        d: Decision = group["decision"]
        size = d.batch_size
        existing = sorted(sid for sid, s in managed.items() if s.batch_key == key)
        members: dict[int, list[Any]] = {sid: [] for sid in existing}
        rest = []
        for view in sorted(group["views"], key=lambda v: v.id):
            if view.managed_source_id in members:
                members[view.managed_source_id].append(view)  # sticky
            else:
                rest.append(view)
        for view in rest:
            room = next((sid for sid in sorted(members) if len(members[sid]) < size), None)
            if room is None:
                placeholder -= 1
                room = placeholder
                members[room] = []
                new_sources[room] = (key, group)
            members[room].append(view)
        for sid, vs in members.items():
            planned[sid] = vs
            for view in vs:
                assignment[view.id] = sid

    managed_total = len(managed)
    created: dict[int, CbomCollectionSource] = {}
    pending: set[int] = set()  # targets assigned to a source whose edit waits for its open job
    for sid, vs in sorted(planned.items(), key=lambda kv: (kv[0] < 0, abs(kv[0]))):
        if sid > 0:
            source = managed[sid]
            d = groups[source.batch_key]["decision"]
            kind = groups[source.batch_key]["kind"]
        else:
            key, group = new_sources[sid]
            d, kind = group["decision"], group["kind"]
        lines = sorted({_line(v) for v in vs})
        handles = {_line(v): (v.handles or {}).get(d.transport or "", "") for v in vs if (v.handles or {}).get(d.transport or "")}
        addresses = {_line(v): sorted(set(v.addresses or []) | ({v.address} if v.address else set())) for v in vs}
        cred = credentials.get(d.credential_id) if d.credential_id else None
        segment_column = hasattr(CbomCollectionSource, "node_segment")
        if d.node_segment is not None and not segment_column:
            out.problems.append(f"policy #{d.policy_id}: node segments need the lean node API (F1.1); choose a scan node")
            _unplan(vs, assignment)
            continue
        if not vs:
            continue
        try:
            cfg = _config(kind, d, lines, handles, cred, addresses)
        except ValueError as exc:
            out.problems.append(f"policy #{d.policy_id}: {exc}")
            _unplan(vs, assignment)
            continue
        config = cfg.model_dump(mode="json")
        if sid > 0:
            source = managed[sid]
            if (source.config or {}) == config and source.node_id == d.node_id and source.credential_id == d.credential_id:
                continue
            if sid in busy:
                current_lines = set((source.config or {}).get("targets") or [])
                kept = [v for v in vs if _line(v) in current_lines]
                waiting = [v for v in vs if _line(v) not in current_lines]
                if len({_line(v) for v in kept}) == len(current_lines):
                    # nothing leaves: additions (or a node / credential change) wait for the open job, which an edit
                    # would cancel
                    out.deferred += 1
                    pending.update(v.id for v in waiting)
                    continue
                # a target leaves: never wait. Apply the removal now and cancel the job made for the old list;
                # what is to be added waits for the next reconcile
                J.cancel_open_jobs(session, source, now, reason="A fleet policy took targets out of this source")
                busy.discard(sid)
                if waiting:
                    out.deferred += 1
                    pending.update(v.id for v in waiting)
                    for v in waiting:
                        assignment[v.id] = None
                if not kept:
                    _drop_source(session, source, team_id, actor_id, now)
                    del managed[sid]
                    out.sources_removed += 1
                    continue
                try:
                    config = _config(kind, d, sorted({_line(v) for v in kept}), handles, cred, addresses
                                     ).model_dump(mode="json")
                except ValueError as exc:
                    out.problems.append(f"policy #{d.policy_id}: {exc}")
                    continue
            source.config, source.node_id, source.credential_id = config, d.node_id, d.credential_id
            if segment_column:
                setattr(source, "node_segment", d.node_segment)
            source.row_version += 1
            source.last_updated, source.updated_by_user_id = now, actor_id
            session.add(source)
            out.sources_updated += 1
            continue
        if managed_total >= max_managed_sources():
            out.problems.append(f"policy #{d.policy_id}: the team has {managed_total} managed sources, the limit "
                                f"(CBOM_MAX_MANAGED_SOURCES) is {max_managed_sources()}")
            _unplan(vs, assignment)
            continue
        policy = by_policy.get(d.policy_id)
        name = _free_name(taken, d.policy_id or 0)
        source = CbomCollectionSource(
            team_id=team_id, owner_user_id=(policy.owner_user_id if policy and policy.owner_user_id else actor_id or 0),
            updated_by_user_id=actor_id, kind=kind, name=name, name_lower=name.lower(), node_id=d.node_id,
            enabled=True, config=config, secret_encrypted=None, secret_fields=[], created_at=now, last_updated=now,
            last_test_status="never", managed_by_policy_id=d.policy_id, credential_id=d.credential_id,
            batch_key=new_sources[sid][0])
        if segment_column:
            setattr(source, "node_segment", d.node_segment)
        session.add(source)
        session.flush()
        audit(session, team_id=team_id, actor_type="system", actor_id=actor_id, action="fleet.source.create",
              object_type="source", object_id=source.id, changed_fields=[f"policy:{d.policy_id}"])
        managed[source.id] = source
        created[sid] = source
        managed_total += 1
        out.sources_created += 1
        for view in vs:
            assignment[view.id] = source.id

    # assignments (sticky) and the pending flag: write only what changed
    changes = []
    for view in views:
        want = assignment.get(view.id)
        if want is not None and want < 0:
            want = created[want].id if want in created else None
        want_pending = now if view.id in pending else None
        if view.managed_source_id != want or (view.pending_since is None) != (want_pending is None):
            changes.append((view.id, want, view.pending_since or want_pending if want_pending else None))
            if view.managed_source_id != want:
                if want is None:
                    out.targets_unassigned += 1
                else:
                    out.targets_assigned += 1
    for target_id, source_id, pending_since in changes:
        session.exec(update(store._TABLE).where(store._TABLE.c.id == target_id)  # type: ignore[call-overload]
                     .values(managed_source_id=source_id, pending_since=pending_since, last_updated=now))
    # empty managed sources go: a source with an open job too (its job was made for targets no policy collects now)
    used = {sid for sid in assignment.values() if sid}
    used |= {created[s].id for s in created}
    for sid, source in list(managed.items()):
        if sid in used or sid in planned and planned[sid]:
            continue
        _drop_source(session, source, team_id, actor_id, now)
        del managed[sid]
        out.sources_removed += 1
    _schedules(session, team_id, now, by_policy, managed, settings.window_timezone, out, actor_id)
    row = state(session, team_id, now)
    row.last_reconcile = {**out.public(), "at": now.isoformat(timespec="seconds") + "Z"}
    if out.deferred:  # the fleet worker retries until every deferred change is applied
        from backend.utilities.cbom_sources.fleet.evaluate import RETRY_DEFERRED

        row.reconcile_requested_at = now + RETRY_DEFERRED
    elif row.reconcile_requested_at is not None and row.reconcile_requested_at <= now:
        row.reconcile_requested_at = None
    session.add(row)
    log("fleet reconciled", team=team_id, **{k: v for k, v in out.public().items() if k != "problems" and v})
    return out


def _unplan(views: list[Any], assignment: dict[int, int | None]) -> None:
    for view in views:
        assignment[view.id] = None


def _schedules(session: Session, team_id: int, now: _dt.datetime, policies: dict[int, CbomFleetPolicy],
               managed: dict[int, CbomCollectionSource], tz: str, out: ReconcileResult, actor_id: int | None) -> None:
    rows = {s.policy_id: s for s in session.exec(select(CbomCollectionSchedule).where(
        CbomCollectionSchedule.team_id == team_id, CbomCollectionSchedule.policy_id.is_not(None))).all()}  # type: ignore[union-attr]
    for policy_id, policy in sorted(policies.items()):
        sources = sorted(sid for sid, s in managed.items() if s.managed_by_policy_id == policy_id)
        sched = (policy.action or {}).get("schedule") if policy.deleted_at is None and policy.enabled else None
        row = rows.pop(policy_id, None)
        if not sched or not sources:
            if row is not None:
                audit(session, team_id=team_id, actor_type="system", actor_id=actor_id, action="fleet.schedule.remove",
                      object_type="schedule", object_id=row.id)
                session.delete(row)
                out.schedules_removed += 1
            continue
        timing = (sched["frequency"], sched["time_of_day"], sched.get("weekday"), sched.get("monthday"))
        name = f"fleet: {policy.name}"[:64]
        if row is None:
            row = CbomCollectionSchedule(team_id=team_id, owner_user_id=policy.owner_user_id or actor_id or 0,
                                         updated_by_user_id=actor_id, name=name, policy_id=policy_id,
                                         created_at=now, last_updated=now)
            out.schedules_created += 1
            old_timing = None
        else:
            old_timing = (row.frequency, row.time_of_day, row.weekday, row.monthday)
            if old_timing == timing and (row.source_ids or []) == sources and row.name == name and row.enabled:
                continue
            out.schedules_updated += 1
        row.name, row.enabled, row.include = name, True, {"servers": True}
        row.frequency, row.time_of_day, row.weekday, row.monthday = timing
        row.source_ids = sources
        row.last_updated, row.updated_by_user_id = now, actor_id
        if old_timing != timing:
            row.next_run_at = SCHED.next_slot(row, tz, now)[1]
        if row.id is not None:
            row.row_version += 1
        session.add(row)
    for row in rows.values():  # a policy row that no longer exists
        session.delete(row)
        out.schedules_removed += 1
