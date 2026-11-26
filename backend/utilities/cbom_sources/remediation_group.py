"""THE assignment of a resource that several sources read (review 6060688856 M1-M4, m3).

A resource two sources read (two IAM roles on one account) has one row per source, each with its own source-scoped
key (``identity.stable_key("node", <source uid>, ...)``).  Which row a view shows follows "latest observation wins"
(``resource_identity.rank`` / ``collections_view._rank``): the freshest read is printed.  The remediation plan, the
status and the Jira ticket must NOT follow that choice, or they flip whenever another role finishes last.  So:

* ``group_key``: one key per resource, derived from its cross-source identity (``resource_identity.resource_identity``
  with ``certificates=True``), whichever source read it.  A plan or ticket made from now on is stored under it, so it
  survives any source being deleted (m3) and any finish order (F2);
* ``resolve``: the one rule every surface uses to find a resource's plan and ticket among its group key and the
  source-scoped keys of its copies (records made before this rule, on whichever row was shown then).  The group
  record, once it exists, is the final word for the plan (round 7, review 6066796071 M1); without one the copies are
  merged field by field: the plan from the most recently updated record that holds one, the ticket from the plan
  record, else the first copy's (review 6060688856 M2, 6064356833 M2).  The group key is scoped to the team
  (6064356833 M1).

Callers: ``collections_view.load_sources_result`` (the team view's remediation status: dashboard fixed counts, the
scan list buckets, D6-D14), ``waves.node_items`` (waves, run tickets, deliverables), ``run_assets._status_clause``
(the run list's status filter) and ``run_tickets`` (the ticket claim and its Jira label search).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

GROUP_SCOPE = "resource"
# the plan fields of an assignment (what a person decided), apart from its ticket fields (what Jira holds)
PLAN_FIELDS = ("wave", "owner", "target_date", "status", "note", "done_at")
TICKET_FIELDS = ("ticket_key", "ticket_url", "ticket_state")


def group_key(identity: str | None, team_id: int) -> str | None:
    """The remediation key of a resource with a cross-source identity (``res|...``), else None.  Scoped to its TEAM
    (review 6064356833 M1): two teams reading one public ARN or endpoint are two resources to plan, two Jira issues."""
    if not identity:
        return None
    from backend.utilities.cbom_sources.identity import stable_key

    return stable_key(GROUP_SCOPE, f"team:{int(team_id)}", identity)


def row_group_key(asset_type: Any, target: Any, location: Any, facts: Mapping[str, Any] | None, *, team_id: int,
                  network: str = "", machine: str = "", cluster: str = "") -> str | None:
    """``group_key`` of one stored row, from its own fields and its job's scope (the run fold's identity rule)."""
    from backend.utilities.cbom_sources.resource_identity import resource_identity

    return group_key(resource_identity(asset_type, target, location, facts, certificates=True, network=network,
                                       machine=machine, cluster=cluster), team_id)


def has_plan(a: Any) -> bool:
    """A record that holds a decision: a status other than "open", or a wave, owner, due date or note.  A record with
    status "open" and none of those is not a plan, whatever its ticket fields (review 6065677758 M1): it is what a
    ticket claim inserts (``run_tickets._claim``) and, before this release, left behind when Jira refused the call
    (P10b), or "Create tickets" made on another copy (a ticket-only record).  Counted as a plan, such a leftover was
    the newest record and hid an older real plan on every surface (P10), and q111 wrote it to the group key (R4).
    A user's reset to blank is written to the group record, which ``resolve`` reads as the final word, so it is no
    exception."""
    if a is None:
        return False
    return str(a.status or "open") != "open" or any(
        getattr(a, name, None) not in (None, "") for name in ("wave", "owner", "target_date", "note"))


@dataclass
class Resolved:
    """``key``: where a change to this resource's plan is written; ``assignment``: the record whose PLAN is shown
    (None: no record at all); ``ticket``: the record whose TICKET is shown (None: none); ``keys``: every key looked
    at, group keys first (the Jira labels a search for an earlier issue of this resource reads)."""

    key: str
    assignment: Any = None
    ticket: Any = None
    keys: tuple[str, ...] = field(default=())
    group: str | None = None  # the resource's group key (where a new plan or ticket goes), None without one
    own: str = ""  # the shown row's own source-scoped key (the key ``run_results`` counts findings by)
    conflicts: tuple[str, ...] = field(default=())  # other ticket keys the resource's copies hold (not shown)

    @property
    def status(self) -> str | None:
        return self.assignment.status if self.assignment is not None else None

    @property
    def ticket_key(self) -> str | None:
        return self.ticket.ticket_key if self.ticket is not None else None

    @property
    def ticket_url(self) -> str | None:
        return self.ticket.ticket_url if self.ticket is not None else None


def candidates(groups: Iterable[str | None], members: Iterable[str]) -> tuple[str, ...]:
    group_keys = sorted({g for g in groups if g})
    copies = sorted({m for m in members if m} - set(group_keys))
    return tuple([*group_keys, *copies])


def _updated(a: Any) -> Any:
    import datetime as _dt

    moment = getattr(a, "last_updated", None) or getattr(a, "created_at", None)
    if isinstance(moment, _dt.datetime):
        return moment.replace(tzinfo=None) if moment.tzinfo is not None else moment
    return _dt.datetime(1970, 1, 1)


def resolve(found: Mapping[str, Any], groups: Sequence[str | None], members: Iterable[str], own: str) -> Resolved:
    """The resource's plan and ticket over its group key and every copy's key.

    THE GROUP RECORD IS THE FINAL WORD WHENEVER IT EXISTS (PR #499 round 7, review 6066796071 M1).  Every write (a plan
    edit, a reset, a ticket claim) goes to the team-scoped group key, and q111 copies each legacy plan there; so once
    the record exists its plan fields are the resource's, a user's reset to blank included, and the per-source copies
    are not read for the plan again: a copy a run does not read (a scheduled single-source run, a deleted source, an
    older run) can never bring an older plan back.  Its ticket is the group record's, else the first copy's that holds
    one (key order), so a ticket made before is never lost.

    Without a group record (a resource no write has touched since the group key, and that q111 could not place), the
    copies are merged FIELD BY FIELD (review 6064356833 M2):

    * the plan shown: the most recently updated record that holds a plan (``has_plan``: never a blank leftover or a
      ticket-only record, review 6065677758 M1), ties by key order; without any plan, the first copy with a ticket,
      else the first copy (all blank: shown as not started);
    * the ticket shown: the plan record's own ticket, else the first copy's by key order.

    Any other ticket key a copy holds is a conflict (``conflicts``: two issues for one resource, made before this
    rule).  The key a change is written to: the group record's key, else the resource's group key (the first write
    creates the group record from what is shown: ``seed_values``), else (no cross-source identity) the plan record's
    key or the row's own key.  Key order is the keys' text, never which row a view shows."""
    keys = candidates(groups, members)
    group_set = {g for g in groups if g}
    order = {k: i for i, k in enumerate(keys)}
    group_keys = [k for k in keys if k in group_set]
    held = [found[k] for k in keys if k in found]
    copies = [a for a in held if a.asset_key not in group_set]
    ticketed = [a for a in held if a.ticket_key]
    record = next((found[k] for k in group_keys if k in found), None)
    if record is not None:
        plan = record
        ticket = record if record.ticket_key else next((a for a in copies if a.ticket_key), None)
        write = record.asset_key
    else:
        planned = [a for a in copies if has_plan(a)]
        if planned:
            plan = sorted(planned, key=lambda a: (-_updated(a).timestamp(), order[a.asset_key]))[0]
        else:
            plan = next((a for a in copies if a.ticket_key), None) or (copies[0] if copies else None)
        ticket = plan if plan is not None and plan.ticket_key else next((a for a in copies if a.ticket_key), None)
        write = group_keys[0] if group_keys else (plan.asset_key if plan is not None else own)
    others = tuple(dict.fromkeys(a.ticket_key for a in ticketed
                                 if ticket is not None and a.ticket_key != ticket.ticket_key))
    return Resolved(key=write, assignment=plan, ticket=ticket, keys=keys,
                    group=record.asset_key if record is not None else (group_keys[0] if group_keys else None),
                    own=own, conflicts=others)


def seed_values(resolved: Resolved) -> dict[str, Any]:
    """The values a NEW group record starts from (``waves.upsert`` and ``run_tickets._ensure_row``, the first write
    to a resource that has none): what the copies show now (``resolve``'s legacy rule), so the write changes only
    what it names.  The plan fields, its creation time and ``done_at`` (time-to-remediate keeps its start) come from
    the plan record when it holds a plan; the ticket fields from the ticket record.  Empty when there is nothing."""
    out: dict[str, Any] = {}
    plan, ticket = resolved.assignment, resolved.ticket
    if plan is not None and has_plan(plan) and plan.asset_key != resolved.key:
        out.update({name: getattr(plan, name) for name in PLAN_FIELDS})
        out["created_at"] = getattr(plan, "created_at", None) or out.get("created_at")
        out["label"] = getattr(plan, "label", None)
    if ticket is not None and ticket.asset_key != resolved.key:
        out.update({name: getattr(ticket, name) for name in TICKET_FIELDS})
        if out.get("ticket_state") == "claimed":  # a claim is its own record's, never copied
            out["ticket_state"] = None
    return {k: v for k, v in out.items() if v is not None}


__all__ = ["GROUP_SCOPE", "PLAN_FIELDS", "Resolved", "TICKET_FIELDS", "candidates", "group_key", "has_plan", "resolve",
           "row_group_key", "seed_values"]
