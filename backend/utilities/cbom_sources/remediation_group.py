"""THE assignment of a resource that several sources read (review 6060688856 M1-M4, m3).

A resource two sources read (two IAM roles on one account) has one row per source, each with its own source-scoped
key (``identity.stable_key("node", <source uid>, ...)``).  Which row a view shows follows "latest observation wins"
(``resource_identity.rank`` / ``collections_view._rank``): the freshest read is printed.  The remediation plan, the
status and the Jira ticket must NOT follow that choice, or they flip whenever another role finishes last.  So:

* ``group_key``: one key per resource, derived from its cross-source identity (``resource_identity.resource_identity``
  with ``certificates=True``), whichever source read it.  A plan or ticket made from now on is stored under it, so it
  survives any source being deleted (m3) and any finish order (F2);
* ``resolve``: the one rule every surface uses to find a resource's assignment among its group key and the
  source-scoped keys of its copies (plans made before this rule, on whichever row was shown then):

  1. the group key's assignment, if there is one;
  2. else the copy whose assignment holds a ticket, the first by key order;
  3. else the first copy with any assignment, by key order;

  and the ticket shown is the primary's, else the first candidate (group first, then copies by key order) holding
  one, so an existing ticket is never hidden behind a plan without one (M2).  Key order is the keys' text: it never
  depends on which row a view shows.

Callers: ``collections_view.load_sources_result`` (the team view's remediation status: dashboard fixed counts, the
scan list buckets, D6-D14), ``waves.node_items`` (waves, run tickets, deliverables), ``run_assets._status_clause``
(the run list's status filter) and ``run_tickets`` (the ticket claim and its Jira label search).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

GROUP_SCOPE = "resource"


def group_key(identity: str | None) -> str | None:
    """The remediation key of a resource with a cross-source identity (``res|...``), else None."""
    if not identity:
        return None
    from backend.utilities.cbom_sources.identity import stable_key

    return stable_key(GROUP_SCOPE, "", identity)


def row_group_key(asset_type: Any, target: Any, location: Any, facts: Mapping[str, Any] | None, *,
                  network: str = "", machine: str = "", cluster: str = "") -> str | None:
    """``group_key`` of one stored row, from its own fields and its job's scope (the run fold's identity rule)."""
    from backend.utilities.cbom_sources.resource_identity import resource_identity

    return group_key(resource_identity(asset_type, target, location, facts, certificates=True, network=network,
                                       machine=machine, cluster=cluster))


@dataclass
class Resolved:
    """``key``: where a change to this resource's plan is written (the primary's key, else the group key, else the
    row's own key); ``assignment``: the primary assignment (None: no plan); ``ticket``: the assignment holding the
    resource's ticket (None: none); ``keys``: every key looked at, group keys first (the Jira labels a search for an
    earlier issue of this resource reads)."""

    key: str
    assignment: Any = None
    ticket: Any = None
    keys: tuple[str, ...] = field(default=())
    group: str | None = None  # the resource's group key (where a new plan or ticket goes), None without one
    own: str = ""  # the shown row's own source-scoped key (the key ``run_results`` counts findings by)

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


def resolve(found: Mapping[str, Any], groups: Sequence[str | None], members: Iterable[str], own: str) -> Resolved:
    """The rule in the module docstring.  ``found``: assignment by key (any superset of the candidates)."""
    keys = candidates(groups, members)
    group_keys = [k for k in keys if k in {g for g in groups if g}]
    copies = [k for k in keys if k not in group_keys]
    primary = next((found[k] for k in group_keys if k in found), None)
    if primary is None:
        primary = next((found[k] for k in copies if k in found and found[k].ticket_key), None)
    if primary is None:
        primary = next((found[k] for k in copies if k in found), None)
    ticket = primary if primary is not None and primary.ticket_key else next(
        (found[k] for k in keys if k in found and found[k].ticket_key), None)
    write = primary.asset_key if primary is not None else (group_keys[0] if group_keys else own)
    return Resolved(key=write, assignment=primary, ticket=ticket, keys=keys,
                    group=group_keys[0] if group_keys else None, own=own)


__all__ = ["GROUP_SCOPE", "Resolved", "candidates", "group_key", "resolve", "row_group_key"]
