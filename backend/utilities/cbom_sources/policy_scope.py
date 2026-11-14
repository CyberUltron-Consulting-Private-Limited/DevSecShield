"""CB-11: what the never-scan list left out of a job, read the same way by the outcome, billing, drift, Q0 scope
items and exports.

A target on the team's (or a server source's own) never-scan list is EXCLUDED BY POLICY: the customer chose it, so it
never makes a collection incomplete, it is never a coverage gap, never "removed", never "new", and never charged.

The scan node reports each such target as ``skipped_never_scan`` in ``result.targets`` (with the reason, which names
the listed host name when the node resolved one to the address).  Past the node's 1,000 target rows the rest are
folded into one ``summary`` row whose error is JSON ``{status: count}``: the count is still exact, and an address
is still matched by the job's never-scan snapshot (``params.exclusions``, the team list when the run was queued).
"""
from __future__ import annotations

import ipaddress
import json
from typing import Any, Mapping

STATUS = "skipped_never_scan"
LABEL = "excluded by policy"
REASON = "excluded by policy: on the never-scan list"
BACK_IN_SCOPE = "back in scope: no longer on the never-scan list"


def _targets(result: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    rows = result.get("targets") if isinstance(result, Mapping) else None
    return [t for t in rows if isinstance(t, dict)] if isinstance(rows, list) else []


def summary_counts(target: Mapping[str, Any]) -> dict[str, int]:
    """The node's "+N more" row: ``{status: count}`` from its error (JSON)."""
    try:
        counts = json.loads(str(target.get("error") or "{}"))
    except ValueError:
        return {}
    if not isinstance(counts, dict):
        return {}
    return {str(k): v for k, v in counts.items() if isinstance(v, int) and not isinstance(v, bool) and v > 0}


def excluded_targets(result: Mapping[str, Any] | None) -> list[str]:
    """The target labels the node listed as on the never-scan list (rows only, not the summary's count)."""
    return [str(t.get("target") or "") for t in _targets(result) if t.get("status") == STATUS and t.get("target")]


def excluded_count(result: Mapping[str, Any] | None) -> int:
    """Every target the never-scan list left out of the job: its rows plus the summary row's count."""
    total = 0
    for t in _targets(result):
        if t.get("status") == STATUS:
            total += 1
        elif t.get("status") == "summary":
            total += summary_counts(t).get(STATUS, 0)
    return total


def snapshot_intervals(params: Mapping[str, Any] | None) -> tuple[tuple[int, int, int], ...]:
    """The address entries of the job's never-scan snapshot, as ``targets`` intervals (the planner's parser; host
    names are left to the node's rows: only it resolves them)."""
    from backend.utilities.cbom_sources import targets as T

    try:
        return tuple(T.parse_exclusions([str(e) for e in (params or {}).get("exclusions") or []]).intervals)
    except T.TargetError:
        return ()


def address_listed(target: str, intervals: tuple[tuple[int, int, int], ...]) -> bool:
    """Whether ``target`` is an address inside one of ``intervals`` (an IPv4-mapped IPv6 address counts as IPv4)."""
    if not intervals or not target:
        return False
    try:
        address = ipaddress.ip_address(target.strip("[]"))
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    value = int(address)
    return any(version == address.version and start <= value <= end for version, start, end in intervals)


ENUMERATE_CAP = 4096  # listed addresses spelled out for a SQL match (drift's carry walk); past it: rows only


def listed_addresses(intervals: tuple[tuple[int, int, int], ...]) -> frozenset[str]:
    """Every address of ``intervals`` as text (the form a target is stored in), when there are at most
    ``ENUMERATE_CAP`` of them; else none (a listed /8 is matched by ``address_listed``, never spelled out)."""
    if sum(end - start + 1 for _v, start, end in intervals) > ENUMERATE_CAP:
        return frozenset()
    out = set()
    for version, start, end in intervals:
        kind = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        out.update(str(kind(value)) for value in range(start, end + 1))
    return frozenset(out)


__all__ = ["STATUS", "LABEL", "REASON", "BACK_IN_SCOPE", "summary_counts", "excluded_targets", "excluded_count",
           "snapshot_intervals", "address_listed", "listed_addresses"]
