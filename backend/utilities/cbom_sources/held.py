"""Never-scan host names a scan node cannot resolve (Minor 2 of the #250 review), for the Network tab.

On the node, a listed host name with no usable address holds every target of every job that carries it (fail closed:
the node cannot tell which address is that host), and each job's result says so in ``never_scan_unresolved``
(scan_node jobctx.result).  The team never-scan list is carried by every job of the team, so a team-list name that a
node cannot resolve holds all of that node's jobs for the team.  This reads that state back from the jobs the nodes
already reported: per node and name, held when the node's latest *informative* job named it, since the first
informative job of that unbroken run.  Nothing new is asked of the node.

Informative (#298 review): only a job that checked an address against the listed names can say a name resolved.
A job stopped by "Stop all" or expired (no result), a PKCS#11 token job, or a job that never reached its first
address says nothing, so it neither ends a hold nor restarts its "since".  Nodes report this in
``never_scan_checked``; for results from older nodes, a finished network or server job that counted targets.

Cost: the settings answer is polled (every 30 s per open Network tab), so the query reads only the two JSON fields it
needs (a JSON path in SQL, never the whole result with its target rows) and at most ``RECENT_JOBS_PER_NODE`` jobs per
node, so a busy node cannot push a quiet node's jobs out of the window.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from sqlalchemy import func, or_
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectionJob,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomScanNode,
)
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.settings import team_exclusions

RECENT_JOBS_PER_NODE = 100  # each node's latest finished jobs read: a run of held jobs longer than this is reported
# "since" its oldest job read
# the jobs that check addresses against the never-scan list (network sweeps and server logins); other kinds (a
# PKCS#11 token, a cloud API) never do, so they are not read at all
ADDRESS_KINDS = ("network_range", "linux_servers", "windows_servers", "appliance")
LEGACY_STATUSES = ("success", "failure")  # an older node's job that ran to the end


def _iso(moment: _dt.datetime | None) -> str | None:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ") if moment else None


def held_jobs_query(team_id: int):
    """Each node's latest network / server jobs of the team, newest first, with only the result fields this reads:
    (id, node_id, claimed_at, finished_at, status, unresolved, checked, total)."""
    job = CbomCollectionJob
    ranked = (
        select(job.id, job.node_id, job.claimed_at, job.finished_at, job.status,
               func.row_number().over(partition_by=job.node_id,
                                      order_by=(job.finished_at.desc(), job.id.desc())).label("rn"))  # type: ignore[union-attr]
        .outerjoin(CbomCollectionSource, CbomCollectionSource.id == job.source_id)
        .where(job.team_id == team_id, job.node_id.is_not(None), job.finished_at.is_not(None),  # type: ignore[union-attr]
               or_(job.kind == "discovery", CbomCollectionSource.kind.in_(ADDRESS_KINDS)))  # type: ignore[attr-defined]
        .subquery())
    # the JSON paths are read only for the rows kept by the window (Postgres: result -> 'x', result #> '{a,b}';
    # SQLite: JSON_EXTRACT), so a job's target rows never leave the database
    return (
        select(ranked.c.id, ranked.c.node_id, ranked.c.claimed_at, ranked.c.finished_at, ranked.c.status,
               job.result["never_scan_unresolved"].label("unresolved"),
               job.result["never_scan_checked"].label("checked"),
               job.result[("counts", "total")].label("total"))
        .join(job, job.id == ranked.c.id)
        .where(ranked.c.rn <= RECENT_JOBS_PER_NODE)
        .order_by(ranked.c.node_id, ranked.c.finished_at.desc(), ranked.c.id.desc()))


def _informative(row: Any) -> bool:
    """Whether the job checked an address against the listed names (so a name it does not report resolved)."""
    if row.checked is not None:  # a node that reports it (SQLite's JSON_EXTRACT gives 1 / 0 for true / false)
        return bool(row.checked)
    try:
        total = int(row.total or 0)
    except (TypeError, ValueError):
        total = 0
    return row.status in LEGACY_STATUSES and total > 0


def _names(value: Any) -> set[str]:
    return {str(n).strip().lower().rstrip(".") for n in value} if isinstance(value, list) else set()


def never_scan_held(session: Session, team_id: int, settings: CbomCollectionSettings) -> list[dict[str, Any]]:
    """[{name, node_id, node_name, since, last_seen, job_id}] for each team never-scan host name that a node's latest
    informative job could not resolve.  Loopback names are never held (the node does not look them up)."""
    names = {n for n in team_exclusions(settings).hostnames if not T.is_loopback_name(n)}
    if not names:
        return []
    by_node: dict[int, list] = {}
    for row in session.exec(held_jobs_query(team_id)).all():  # type: ignore[call-overload]
        if _informative(row):
            by_node.setdefault(int(row.node_id), []).append(row)
    if not by_node:
        return []
    node_names = {n.id: n.name for n in session.exec(select(CbomScanNode).where(
        CbomScanNode.team_id == team_id, CbomScanNode.id.in_(list(by_node)))).all()}  # type: ignore[union-attr]

    out: list[dict[str, Any]] = []
    for node_id, jobs in by_node.items():
        if node_id not in node_names:
            continue
        newest = jobs[0]
        for name in sorted(_names(newest.unresolved) & names):
            first = newest
            for job in jobs[1:]:  # newest first: walk back while the node kept reporting the name
                if name not in _names(job.unresolved):
                    break
                first = job
            out.append({"name": name, "node_id": node_id, "node_name": node_names[node_id],
                        "since": _iso(first.claimed_at or first.finished_at), "last_seen": _iso(newest.finished_at),
                        "job_id": int(newest.id)})
    return sorted(out, key=lambda h: (h["name"], h["node_name"].lower()))
