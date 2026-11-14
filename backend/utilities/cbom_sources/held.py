"""Never-scan host names a scan node cannot resolve (Minor 2 of the #250 review), for the Network tab.

On the node, a listed host name with no usable address holds every target of every job that carries it (fail closed:
the node cannot tell which address is that host), and each job's result says so in ``never_scan_unresolved``
(scan_node jobctx.result).  The team never-scan list is carried by every job of the team, so a team-list name that a
node cannot resolve holds all of that node's jobs for the team.  This reads that state back from the jobs the nodes
already reported: per node and name, held when the node's latest finished job named it, since the first job of that
unbroken run.  Nothing new is asked of the node.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionSettings, CbomScanNode
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.settings import team_exclusions

RECENT_JOBS = 500  # the team's latest finished node jobs read (one query): a run of held jobs longer than this is
# reported "since" its oldest job read


def _iso(moment: _dt.datetime | None) -> str | None:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ") if moment else None


def never_scan_held(session: Session, team_id: int, settings: CbomCollectionSettings) -> list[dict[str, Any]]:
    """[{name, node_id, node_name, since, last_seen, job_id}] for each team never-scan host name that a node's latest
    finished job could not resolve.  Loopback names are never held (the node does not look them up)."""
    names = {n for n in team_exclusions(settings).hostnames if not T.is_loopback_name(n)}
    if not names:
        return []
    rows = session.exec(
        select(CbomCollectionJob.id, CbomCollectionJob.node_id, CbomCollectionJob.claimed_at,
               CbomCollectionJob.finished_at, CbomCollectionJob.result)
        .where(CbomCollectionJob.team_id == team_id, CbomCollectionJob.node_id.is_not(None),  # type: ignore[union-attr]
               CbomCollectionJob.finished_at.is_not(None))  # type: ignore[union-attr]
        .order_by(CbomCollectionJob.finished_at.desc(), CbomCollectionJob.id.desc())  # type: ignore[union-attr]
        .limit(RECENT_JOBS)).all()
    by_node: dict[int, list] = {}
    for row in rows:
        by_node.setdefault(int(row[1]), []).append(row)
    if not by_node:
        return []
    node_names = {n.id: n.name for n in session.exec(select(CbomScanNode).where(
        CbomScanNode.team_id == team_id, CbomScanNode.id.in_(list(by_node)))).all()}  # type: ignore[union-attr]

    def unresolved(result: Any) -> set[str]:
        held = (result or {}).get("never_scan_unresolved") if isinstance(result, dict) else None
        return {str(n).strip().lower().rstrip(".") for n in held} if isinstance(held, list) else set()

    out: list[dict[str, Any]] = []
    for node_id, jobs in by_node.items():
        if node_id not in node_names:
            continue
        newest = jobs[0]
        for name in sorted(unresolved(newest[4]) & names):
            first = newest
            for job in jobs[1:]:  # newest first: walk back while the node kept reporting the name
                if name not in unresolved(job[4]):
                    break
                first = job
            out.append({"name": name, "node_id": node_id, "node_name": node_names[node_id],
                        "since": _iso(first[2] or first[3]), "last_seen": _iso(newest[3]), "job_id": int(newest[0])})
    return sorted(out, key=lambda h: (h["name"], h["node_name"].lower()))
