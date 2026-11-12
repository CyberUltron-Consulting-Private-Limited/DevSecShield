"""Queue a collection run: the one code path for "Start run" in the browser and for a schedule's slot.

Plan (``plan_run``: sources already queued are skipped), SOC acknowledgement for network ranges, credits charged in
the same transaction as the run and its jobs, idempotent per ``client_request_id`` (unique per team). Raises
``HTTPException`` (400 / 409) for the reasons the browser shows; the caller commits.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionRun, CbomCollectionSettings, CbomCollectionSource, \
    CbomScanNode, Scan, Team
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION
from backend.utilities.cbom_sources.common import audit, engine_version
from backend.utilities.cbom_sources.kinds import KINDS
from backend.utilities.cbom_sources.planning import credits, plan_run
from backend.utilities.cbom_sources.schemas import RunCreate


def _existing(session: Session, team_id: int, client_request_id: str) -> CbomCollectionRun | None:
    return session.exec(select(CbomCollectionRun).where(
        CbomCollectionRun.team_id == team_id, CbomCollectionRun.client_request_id == client_request_id)).first()


def queue_run(session: Session, team_id: int, user_id: int, body: RunCreate, settings: CbomCollectionSettings,
              now: _dt.datetime, *, schedule_id: int | None = None) -> tuple[CbomCollectionRun, bool]:
    """Create the run and its jobs (not committed). Returns (run, replayed); a replay changed nothing."""
    existing = _existing(session, team_id, body.client_request_id)
    if existing is not None:
        return existing, True
    if body.scan_id is not None:
        scan = session.get(Scan, body.scan_id)
        if scan is None or scan.team_id != team_id:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.scan_type != "cbom":
            raise HTTPException(status_code=400, detail="scan_id: only a CBOM scan can be linked")
    include = body.include.model_dump()
    if not any(include.values()):
        raise HTTPException(status_code=400, detail="include: choose at least one group to scan")
    plan = plan_run(session, team_id, settings, now, include=include, source_ids=body.source_ids)
    queued = [i for i in plan.items if i.status == "queued"]
    if not queued:
        if plan.items and all((i.reason or "").startswith("Already queued") for i in plan.items):
            raise HTTPException(status_code=409, detail="Every selected source is already queued in a run")
        raise HTTPException(status_code=400, detail="Nothing to scan: every selected source is skipped (see 'Will be skipped')")
    if any(i.group == "network" for i in queued) and not body.soc_ack:
        raise HTTPException(status_code=400, detail="soc_ack: confirm that your SOC has agreed the network ranges and scan windows")
    total_c = plan.total_c
    if body.expected_credits is not None and round(body.expected_credits * 100) != total_c:
        raise HTTPException(status_code=409, detail=f"The estimate changed to {credits(total_c)} credits. Review it and start again.")
    team_row = session.get(Team, team_id)
    if team_row is None or float(team_row.credit_balance or 0) < total_c / 100 - J._BALANCE_SLACK:
        balance = round(float(team_row.credit_balance or 0), 2) if team_row else 0
        raise HTTPException(status_code=400, detail=f"Not enough credits: this run needs {credits(total_c)}, the team has {balance}")
    run = CbomCollectionRun(
        team_id=team_id, owner_user_id=user_id, scan_id=body.scan_id, client_request_id=body.client_request_id,
        status="queued", include=include, credits_charged_c=total_c,
        breakdown={"groups": plan.groups(), "skipped": [i.public() for i in plan.items if i.status == "skipped"]},
        soc_ack_by=user_id if body.soc_ack else None, soc_ack_at=now if body.soc_ack else None,
        created_at=now, last_updated=now, schedule_id=schedule_id,
        # what judges this run's facts (classification happens here, on the API)
        kb_version=(crypto_kb.version() or None), classifier_version=CLASSIFIER_VERSION,
        engine_version=engine_version(),
    )
    session.add(run)
    try:
        session.flush()
    except IntegrityError:  # the same client_request_id raced in from another tab or scheduler
        session.rollback()
        existing = _existing(session, team_id, body.client_request_id)
        if existing is None:
            raise
        return existing, True
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)).all()}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    snapshot = [str(i.get("cidr")) for i in (settings.network_exclusions or []) if isinstance(i, dict)]
    for item in queued:
        source = sources[item.source_id]
        params: dict[str, Any] = {
            "source_name": source.name, "units": item.units, "unit": item.unit, "exclusions": snapshot,
            "conn_v": J.connection_version(source),
            # the stable identity of the source: diffs and drift follow it after a rename or a delete
            "source_uid": source.source_uid,
            # criticality / exposure / owner ... as of now: posture scores this run with them, whatever changes later
            "metadata": J.metadata_snapshot(source, nodes.get(source.node_id or 0)),
        }
        node_less = KINDS[source.kind].node_less
        # a source on a segment (no node) queues a segment job: any agentless node of that segment claims it (F1.1)
        segment = None if node_less or source.node_id else (source.node_segment or None)
        session.add(CbomCollectionJob(
            team_id=team_id, run_id=run.id, source_id=source.id,
            node_id=None if node_less else source.node_id, node_segment=segment, kind="collect", params=params,
            source_version=source.row_version, weight_c=item.credits_c, created_by_user_id=user_id, created_at=now,
        ))
    # the jobs are flushed first, the team is charged last (DA C3): the team row is locked from the charge to the
    # commit only, not for the whole insert of thousands of jobs (a concurrent team UPDATE waited 2.4 s)
    session.flush()
    if not J.charge_team(session, team_id, total_c):
        session.rollback()
        team = session.get(Team, team_id)
        balance = round(float(team.credit_balance or 0), 2) if team else 0
        raise HTTPException(status_code=400, detail=f"Not enough credits: this run needs {credits(total_c)}, the team has {balance}")
    audit(session, team_id=team_id, actor_type="system" if schedule_id else "user", actor_id=user_id,
          action="run.create", object_type="run", object_id=run.id,
          changed_fields=[k for k, v in include.items() if v] + ([f"schedule:{schedule_id}"] if schedule_id else []))
    return run, False


__all__ = ["queue_run"]
