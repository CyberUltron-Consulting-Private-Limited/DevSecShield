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
from backend.utilities.cbom_sources import qgrade as QG
from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION
from backend.utilities.cbom_sources.common import audit, engine_version
from backend.utilities.cbom_sources.kinds import KINDS
from backend.utilities.cbom_sources.planning import NETWORK_STOPPED, credits, plan_run
from backend.utilities.cbom_sources.schemas import RunCreate

STOPPED_REFUSAL = "Scanning is stopped (Stop all). Resume scanning to start a run."


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
        if any(i.reason == NETWORK_STOPPED for i in plan.items):
            # say WHY (N12): "every selected source is skipped" alone hid that Stop all is on
            others = [i for i in plan.items if i.reason != NETWORK_STOPPED and i.status == "skipped"]
            raise HTTPException(status_code=400, detail=STOPPED_REFUSAL + (
                f" {len(others)} other selected source{'s are' if len(others) != 1 else ' is'} skipped too "
                "(see 'Will be skipped')." if others else ""))
        raise HTTPException(status_code=400, detail="Nothing to scan: every selected source is skipped (see 'Will be skipped')")
    if any(i.group == "network" for i in queued) and not body.soc_ack:
        raise HTTPException(status_code=400, detail="soc_ack: confirm that your SOC has agreed the network ranges and scan windows")
    total_c = plan.total_c
    if body.expected_credits is not None and round(body.expected_credits * 100) != total_c:
        raise HTTPException(status_code=409, detail=f"The estimate changed to {credits(total_c)} credits. Review it and start again.")
    if not J.charge_team(session, team_id, total_c):
        team = session.get(Team, team_id)
        balance = round(float(team.credit_balance or 0), 2) if team else 0
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
        # the grade inputs at Start (CB-19 PR-2): run views grade with these; later team edits are shown beside them
        grade_model_version=QG.GRADE_MODEL_VERSION, grade_inputs=QG.snapshot_inputs(session, team_id, settings, now),
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
        session.add(CbomCollectionJob(
            team_id=team_id, run_id=run.id, source_id=source.id,
            node_id=None if KINDS[source.kind].node_less else source.node_id, kind="collect", params=params,
            source_version=source.row_version, weight_c=item.credits_c, created_by_user_id=user_id, created_at=now,
        ))
    audit(session, team_id=team_id, actor_type="system" if schedule_id else "user", actor_id=user_id,
          action="run.create", object_type="run", object_id=run.id,
          changed_fields=[k for k, v in include.items() if v] + ([f"schedule:{schedule_id}"] if schedule_id else []))
    return run, False


__all__ = ["queue_run"]
