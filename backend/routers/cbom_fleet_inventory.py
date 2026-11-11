"""Fleet inventory routes (F1.2, contract section 3), behind ``CBOM_FLEET_INVENTORY`` (404 while it is off).

``/{team_id}/cbom/sources/fleet/inventory/...``: targets (list, detail with the live decision, CSV/JSON import, API
upsert, soft delete) and inventory sources (AWS / CSV / JSON / API; CRUD and sync).  Members read; writes need a team
admin (400, never 403).  Every write is audited (field names only).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import func, update
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource
from backend.utilities.cbom_sources.common import audit, log, utcnow
from backend.utilities.cbom_sources.fleet import flags as FLAGS
from backend.utilities.cbom_sources.fleet import store
from backend.utilities.cbom_sources.fleet import sync as SYNC
from backend.utilities.cbom_sources.fleet.aws_inventory import AwsInventoryConfig
from backend.utilities.cbom_sources.fleet.http import FLEET, Member, permission
from backend.utilities.cbom_sources.fleet.inventory_sources import (
    MAX_IMPORT_BYTES, InventoryError, Parsed, _collect, parse_csv, parse_json)
from backend.utilities.cbom_sources.fleet.models import (
    CbomFleetPolicy, CbomInventorySource, CbomInventoryTarget, TARGET_KINDS)
from backend.utilities.cbom_sources.fleet.policy import PolicyEngine
from backend.utilities.cbom_sources.fleet.refs import build_refs
from backend.utilities.cbom_sources.fleet.schemas import (
    ApiTargetsBody, ImportBody, InventorySourceCreate, InventorySourceUpdate, public_inventory_source, public_target)
from backend.utilities.cbom_sources.http import (
    PRIVATE, ObjectId, TeamId, bad_request, bump_version, check_version, read_capped_json, read_limiter,
    require_admin, server_error, write_limiter)
from backend.utilities.cbom_sources.settings import get_or_create_settings

router = APIRouter(tags=["cbom-fleet"], route_class=FLAGS.route_class("inventory"))
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
INV = FLEET + "/inventory"
MAX_INVENTORY_SOURCES = 50
MAX_TARGETS_PER_TEAM = 50_000
IMPORT_BODY_LIMIT = MAX_IMPORT_BYTES + 64 * 1024
API_BODY_LIMIT = 4 * 1024 * 1024
DEFAULT_IMPORT_NAMES = {"csv": "CSV import", "json": "JSON import"}


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom fleet {what}", exc, team=team_id) from None


def _ok(payload: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=PRIVATE)


def _engine_for(session: Session, team_id: int, now) -> tuple[PolicyEngine, dict[int, CbomFleetPolicy]]:
    policies = session.exec(select(CbomFleetPolicy).where(CbomFleetPolicy.team_id == team_id)).all()
    engine = PolicyEngine(policies, get_or_create_settings(session, team_id),
                          refs=build_refs(session, team_id, policies), now=now)
    return engine, {p.id: p for p in policies}


def _owned_source(session: Session, team_id: int, source_id: int) -> CbomInventorySource:
    row = session.get(CbomInventorySource, source_id)
    if row is None or row.team_id != team_id or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Inventory source not found")
    return row


def _source_named(session: Session, team_id: int, kind: str, name: str, user_id: int, now) -> CbomInventorySource:
    """The live inventory source of this kind and name, created on first use (imports and the API)."""
    row = session.exec(select(CbomInventorySource).where(
        CbomInventorySource.team_id == team_id, CbomInventorySource.kind == kind,
        CbomInventorySource.deleted_at.is_(None), func.lower(CbomInventorySource.name) == name.lower())).first()  # type: ignore[union-attr]
    if row is not None:
        return row
    _check_source_cap(session, team_id)
    row = CbomInventorySource(team_id=team_id, owner_user_id=user_id, updated_by_user_id=user_id, kind=kind, name=name,
                              config={}, created_at=now, last_updated=now)
    session.add(row)
    session.flush()
    audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.inventory_source.create",
          object_type="inventory_source", object_id=row.id, changed_fields=["kind", "name"])
    return row


def _check_source_cap(session: Session, team_id: int) -> None:
    total = session.exec(select(func.count()).select_from(CbomInventorySource).where(
        CbomInventorySource.team_id == team_id, CbomInventorySource.deleted_at.is_(None))).one()  # type: ignore[union-attr]
    if total >= MAX_INVENTORY_SOURCES:
        raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_INVENTORY_SOURCES} inventory sources")


def _check_target_cap(session: Session, team_id: int, adding: int) -> None:
    total = session.exec(select(func.count()).select_from(CbomInventoryTarget)
                         .where(CbomInventoryTarget.team_id == team_id)).one()
    if total + adding > MAX_TARGETS_PER_TEAM:
        raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_TARGETS_PER_TEAM:,} inventory targets")


def _save(session: Session, team_id: int, user_id: int, source: CbomInventorySource, parsed: Parsed, now, *,
          snapshot: bool, dry_run: bool, action: str) -> dict[str, Any]:
    engine, _policies = _engine_for(session, team_id, now)
    known = store._existing(session, team_id, [t.external_id for t in parsed.targets])
    _check_target_cap(session, team_id, len(parsed.targets) - len(known))
    # a file with rows that failed is not a complete snapshot: nothing is marked missing from it
    result = store.upsert(session, team_id, source, parsed.targets, now, engine=engine,
                          snapshot=snapshot and parsed.error_count == 0, dry_run=dry_run)
    out = result.public()
    out["errors"] = parsed.errors
    out["error_count"] = parsed.error_count
    out["rows"] = parsed.rows
    out["dry_run"] = dry_run
    out["inventory_source_id"] = source.id
    out["missing_skipped"] = snapshot and parsed.error_count > 0
    if not dry_run:
        source.last_sync_at, source.last_sync_status, source.last_updated = now, "ok" if not parsed.error_count else "partial", now
        source.last_sync_summary = {k: out[k] for k in ("created", "updated", "unchanged", "missing", "error_count",
                                                         "rows", "digest")}
        session.add(source)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action=action,
              object_type="inventory_source", object_id=source.id,
              changed_fields=[f"created:{result.created}", f"updated:{result.updated}", f"missing:{result.missing}"])
    return out


# ----------------------------------------------------------------------------- targets
def _list_targets(engine, team_id: int, kind: str | None, tag: str | None, q: str | None, missing: str | None,
                  source_id: int | None, decision: str | None, cursor: int, limit: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        policy_engine, policies = _engine_for(session, team_id, now)
        t = CbomInventoryTarget
        query = select(t).where(t.team_id == team_id)
        count = select(func.count()).select_from(t).where(t.team_id == team_id)
        conds = []
        if kind:
            conds.append(t.kind == kind)
        if source_id:
            conds.append(t.inventory_source_id == source_id)
        if missing == "yes":
            conds.append(t.missing_since.is_not(None))  # type: ignore[union-attr]
        elif missing != "all":
            conds.append(t.missing_since.is_(None))  # type: ignore[union-attr]
        if q:
            like = f"%{q.lower()}%"
            conds.append(func.lower(t.external_id).like(like) | func.lower(func.coalesce(t.address, "")).like(like)
                         | func.lower(func.coalesce(t.hostname, "")).like(like))
        for cond in conds:
            query, count = query.where(cond), count.where(cond)
        tag_key, _, tag_value = (tag or "").partition(":")
        tag_key = tag_key.strip().lower()
        python_filter = bool(tag_key) or bool(decision)
        rows: list[Any] = []
        total = 0
        if not python_filter:  # the total counts every match; the page starts after the cursor
            total = session.exec(count).one()
            rows = list(session.exec(query.where(t.id > cursor).order_by(t.id).limit(limit + 1)).all())
        else:  # tag and decision filters are applied here (JSON columns; the decision is evaluated live)
            for row in session.exec(query.order_by(t.id)).all():
                if tag_key and (tag_key not in (row.tags or {}) or (tag_value and (row.tags or {}).get(tag_key) != tag_value)):
                    continue
                if decision and policy_engine.evaluate(row).action != decision:
                    continue
                total += 1
                if row.id > cursor and len(rows) <= limit:
                    rows.append(row)
        page, more = rows[:limit], len(rows) > limit
        items = [public_target(r, policy_engine.evaluate(r).to_dict()) for r in page]
        names = {pid: {"name": p.name, "priority": p.priority, "enabled": p.enabled, "deleted": p.deleted_at is not None}
                 for pid, p in policies.items()}
        return {"targets": items, "next_cursor": page[-1].id if more and page else None, "total": total,
                "policies": {str(k): v for k, v in names.items()}}


@router.get(INV + "/targets", dependencies=READ, openapi_extra=permission("cbom.fleet.read"),
            summary="Inventory targets with the policy decision of each (page with cursor)")
async def list_targets(team_id: TeamId, ctx: Member, kind: str | None = Query(default=None, max_length=24),
                       tag: str | None = Query(default=None, max_length=400), q: str | None = Query(default=None, max_length=200),
                       missing: str | None = Query(default=None, pattern="^(yes|no|all)$"),
                       source_id: int | None = Query(default=None, ge=1, le=2_147_483_647),
                       decision: str | None = Query(default=None, pattern="^(collect|never_scan|unmanaged)$"),
                       cursor: int = Query(default=0, ge=0, le=2_147_483_647), limit: int = Query(default=100, ge=1, le=500)):
    engine, _user = ctx
    if kind is not None and kind not in TARGET_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {', '.join(TARGET_KINDS)}")
    return _ok(await _run("list targets", team_id, _list_targets, engine, team_id, kind, tag, q, missing, source_id,
                          decision, cursor, limit))


def _get_target(engine, team_id: int, target_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        row = session.get(CbomInventoryTarget, target_id)
        if row is None or row.team_id != team_id:
            raise HTTPException(status_code=404, detail="Target not found")
        policy_engine, policies = _engine_for(session, team_id, now)
        decision = policy_engine.evaluate(row)
        matched = set(decision.matched_policy_ids)
        ordered = [{"id": p.id, "name": p.name, "priority": p.priority, "won": p.id == decision.policy_id}
                   for p in policy_engine.policies if p.id in matched]
        managed = session.get(CbomCollectionSource, row.managed_source_id) if row.managed_source_id else None
        return {"target": public_target(row, decision.to_dict()), "decision": decision.to_dict(),
                "matched_policies": ordered,
                "managed_source": {"id": managed.id, "name": managed.name} if managed is not None else None}


@router.get(INV + "/targets/{target_id}", dependencies=READ, openapi_extra=permission("cbom.fleet.read"),
            summary="One target, its live decision and every policy that matches it (the winner first)")
async def get_target(team_id: TeamId, target_id: ObjectId, ctx: Member):
    engine, _user = ctx
    return _ok(await _run("get target", team_id, _get_target, engine, team_id, target_id))


def _import(engine, team_id: int, user_id: int, body: ImportBody) -> dict:
    now = utcnow()
    try:
        parsed = parse_csv(body.content) if body.format == "csv" else parse_json(body.content)
    except InventoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the inventory")
        if body.inventory_source_id:
            source = _owned_source(session, team_id, body.inventory_source_id)
            if source.kind not in ("csv", "json"):
                raise HTTPException(status_code=400, detail="inventory_source_id: import into a CSV or JSON source "
                                                            "(AWS sources sync, API sources take PUT)")
        else:
            source = _source_named(session, team_id, body.format, DEFAULT_IMPORT_NAMES[body.format], user_id, now)
        out = _save(session, team_id, user_id, source, parsed, now, snapshot=True, dry_run=body.dry_run,
                    action="fleet.inventory.import")
        if body.dry_run:
            session.rollback()
        else:
            session.commit()
        log("inventory imported", team=team_id, source=source.id, rows=parsed.rows, created=out["created"],
            updated=out["updated"], unchanged=out["unchanged"], missing=out["missing"], errors=parsed.error_count,
            dry_run=body.dry_run, by=user_id)
        return out


@router.post(INV + "/import", dependencies=WRITE, openapi_extra=permission("cbom.inventory.write"),
             summary="Import targets from CSV or JSON (≤ 10 MB, ≤ 10,000 rows; upsert on external_id; dry_run)")
async def import_targets(team_id: TeamId, ctx: Member, request: Request):
    engine, user = ctx
    raw = await read_capped_json(request, IMPORT_BODY_LIMIT)
    try:
        body = ImportBody.model_validate(raw)
    except ValidationError as exc:
        raise bad_request(exc) from None
    return _ok(await _run("import", team_id, _import, engine, team_id, user.id, body))


def _put_targets(engine, team_id: int, user_id: int, body: ApiTargetsBody) -> dict:
    now = utcnow()
    try:
        parsed = _collect(((i, row) for i, row in enumerate(body.targets, start=1)), len(body.targets))
    except InventoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the inventory")
        source = _source_named(session, team_id, "api", body.source_name, user_id, now)
        out = _save(session, team_id, user_id, source, parsed, now, snapshot=False, dry_run=False,
                    action="fleet.inventory.put")
        session.commit()
        return out


@router.put(INV + "/targets", dependencies=WRITE, openapi_extra=permission("cbom.inventory.write"),
            summary="Add or update up to 1,000 targets through the API (an API inventory source, by name)")
async def put_targets(team_id: TeamId, ctx: Member, request: Request):
    engine, user = ctx
    raw = await read_capped_json(request, API_BODY_LIMIT)
    try:
        body = ApiTargetsBody.model_validate(raw)
    except ValidationError as exc:
        raise bad_request(exc) from None
    return _ok(await _run("put targets", team_id, _put_targets, engine, team_id, user.id, body))


def _delete_target(engine, team_id: int, user_id: int, target_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the inventory")
        row = session.get(CbomInventoryTarget, target_id)
        if row is None or row.team_id != team_id:
            raise HTTPException(status_code=404, detail="Target not found")
        session.exec(update(CbomInventoryTarget).where(CbomInventoryTarget.id == target_id).values(  # type: ignore[call-overload]
            missing_since=row.missing_since or now, managed_source_id=None, last_updated=now,
            row_version=CbomInventoryTarget.row_version + 1))
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.inventory_target.delete",
              object_type="inventory_target", object_id=target_id)
        session.commit()
        return {"deleted": target_id}


@router.delete(INV + "/targets/{target_id}", dependencies=WRITE, openapi_extra=permission("cbom.inventory.write"),
               summary="Mark a target missing and take it out of its managed source (soft delete)")
async def delete_target(team_id: TeamId, target_id: ObjectId, ctx: Member):
    engine, user = ctx
    return _ok(await _run("delete target", team_id, _delete_target, engine, team_id, user.id, target_id))


# ----------------------------------------------------------------------------- inventory sources
def _counts_by_source(session: Session, team_id: int) -> dict[int, int]:
    t = CbomInventoryTarget
    rows = session.exec(select(t.inventory_source_id, func.count()).where(t.team_id == team_id, t.missing_since.is_(None))  # type: ignore[union-attr]
                        .group_by(t.inventory_source_id)).all()
    return {int(sid): int(n) for sid, n in rows}


def _list_sources(engine, team_id: int) -> dict:
    with Session(engine) as session:
        counts = _counts_by_source(session, team_id)
        rows = session.exec(select(CbomInventorySource).where(CbomInventorySource.team_id == team_id,
                                                              CbomInventorySource.deleted_at.is_(None))  # type: ignore[union-attr]
                            .order_by(CbomInventorySource.id)).all()
        aws = session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id,
                                                              CbomCollectionSource.kind == "aws_account")).all()
        return {"sources": [public_inventory_source(r, counts.get(r.id, 0)) for r in rows],
                "aws_accounts": [{"id": a.id, "name": a.name, "validated": a.last_test_status == "passed"} for a in aws]}


@router.get(INV + "/sources", dependencies=READ, openapi_extra=permission("cbom.fleet.read"),
            summary="Inventory sources (AWS, CSV, JSON, API) with their last sync")
async def list_sources(team_id: TeamId, ctx: Member):
    engine, _user = ctx
    return _ok(await _run("list inventory sources", team_id, _list_sources, engine, team_id))


def _check_aws_config(session: Session, team_id: int, config: dict[str, Any]) -> dict[str, Any]:
    try:
        cfg = AwsInventoryConfig.model_validate(config)
    except ValidationError as exc:
        raise bad_request(exc) from None
    account = session.get(CbomCollectionSource, cfg.aws_account_source_id)
    if account is None or account.team_id != team_id or account.kind != "aws_account":
        raise HTTPException(status_code=400, detail="aws_account_source_id: the AWS account was not found in this team")
    return cfg.model_dump()


def _create_source(engine, team_id: int, user_id: int, body: InventorySourceCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "inventory sources")
        _check_source_cap(session, team_id)
        config = _check_aws_config(session, team_id, body.config) if body.kind == "aws" else {}
        if body.kind != "aws" and body.config:
            raise HTTPException(status_code=400, detail="config: only AWS inventory sources have settings")
        row = CbomInventorySource(team_id=team_id, owner_user_id=user_id, updated_by_user_id=user_id, kind=body.kind,
                                  name=body.name, config=config, sync_every_min=body.sync_every_min,
                                  enabled=body.enabled, created_at=now, last_updated=now)
        session.add(row)
        session.flush()
        if body.kind == "aws" and body.enabled:
            SYNC.request_sync(session, row, now)  # the first sync runs right away
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.inventory_source.create",
              object_type="inventory_source", object_id=row.id, changed_fields=body.model_dump(exclude_unset=True).keys())
        session.commit()
        session.refresh(row)
        return {"source": public_inventory_source(row, 0)}


@router.post(INV + "/sources", dependencies=WRITE, openapi_extra=permission("cbom.inventory.write"),
             summary="Add an inventory source (AWS: an AWS account of the team, regions and services)")
async def create_source(team_id: TeamId, ctx: Member, body: InventorySourceCreate):
    engine, user = ctx
    return _ok(await _run("create inventory source", team_id, _create_source, engine, team_id, user.id, body), 201)


def _update_source(engine, team_id: int, user_id: int, source_id: int, body: InventorySourceUpdate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "inventory sources")
        row = _owned_source(session, team_id, source_id)
        check_version(row, body.expected_version)
        fields = body.model_dump(exclude_unset=True, exclude={"expected_version"})
        if "config" in fields and fields["config"] is not None:
            if row.kind != "aws":
                raise HTTPException(status_code=400, detail="config: only AWS inventory sources have settings")
            row.config = _check_aws_config(session, team_id, fields["config"])
        for name in ("name", "sync_every_min", "enabled"):
            if fields.get(name) is not None:
                setattr(row, name, fields[name])
        bump_version(session, row)
        row.updated_by_user_id, row.last_updated = user_id, now
        session.add(row)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.inventory_source.update",
              object_type="inventory_source", object_id=row.id, changed_fields=fields.keys())
        session.commit()
        session.refresh(row)
        return {"source": public_inventory_source(row, _counts_by_source(session, team_id).get(row.id, 0))}


@router.patch(INV + "/sources/{source_id}", dependencies=WRITE, openapi_extra=permission("cbom.inventory.write"),
              summary="Edit, pause or resume an inventory source")
async def update_source(team_id: TeamId, source_id: ObjectId, ctx: Member, body: InventorySourceUpdate):
    engine, user = ctx
    return _ok(await _run("update inventory source", team_id, _update_source, engine, team_id, user.id, source_id, body))


def _delete_source(engine, team_id: int, user_id: int, source_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "inventory sources")
        row = _owned_source(session, team_id, source_id)
        row.deleted_at, row.enabled, row.last_updated = now, False, now
        bump_version(session, row)
        session.add(row)
        # its targets are no longer seen: missing (kept for history; a policy stops collecting them after 7 days)
        session.exec(update(CbomInventoryTarget).where(  # type: ignore[call-overload]
            CbomInventoryTarget.team_id == team_id, CbomInventoryTarget.inventory_source_id == source_id,
            CbomInventoryTarget.missing_since.is_(None)).values(missing_since=now, last_updated=now))  # type: ignore[union-attr]
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.inventory_source.delete",
              object_type="inventory_source", object_id=row.id)
        session.commit()
        return {"deleted": source_id}


@router.delete(INV + "/sources/{source_id}", dependencies=WRITE, openapi_extra=permission("cbom.inventory.write"),
               summary="Delete an inventory source (its targets are marked missing)")
async def delete_source(team_id: TeamId, source_id: ObjectId, ctx: Member):
    engine, user = ctx
    return _ok(await _run("delete inventory source", team_id, _delete_source, engine, team_id, user.id, source_id))


def _sync_source(engine, team_id: int, user_id: int, source_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "inventory sources")
        row = _owned_source(session, team_id, source_id)
        if row.kind != "aws":
            raise HTTPException(status_code=400, detail="Only AWS inventory sources sync; import a file or PUT targets")
        if not row.enabled:
            raise HTTPException(status_code=400, detail="The inventory source is paused; resume it first")
        if row.last_sync_status == "running" and row.lease_until and row.lease_until > now:
            raise HTTPException(status_code=409, detail="A sync of this source is already running")
        sync_id = SYNC.request_sync(session, row, now)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.inventory_source.sync",
              object_type="inventory_source", object_id=row.id)
        session.commit()
        return {"sync_id": sync_id, "status": "queued"}


@router.post(INV + "/sources/{source_id}/sync", dependencies=WRITE, openapi_extra=permission("cbom.inventory.write"),
             summary="Sync an AWS inventory source now (runs on the inventory thread)")
async def sync_source(team_id: TeamId, source_id: ObjectId, ctx: Member):
    engine, user = ctx
    return _ok(await _run("sync inventory source", team_id, _sync_source, engine, team_id, user.id, source_id), 202)
