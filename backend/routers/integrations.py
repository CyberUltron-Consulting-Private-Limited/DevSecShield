"""Integrations (WP11): ServiceNow, syslog / Splunk HEC (SIEM), signed webhooks, OSCAL push; OSCAL export; CMDB import.

Conventions of the CBOM Sources API (``backend/utilities/cbom_sources/http.py``): team members only (the existing 403
for non-members); another team's or a missing record is a 404; a change needs a team admin (400, never 403, which
signs the user out of the frontend); a stale form gets 409; validation errors are a 400 that never echoes input.

* Secrets are write-only: accepted in ``secrets``, stored encrypted, never returned (``secrets_set`` lists names).
  Changing where an integration sends (URL, host, instance, user, client id, CA) clears its stored secret unless it is
  re-entered, so a token can never be redirected by someone who cannot see it.
* A connection test and every delivery go through ``integrations.outbound`` (SSRF guard); results carry a status and
  a short reason, never a response body.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import CbomCollectionRun, IntegrationDelivery, Scan, TeamIntegration
from backend.utilities.cbom_sources.common import audit, iso_z, log, utcnow
from backend.utilities.cbom_sources.crypto import decrypt_secrets, encrypt_secrets
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    ObjectId,
    TeamId,
    authorize,
    bad_request,
    check_version,
    read_limiter,
    require_admin,
    server_error,
    write_limiter,
)
from backend.utilities.integrations import cmdb as CMDB
from backend.utilities.integrations import oscal as OSCAL
from backend.utilities.integrations import outbound
from backend.utilities.integrations import servicenow as SN
from backend.utilities.integrations.base import Context, Outcome
from backend.utilities.integrations.dispatch import context_for, queue_counts
from backend.utilities.integrations.events import EVENT_KINDS, SCHEMA, TYPES
from backend.utilities.integrations.registry import KINDS, SPECS, validate_config
from backend.utilities.integrations.webhook import MIN_SECRET, VERIFY_SNIPPET

router = APIRouter(tags=["integrations"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
BASE = "/{team_id}/integrations"
SRC = "/{team_id}/cbom/sources"
CODE = "/{team_id}/cbom/code-scans"
MAX_SECRET = 4096
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"integrations {what}", exc, team=team_id) from None


def _ok(payload: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=PRIVATE)


def _kind(kind: str) -> str:
    if kind not in SPECS:
        raise HTTPException(status_code=404, detail="Unknown integration")
    return kind


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class IntegrationSave(_Body):
    enabled: bool = False
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    clear_secrets: list[str] = Field(default_factory=list, max_length=10)
    expected_version: int | None = None


class RetryBody(_Body):
    ids: list[int] = Field(default_factory=list, max_length=500)
    kind: str | None = None
    all_dead: bool = False


class CmdbBody(_Body):
    source: Literal["csv", "servicenow"] = "csv"
    csv: str | None = Field(default=None, max_length=CMDB.MAX_CSV_BYTES)
    node_id: int | None = Field(default=None, ge=1, le=2_147_483_647)
    create_missing: bool = True
    digest: str | None = Field(default=None, max_length=64)


# ============================================================================ integrations
def public_integration(spec_kind: str, row: TeamIntegration | None, counts: dict[str, int] | None) -> dict[str, Any]:
    spec = SPECS[spec_kind]
    out: dict[str, Any] = {"kind": spec_kind, "label": spec.label, "configured": row is not None,
                           "allowed_events": list(spec.allowed_events), "default_events": list(spec.default_events)}
    if row is None:
        return {**out, "enabled": False, "config": None, "secrets_set": [], "row_version": None,
                "queue": {}, "last_test": None}
    try:
        required = sorted(spec.secret_fields(validate_config(spec_kind, row.config or {})))
    except (ValidationError, ValueError):
        required = []
    return {**out, "id": row.id, "enabled": row.enabled, "config": row.config or {},
            "secrets_set": sorted(row.secret_fields or []), "secrets_required": required,
            "row_version": row.row_version, "queue": counts or {},
            "last_test": {"status": row.last_test_status, "at": iso_z(row.last_test_at),
                          "message": row.last_test_message},
            "failures": row.failures, "next_attempt_at": iso_z(row.next_attempt_at),
            "last_delivery_at": iso_z(row.last_delivery_at), "last_error": row.last_error,
            "updated_at": iso_z(row.last_updated)}


def _list(engine, team_id: int) -> dict:
    with Session(engine) as session:
        rows = {r.kind: r for r in session.exec(select(TeamIntegration).where(TeamIntegration.team_id == team_id)).all()}
        counts = queue_counts(session, team_id)
        return {"integrations": [public_integration(k, rows.get(k), counts.get(rows[k].id) if k in rows else None)
                                 for k in KINDS],
                "event_types": {k: TYPES[k] for k in EVENT_KINDS}, "schema": SCHEMA,
                "webhook_verify_snippet": VERIFY_SNIPPET,
                "private_destinations": {"env": outbound.ENV_ALLOWED_PRIVATE,
                                         "configured": bool(outbound.allowlist().networks or outbound.allowlist().hosts)}}


@router.get(BASE, dependencies=READ, summary="Integrations of the team (secrets are never returned)")
async def list_integrations(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("list", team_id, _list, engine, team_id))


def _check_secret(kind: str, name: str, value: str) -> str:
    if len(value) > MAX_SECRET or _CTRL.search(value):
        raise HTTPException(status_code=400, detail=f"secrets.{name}: at most {MAX_SECRET} printable characters")
    if name == "signing_secret" and len(value) < MIN_SECRET:
        raise HTTPException(status_code=400, detail=f"secrets.{name}: use at least {MIN_SECRET} characters")
    return value


def _save(engine, team_id: int, user_id: int, kind: str, body: IntegrationSave) -> dict:
    spec = SPECS[kind]
    try:
        cfg = validate_config(kind, body.config)
    except (ValidationError, ValueError) as exc:
        err = bad_request(exc)
        err.detail = f"config.{err.detail}" if not str(err.detail).startswith("config") else err.detail
        raise err from None
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "integrations")
        row = session.exec(select(TeamIntegration).where(TeamIntegration.team_id == team_id,
                                                         TeamIntegration.kind == kind)).first()
        if row is not None:
            check_version(row, body.expected_version)
        new_dump = cfg.model_dump(mode="json")
        old_dump = (row.config or {}) if row is not None else {}
        current = decrypt_secrets(row.secret_encrypted) if row is not None else {}
        where_changed = row is not None and any(old_dump.get(f) != new_dump.get(f) for f in spec.where_fields)
        required = spec.secret_fields(cfg)
        merged = {} if where_changed else {k: v for k, v in current.items() if k in required}
        for name in body.clear_secrets:
            merged.pop(name, None)
        for name, value in body.secrets.items():
            if value == "":
                continue
            if name not in required:
                raise HTTPException(status_code=400, detail=f"secrets.{name}: not used by this integration")
            merged[name] = _check_secret(kind, name, value)
        missing = sorted(required - set(merged))
        if missing and body.enabled:
            if where_changed and current:
                raise HTTPException(status_code=400, detail=f"secrets.{missing[0]}: re-enter it; a stored secret is "
                                                            "cleared when the destination changes")
            raise HTTPException(status_code=400, detail=f"secrets.{missing[0]}: required to turn this integration on")
        changed = []
        if row is None:
            row = TeamIntegration(team_id=team_id, kind=kind, created_at=now)
            changed.append("kind")
        if row.config != new_dump:
            changed.append("config")
        if row.enabled != body.enabled:
            changed.append("enabled")
        if merged != current:
            changed += [f"secrets.{k}" for k in sorted(set(merged) | set(current))]
            row.secret_encrypted, row.secret_fields = encrypt_secrets(merged), sorted(merged)
        if changed:
            if where_changed or "secrets" in " ".join(changed):
                row.last_test_status, row.last_test_at, row.last_test_message = "never", None, None
            if "enabled" in changed and body.enabled:
                row.failures, row.next_attempt_at, row.last_error = 0, None, None
            row.config, row.enabled = new_dump, body.enabled
            row.row_version = (row.row_version or 0) + (1 if row.id is not None else 0)
            row.updated_by_user_id, row.last_updated = user_id, now
            session.add(row)
            session.flush()
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="integration.save",
                  object_type="integration", object_id=row.id, changed_fields=changed)
            session.commit()
            session.refresh(row)
            log("integration saved", team=team_id, kind=kind, by=user_id, enabled=row.enabled, fields=len(changed))
        counts = queue_counts(session, team_id).get(row.id or 0)
        return {"integration": public_integration(kind, row, counts)}


@router.put(BASE + "/{kind}", dependencies=WRITE, summary="Create or update an integration (admin; secrets are write-only)")
async def save_integration(team_id: TeamId, kind: str, body: IntegrationSave, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("save", team_id, _save, engine, team_id, user.id, _kind(kind), body))


def _delete(engine, team_id: int, user_id: int, kind: str) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "integrations")
        row = session.exec(select(TeamIntegration).where(TeamIntegration.team_id == team_id,
                                                         TeamIntegration.kind == kind)).first()
        if row is None:
            raise HTTPException(status_code=404, detail="Integration not configured")
        for delivery in session.exec(select(IntegrationDelivery).where(IntegrationDelivery.integration_id == row.id)).all():
            session.delete(delivery)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="integration.delete",
              object_type="integration", object_id=row.id)
        session.delete(row)
        session.commit()
        log("integration deleted", team=team_id, kind=kind, by=user_id)
        return {"deleted": kind}


@router.delete(BASE + "/{kind}", dependencies=WRITE, summary="Remove an integration and its delivery log (admin)")
async def delete_integration(team_id: TeamId, kind: str, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("delete", team_id, _delete, engine, team_id, user.id, _kind(kind)))


def test_event(team_id: int) -> dict[str, Any]:
    return {"schema": SCHEMA, "id": str(uuid.uuid4()), "type": "integration.test", "kind": "test",
            "time": iso_z(utcnow()), "team_id": team_id, "severity": "Info", "scope": "node", "run_id": None,
            "baseline_run_id": None, "scan_id": None, "baseline_scan_id": None,
            "source": {"ref": "test", "name": "ZeroShield integration test"}, "asset": None, "finding": None,
            "detail": {"message": "Connection test from ZeroShield DevSecShield; safe to ignore."}}


def _test(engine, team_id: int, user_id: int, kind: str) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "integrations")
        row = session.exec(select(TeamIntegration).where(TeamIntegration.team_id == team_id,
                                                         TeamIntegration.kind == kind)).first()
        if row is None:
            raise HTTPException(status_code=400, detail="Save the integration before testing it")
        try:
            ctx = context_for(row, engine)
        except (ValidationError, ValueError) as exc:
            raise bad_request(exc) from None
        missing = sorted(SPECS[kind].secret_fields(ctx.config) - set(ctx.secrets))
        if missing:
            raise HTTPException(status_code=400, detail=f"secrets.{missing[0]}: required before testing")
        integration_id = row.id
    try:
        outcome = SPECS[kind].test(ctx, test_event(team_id))
    except Exception as exc:  # a connector bug must not become a 500 with details
        outcome = Outcome("retry", f"the test could not run ({type(exc).__name__})")
    now = utcnow()
    ok = outcome.status == "ok"
    # "unconfirmed": sent, but the destination cannot acknowledge it (syslog over UDP): never shown as passed
    status = ("ok" if outcome.confirmed else "unconfirmed") if ok else "failed"
    with Session(engine) as session:
        session.exec(update(TeamIntegration).where(TeamIntegration.id == integration_id).values(
            last_test_status=status, last_test_at=now, last_test_message=outcome.reason[:255]))
        # a test sends data (or, for ServiceNow, reads a record) at an external destination: audited like a change
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="integration.test",
              object_type="integration", object_id=integration_id, changed_fields=["last_test_status"])
        session.commit()
    log("integration tested", team=team_id, kind=kind, by=user_id, ok=ok, status=status)
    return {"ok": ok, "confirmed": ok and outcome.confirmed, "status": status, "message": outcome.reason,
            "at": iso_z(now)}


@router.post(BASE + "/{kind}/test", dependencies=WRITE,
             summary="Send a test event (ServiceNow: read one record) and report the status (admin)")
async def test_integration(team_id: TeamId, kind: str, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("test", team_id, _test, engine, team_id, user.id, _kind(kind)))


def _public_delivery(d: IntegrationDelivery) -> dict[str, Any]:
    payload = d.payload or {}
    return {"id": d.id, "kind": d.kind, "event_id": d.event_uid, "event_type": d.event_type, "status": d.status,
            "attempts": d.attempts, "queued_at": iso_z(d.created_at), "last_attempt_at": iso_z(d.last_attempt_at),
            "delivered_at": iso_z(d.delivered_at), "result": d.last_result, "external_ref": d.external_ref,
            "code": (payload.get("finding") or {}).get("code"), "asset": (payload.get("asset") or {}).get("label"),
            "source": (payload.get("source") or {}).get("name"), "run_id": payload.get("run_id"),
            "scan_id": payload.get("scan_id")}


def _deliveries(engine, team_id: int, kind: str | None, status: str | None, before_id: int | None, limit: int) -> dict:
    with Session(engine) as session:
        query = select(IntegrationDelivery).where(IntegrationDelivery.team_id == team_id)
        if kind:
            query = query.where(IntegrationDelivery.kind == kind)
        if status:
            query = query.where(IntegrationDelivery.status == status)
        if before_id:
            query = query.where(IntegrationDelivery.id < before_id)
        rows = session.exec(query.order_by(IntegrationDelivery.id.desc()).limit(limit)).all()  # type: ignore[union-attr]
        items = [_public_delivery(d) for d in rows]
        return {"deliveries": items, "next_before_id": items[-1]["id"] if len(items) == limit else None}


@router.get(BASE + "/deliveries", dependencies=READ, summary="Delivery log and dead-letter list (newest first)")
async def list_deliveries(team_id: TeamId, kind: str | None = Query(default=None, max_length=16),
                          status: str | None = Query(default=None, pattern="^(pending|delivered|dead)$"),
                          before_id: int | None = Query(default=None, ge=1, le=2_147_483_647),
                          limit: int = Query(default=50, ge=1, le=200), Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    if kind is not None:
        _kind(kind)
    return _ok(await _run("deliveries", team_id, _deliveries, engine, team_id, kind, status, before_id, limit))


def _retry(engine, team_id: int, user_id: int, body: RetryBody) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "integrations")
        query = update(IntegrationDelivery).where(IntegrationDelivery.team_id == team_id,
                                                  IntegrationDelivery.status == "dead")
        if body.ids:
            query = query.where(IntegrationDelivery.id.in_(body.ids))  # type: ignore[union-attr]
        elif body.all_dead and body.kind:
            query = query.where(IntegrationDelivery.kind == _kind(body.kind))
        else:
            raise HTTPException(status_code=400, detail="Choose deliveries (ids) or all dead ones of one integration")
        n = int(session.exec(query.values(status="pending", created_at=now, last_result="queued again")).rowcount or 0)
        session.exec(update(TeamIntegration).where(TeamIntegration.team_id == team_id).values(next_attempt_at=None))
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="integration.retry",
              object_type="integration", object_id=None, changed_fields=["status"])
        session.commit()
        log("integration deliveries requeued", team=team_id, by=user_id, count=n)
        return {"requeued": n}


@router.post(BASE + "/deliveries/retry", dependencies=WRITE, summary="Queue dead-lettered deliveries again (admin)")
async def retry_deliveries(team_id: TeamId, body: RetryBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("retry", team_id, _retry, engine, team_id, user.id, body))


# ============================================================================ OSCAL export
def _oscal_response(doc: dict[str, Any], filename: str) -> Response:
    problems = OSCAL.validate(doc)
    if problems:
        raise RuntimeError(f"OSCAL schema validation failed: {problems[0][:200]}")
    body = json.dumps(doc, indent=1, ensure_ascii=False).encode("utf-8")
    return Response(body, media_type="application/json",
                    headers={**PRIVATE, "Content-Disposition": f'attachment; filename="{filename}"'})


def _run_oscal(engine, team_id: int, run_id: int) -> Response:
    from backend.utilities.cbom_sources.drift import FINISHED

    with Session(engine) as session:
        run = session.get(CbomCollectionRun, run_id)
        if run is None or run.team_id != team_id:
            raise HTTPException(status_code=404, detail="Run not found")
        if run.status not in FINISHED:
            raise HTTPException(status_code=400, detail="The run has not finished yet")
        doc = OSCAL.run_document(session, run)
    return _oscal_response(doc, f"zeroshield-cbom-run-{run_id}-oscal-assessment-results.json")


@router.get(SRC + "/runs/{run_id}/oscal", dependencies=READ,
            summary="OSCAL 1.2.3 assessment results of a finished collection run (schema-validated)")
async def run_oscal(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return await _run("run oscal", team_id, _run_oscal, engine, team_id, run_id)


def _scan_oscal(engine, team_id: int, scan_id: int) -> Response:
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None or scan.team_id != team_id or scan.scan_type != "cbom":
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.scan_status != "success":
            raise HTTPException(status_code=400, detail="The scan has not finished successfully")
        doc = OSCAL.scan_document(scan)
    return _oscal_response(doc, f"zeroshield-cbom-scan-{scan_id}-oscal-assessment-results.json")


@router.get(CODE + "/{scan_id}/oscal", dependencies=READ,
            summary="OSCAL 1.2.3 assessment results of a CBOM code scan (schema-validated)")
async def scan_oscal(team_id: TeamId, scan_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return await _run("scan oscal", team_id, _scan_oscal, engine, team_id, scan_id)


# ============================================================================ CMDB import
def _cmdb_rows(engine, team_id: int, body: CmdbBody) -> tuple[list[dict[str, Any]], bool]:
    if body.source == "csv":
        if not body.csv or not body.csv.strip():
            raise HTTPException(status_code=400, detail="csv: paste or upload a CSV file")
        try:
            return CMDB.parse_csv(body.csv), False
        except CMDB.ImportError_ as exc:
            raise HTTPException(status_code=400, detail=f"csv: {exc}") from None
    with Session(engine) as session:
        row = session.exec(select(TeamIntegration).where(TeamIntegration.team_id == team_id,
                                                         TeamIntegration.kind == "servicenow")).first()
        if row is None:
            raise HTTPException(status_code=400, detail="Set up the ServiceNow integration first (Settings > Integrations)")
        try:
            ctx: Context = context_for(row, engine)
        except (ValidationError, ValueError) as exc:
            raise bad_request(exc) from None
    if SPECS["servicenow"].secret_fields(ctx.config) - set(ctx.secrets):
        raise HTTPException(status_code=400, detail="The ServiceNow integration has no stored credential")
    try:
        return SN.cmdb_rows(ctx)
    except (outbound.Refused, outbound.TransportError, PermissionError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=f"ServiceNow CMDB: {str(exc)[:240]}") from None


def _cmdb_preview(engine, team_id: int, user_id: int, body: CmdbBody) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "sources from a CMDB")
    rows, truncated = _cmdb_rows(engine, team_id, body)
    with Session(engine) as session:
        plan = CMDB.build_plan(session, team_id, rows, create_missing=body.create_missing)
    return {"source": body.source, "source_truncated": truncated, "plan": plan.public()}


@router.post(SRC + "/cmdb/preview", dependencies=WRITE,
             summary="CMDB import preview: which sources would be created or have metadata updated (admin; changes nothing)")
async def cmdb_preview(team_id: TeamId, body: CmdbBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("cmdb preview", team_id, _cmdb_preview, engine, team_id, user.id, body))


def _cmdb_apply(engine, team_id: int, user_id: int, body: CmdbBody) -> dict:
    if not body.digest:
        raise HTTPException(status_code=400, detail="digest: preview first, then confirm that preview")
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "sources from a CMDB")
    rows, _truncated = _cmdb_rows(engine, team_id, body)
    with Session(engine) as session:
        plan = CMDB.build_plan(session, team_id, rows, create_missing=body.create_missing)
        if plan.digest() != body.digest:
            raise HTTPException(status_code=409, detail="The sources or the CMDB changed since the preview. Preview again.")
        try:
            result = CMDB.apply_plan(session, team_id, user_id, plan, node_id=body.node_id)
        except (ValidationError, ValueError) as exc:
            session.rollback()
            raise bad_request(exc) from None
        session.commit()
    return {"result": result, "plan": plan.public()}


@router.post(SRC + "/cmdb/apply", dependencies=WRITE,
             summary="Apply a previewed CMDB import (admin; metadata edits never cancel running jobs)")
async def cmdb_apply(team_id: TeamId, body: CmdbBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("cmdb apply", team_id, _cmdb_apply, engine, team_id, user.id, body))


__all__ = ["router", "public_integration", "test_event"]
