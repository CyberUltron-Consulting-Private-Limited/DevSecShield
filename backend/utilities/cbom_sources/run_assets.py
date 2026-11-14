"""A run's assets as rows of the unified CBOM results table (CB-38 PR-1a): ``GET /{team}/cbom/sources/runs/{id}/assets``.

Additive over ``inventory.list_assets`` (its items, totals, facets and targets are returned unchanged):

* ``view=all`` (default: today's list) or ``view=findings`` (assets that are not ``coverage`` rows and have an impact,
  judged today exactly as the list shows the impact); ``status=not_started|in_progress|fixed|ignored`` keeps the
  assets whose remediation assignment is in that bucket (``contracts/cbom/status_buckets.json``; no assignment is
  ``not_started``; ``coverage`` rows are never plannable: their ``status`` is null and a status filter leaves them
  out).
* every item gains ``asset_key`` (the stable key ``waves.node_items`` gives the asset; null for a ``coverage`` row,
  whose ``risk_score`` is 0 as it is never a finding),
  ``status`` / ``assignment_status``, ``wave`` (the asset's ``node_items`` entry, computed for the page's assets only),
  ``risk_score`` (0-10, ``bom_risk_score.cbom_finding_risk_score`` over ``collections_view.node_row``), the code-lane
  names from ``node_row`` (``algorithm_name``, ``algorithm_type``, ``crypto_strength``, ``quantum_safe``,
  ``description``) and ``type_label``;
* the response gains ``findings_total`` (the run's findings, judged today) next to ``all_total`` and ``total``.

Fields other features add to the items (``q_grade``, ``q_label``, ``fix_class`` ...) pass through untouched.
"""
from __future__ import annotations

import datetime as _dt
import time
from types import SimpleNamespace
from typing import Any

from sqlalchemy import and_, false, func, or_
from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSource
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources import inventory as INV
from backend.utilities.cbom_sources import waves as WAVES
from backend.utilities.cbom_sources.collections_view import Collection, node_row
from backend.utilities.cbom_sources.run_list import finding_status, log_line

VIEWS = ("all", "findings")
FINDING_STATUSES = ("not_started", "in_progress", "fixed", "ignored")
IMPACTS = ("Critical", "High", "Medium", "Low")
COVERAGE = "coverage"
_UTC = _dt.timezone.utc

# The run table's type names (frontend RunResults.tsx ASSET_TYPE_LABEL), so both lanes' tables print one column.
TYPE_LABEL = {
    "certificate": "Certificate", "private_key": "Private key", "public_key": "Public key", "keystore": "Keystore",
    "ssh_host_key": "SSH host key", "ssh_server_config": "SSH server config", "ssh_endpoint": "SSH endpoint",
    "tls_endpoint": "TLS endpoint", "crypto_library": "Crypto library", "process_library": "Process library",
    "disk_encryption": "Disk encryption", "os_crypto_policy": "OS crypto policy", "database_tls": "Database TLS",
    "database_config": "Database settings", "database_user_auth": "Database authentication",
    "k8s_cluster": "Kubernetes cluster", "k8s_tls_secret": "Kubernetes TLS secret",
    "k8s_certificate": "cert-manager certificate", "k8s_ingress_tls": "Ingress TLS",
    "k8s_mesh_policy": "Mesh mTLS policy", "kms_key": "KMS key", "cloud_secret": "Cloud secret",
    "host_secret": "Secret in a service or script", "crypto_config": "Crypto configuration",
    "storage_encryption": "Storage encryption", "load_balancer_tls": "Load balancer TLS", "cdn_tls": "CDN TLS",
    "api_tls": "API TLS", "cloud_ca": "Certificate authority", "iam_certificate": "IAM certificate",
    "identity_provider": "Identity provider", "signing_key": "Signing key", "open_port": "Open port",
    "glue_catalog": "Glue Data Catalog", "glue_connection": "Glue connection", "key_vault": "Key vault",
    "coverage": "Not collected",
}


def type_label(asset_type: str | None) -> str:
    value = str(asset_type or "")
    return TYPE_LABEL.get(value) or (value.replace("_", " ").capitalize() if value else "Other")


# ----------------------------------------------------------------------------- filters
def _findings_clause(changed: dict[int, dict[str, Any]]):
    """Not ``coverage`` and an impact, by today's verdict (a row a date-based rule changed is judged by today's)."""
    stored = CbomCollectedAsset.impact.in_(IMPACTS)  # type: ignore[union-attr]
    if changed:
        stored = and_(stored, CbomCollectedAsset.id.notin_(list(changed)))  # type: ignore[union-attr]
        today = [aid for aid, view in changed.items() if view.get("impact") in IMPACTS]
        if today:
            stored = or_(stored, CbomCollectedAsset.id.in_(today))  # type: ignore[union-attr]
    return and_(CbomCollectedAsset.asset_type != COVERAGE, stored)


def _job_refs(session: Session, team_id: int, run: CbomCollectionRun) -> dict[int, str]:
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id,
                                                        CbomCollectionJob.run_id == run.id)).all()
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    return {int(j.id): ID.job_source_ref(j, sources.get(j.source_id or 0)) for j in jobs}


def run_asset_keys(session: Session, team_id: int, run: CbomCollectionRun) -> dict[int, str]:
    """``asset id -> stable key`` for every non-coverage asset of the run (the key ``waves.node_items`` gives it).
    Certificates are keyed by their subject and issuer, so only their facts are read."""
    refs = _job_refs(session, team_id, run)
    cols = (CbomCollectedAsset.id, CbomCollectedAsset.job_id, CbomCollectedAsset.source_id,
            CbomCollectedAsset.asset_key, CbomCollectedAsset.asset_type, CbomCollectedAsset.cdx_type,
            CbomCollectedAsset.target, CbomCollectedAsset.location)
    scope = (CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id,
             CbomCollectedAsset.asset_type != COVERAGE)
    is_cert = or_(CbomCollectedAsset.cdx_type == ID.CERT_CDX,
                  CbomCollectedAsset.asset_type.in_(("certificate", "k8s_certificate")))  # type: ignore[union-attr]
    out: dict[int, str] = {}
    for with_facts in (False, True):
        query = (select(*cols, CbomCollectedAsset.facts).where(*scope, is_cert) if with_facts
                 else select(*cols).where(*scope, ~is_cert))
        for rec in session.exec(query).all():
            aid, job_id, source_id, asset_key, asset_type, cdx_type, target, location = rec[:8]
            row = SimpleNamespace(asset_key=asset_key, asset_type=asset_type, cdx_type=cdx_type, target=target,
                                  location=location, facts=(rec[8] if with_facts else None) or {})
            ref = refs.get(int(job_id)) if job_id is not None else None
            out[int(aid)] = ID.stable_key("node", ref or f"source-{source_id}", ID.node_identity(row))
    return out


def _status_clause(session: Session, team_id: int, run: CbomCollectionRun, status: str):
    started = time.perf_counter()
    keys = run_asset_keys(session, team_id, run)
    found = WAVES._assignments(session, team_id, keys.values())
    bucket = {aid: finding_status(found[key].status if key in found else None) for aid, key in keys.items()}
    # the cost of this path grows with the run (PR-2's stored keys replace it): one line per request
    log_line(f"cbom run assets status_filter team={team_id} run={run.id} status={status} keys={len(keys)} "
             f"planned={len(found)} ms={int((time.perf_counter() - started) * 1000)}")
    if status == "not_started":  # the common case: exclude the (few) planned assets instead of listing every id
        others = [aid for aid, value in bucket.items() if value != "not_started"]
        clause = CbomCollectedAsset.asset_type != COVERAGE
        return and_(clause, CbomCollectedAsset.id.notin_(others)) if others else clause  # type: ignore[union-attr]
    wanted = [aid for aid, value in bucket.items() if value == status]
    return CbomCollectedAsset.id.in_(wanted) if wanted else false()  # type: ignore[union-attr]


def findings_total(session: Session, team_id: int, run_id: int, changed: dict[int, dict[str, Any]]) -> int:
    """The run's findings judged today (the ``view=findings`` total with no other filter)."""
    query = select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id,
        CbomCollectedAsset.asset_type != COVERAGE, CbomCollectedAsset.impact.in_(IMPACTS))  # type: ignore[union-attr]
    if changed:
        query = query.where(CbomCollectedAsset.id.notin_(list(changed)))  # type: ignore[union-attr]
    stored = int(session.exec(query).one())
    return stored + sum(1 for view in changed.values() if view.get("impact") in IMPACTS)


# ----------------------------------------------------------------------------- item fields
def _aware(moment: _dt.datetime | None) -> _dt.datetime:
    if moment is None:
        return _dt.datetime(1970, 1, 1, tzinfo=_UTC)
    return moment.replace(tzinfo=_UTC) if moment.tzinfo is None else moment.astimezone(_UTC)


def _collections(session: Session, team_id: int, run: CbomCollectionRun, job_ids: set[int]) -> dict[int, Collection]:
    if not job_ids:
        return {}
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id,
                                                        CbomCollectionJob.id.in_(sorted(job_ids)))).all()  # type: ignore[union-attr]
    source_ids = sorted({j.source_id for j in jobs if j.source_id is not None})
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id, CbomCollectionSource.id.in_(source_ids))).all()} if source_ids else {}  # type: ignore[union-attr]
    out: dict[int, Collection] = {}
    for job in jobs:
        src = sources.get(job.source_id or 0)
        out[int(job.id)] = Collection(run_id=int(run.id), job_id=int(job.id), source_ref=ID.job_source_ref(job, src),
                                      source_name=ID.job_source_name(job, src),
                                      source_kind=src.kind if src is not None else "",
                                      observed_at=_aware(job.finished_at or job.created_at))
    return out


def enrich_items(session: Session, team_id: int, run: CbomCollectionRun, items: list[dict[str, Any]]) -> None:
    """Add the unified-table fields to a page of ``inventory.public_asset`` items, in place."""
    from backend.utilities.dashboard.bom_risk_score import cbom_finding_risk_score

    ids = [int(i["id"]) for i in items if i.get("id") is not None]
    if not ids:
        return
    rows = {int(r.id): r for r in session.exec(select(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.id.in_(ids))).all()}  # type: ignore[union-attr]
    plannable = [aid for aid in ids if aid in rows and rows[aid].asset_type != COVERAGE]
    waves = {int(w["asset_id"]): w for w in WAVES.node_items(session, team_id, run, asset_ids=plannable)} if plannable else {}
    collections = _collections(session, team_id, run, {int(r.job_id) for r in rows.values() if r.job_id is not None})
    for item in items:
        row = rows.get(int(item["id"]))
        wave = waves.get(int(item["id"]))
        assignment = (wave or {}).get("assignment") or None
        raw_status = assignment.get("status") if isinstance(assignment, dict) else None
        coverage = item.get("type") == COVERAGE  # "could not read X": never planned, never a finding
        item["asset_key"] = wave["asset_key"] if wave else None
        item["assignment_status"] = raw_status
        item["status"] = None if coverage else finding_status(raw_status)
        item["wave"] = wave
        item["type_label"] = type_label(item.get("type"))
        collection = collections.get(int(row.job_id)) if row is not None and row.job_id is not None else None
        if row is None or collection is None:
            item.update({"risk_score": 0.0, "algorithm_name": item.get("algorithm") or item.get("name"),
                         "algorithm_type": None, "crypto_strength": None, "quantum_safe": None,
                         "description": item.get("finding") or ""})
            continue
        # judged today, exactly as the item shows it (impact, finding sentence, codes)
        code_row = node_row(row, collection, {"impact": item.get("impact"), "finding": item.get("finding"),
                                              "finding_codes": item.get("finding_codes") or []})
        item["risk_score"] = 0.0 if coverage else cbom_finding_risk_score(code_row)
        for key in ("algorithm_name", "algorithm_type", "crypto_strength", "quantum_safe", "description"):
            item[key] = code_row.get(key)


# ----------------------------------------------------------------------------- the page
def list_run_assets(session: Session, *, team_id: int, run: CbomCollectionRun, params: dict[str, Any],
                    view: str = "all", status: str | None = None) -> dict[str, Any]:
    if view not in VIEWS:
        raise ValueError(f"view: {view}")
    if status is not None and status not in FINDING_STATUSES:
        raise ValueError(f"status: {status}")
    seen: dict[str, Any] = {}

    def refine(query, changed: dict[int, dict[str, Any]]):
        seen["changed"] = changed
        if view == "findings":
            query = query.where(_findings_clause(changed))
        if status is not None:
            query = query.where(_status_clause(session, team_id, run, status))
        return query

    out = INV.list_assets(session, team_id=team_id, run_id=run.id, refine=refine, **params)
    out["findings_total"] = findings_total(session, team_id, int(run.id), seen.get("changed") or {})
    out["view"] = view
    out["status_filter"] = status
    enrich_items(session, team_id, run, out["items"])
    return out


__all__ = ["FINDING_STATUSES", "TYPE_LABEL", "VIEWS", "enrich_items", "findings_total", "list_run_assets",
           "run_asset_keys", "type_label"]
