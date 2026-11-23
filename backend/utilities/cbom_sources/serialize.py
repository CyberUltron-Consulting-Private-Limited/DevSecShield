"""Browser-facing shapes.  Each function whitelists fields: secrets and token hashes never appear."""
from __future__ import annotations

import datetime as _dt
import logging
from typing import Any

from backend.new_models import (
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomEvidenceArea,
    CbomEvidenceVendor,
    CbomScanNode,
)
from backend.utilities.cbom_sources.agility import evidence_area_fields, evidence_vendor_fields
from backend.utilities.cbom_sources.common import iso_z
from backend.utilities.cbom_sources.evidence import AREAS, CONFIDENCE_LABEL, area_level, level, vendor_level, vendor_status
from backend.utilities.cbom_sources.jobs import job_waiting_reason, run_credit_summary
from backend.utilities.cbom_sources.kinds import KINDS
from backend.utilities.cbom_sources.node_release import node_update, parse_reported, server_label, server_release
from backend.utilities.cbom_sources.planning import RangeContext, node_status, source_targets
from backend.utilities.cbom_sources.settings import next_window_start
from backend.utilities.cbom_sources import vault_support as VAULT_SUPPORT


_log = logging.getLogger(__name__)


def node_update_or_unknown(reported: str | None, server: tuple[str | None, str | None]) -> dict[str, Any]:
    """``node_update`` for one node, never raising: ``node_version`` is node-controlled text, and one node the comparison
    cannot handle must not 500 the whole Scan nodes list (review of PR #286); that node says "unknown" instead."""
    try:
        return node_update(reported, *server)
    except Exception:  # noqa: BLE001 - report "unknown" for this node, keep the rest of the list
        _log.warning("cbom node update check failed for reported version %r", (reported or "")[:64], exc_info=True)
        return {"state": "unknown", "reason": "compare_failed", "message": None,
                "server_build": server_label(*server)}


def public_node(node: CbomScanNode, now: _dt.datetime, *, assigned_targets: int = 0, sources: int = 0,
                server: tuple[str | None, str | None] | None = None) -> dict[str, Any]:
    """``server``: ``server_release()`` read once by a caller serialising many nodes; read here when not given."""
    status = node_status(node, now)
    _version, build = parse_reported(node.node_version)
    return {
        "id": node.id,
        "team_id": node.team_id,
        "owner_user_id": node.owner_user_id,
        "name": node.name,
        "segment": node.segment,
        "timezone": node.timezone,
        "deployment": node.deployment,
        "proxy_url": node.proxy_url,
        "has_proxy_ca": bool(node.proxy_ca_pem),
        "proxy_tls_inspect": node.proxy_tls_inspect,
        "proxy_user": node.proxy_user,
        "status": status,
        "registration_issued_at": iso_z(node.registration_issued_at),
        "registration_expires_at": iso_z(node.registration_expires_at),
        "enrolled_at": iso_z(node.enrolled_at),
        "hostname": node.hostname,
        "node_version": node.node_version,
        # the commit the node's image was built from (12 characters), None when it reports none (staging QA B6-1)
        "node_build": build,
        # does it run this server's node build? {"state": current|update_available|newer|unknown, "reason", "message",
        # "server_build"} (node_release.node_update)
        "update": node_update_or_unknown(node.node_version, server if server is not None else server_release()),
        "source_ips": node.source_ips or [],
        "ssh_public_key": node.ssh_public_key,
        "capabilities": node.capabilities or {},
        # #364: what the node reported for vault credentials: {"enabled": bool|None (not reported), "providers",
        # "prefix" (without KV v2 data/), "setup": {provider: "ready" or what is missing}}
        "vault": VAULT_SUPPORT.node_vault(node.capabilities),
        "clock_skew_s": node.clock_skew_s,
        "clock_in_sync": None if node.clock_skew_s is None else abs(node.clock_skew_s) <= 300,
        "last_heartbeat_at": iso_z(node.last_heartbeat_at),
        "last_claim_at": iso_z(node.last_claim_at),
        "last_seen_ip": node.last_seen_ip,
        "last_node_error": node.last_node_error,
        # "required": every request is Ed25519-signed with the key sent at enrollment; "legacy": enrolled before
        # signing existed (unsigned until the node is reset and enrolled again)
        "signing": "required" if node.signing_public_key else "legacy",
        "client_cert_sha256": node.client_cert_sha256,
        # "agent": collects only its own host, never given a credential (ZS_MODE=agent, WP8b); pool it enrolled with
        "mode": node.mode or "agentless",
        "pool_id": node.pool_id,
        "assigned_targets": assigned_targets,
        "sources": sources,
        "row_version": node.row_version,
        "created_at": iso_z(node.created_at),
        "last_updated": iso_z(node.last_updated),
    }


def last_collects(session: Any, team_id: int, source_ids: list[int]) -> dict[int, dict[str, Any]]:
    """The newest finished collection of each source: {"status": ok|partial|failed, "at", "summary", "job_id",
    "run_id"}.  A collection that read the source (or failed to) says as much about it as a connection test, so the
    source card judges the newer of the two (owner bug C8: a test that passed days ago kept the card "Passed" after
    the server was gone).  Cancelled jobs say nothing about the source and are left out; "expired" (no node ran it in
    time) is a failure to collect.  One query for the whole list."""
    from sqlmodel import col, func, select

    ids = [i for i in source_ids if i is not None]
    if not ids:
        return {}
    newest = (select(CbomCollectionJob.source_id, func.max(CbomCollectionJob.id).label("job_id"))
              .where(CbomCollectionJob.team_id == team_id, col(CbomCollectionJob.source_id).in_(ids),
                     CbomCollectionJob.kind == "collect",
                     col(CbomCollectionJob.status).in_(("success", "failure", "expired")),
                     col(CbomCollectionJob.finished_at).is_not(None))
              .group_by(CbomCollectionJob.source_id).subquery())
    rows = session.exec(select(CbomCollectionJob).join(newest, CbomCollectionJob.id == newest.c.job_id)).all()
    out: dict[int, dict[str, Any]] = {}
    for job in rows:
        status = job.outcome if job.status == "success" and job.outcome in ("ok", "partial", "failed") else "failed"
        result = job.result if isinstance(job.result, dict) else {}
        summary = job.error or (str(result.get("summary")) if result.get("summary") else None)
        out[int(job.source_id)] = {"status": status, "at": iso_z(job.finished_at), "job_id": job.id,
                                   "run_id": job.run_id, "summary": summary[:512] if summary else None}
    return out


_PCA_ARN = "arn:aws:acm-pca:"


def pca_reads(session: Any, team_id: int, sources: list[CbomCollectionSource],
              accounts: dict[int, CbomCollectionSource] | None = None) -> dict[int, dict[str, Any] | None]:
    """#368: what the newest finished collection of each AWS Private CA source's AWS account read of ACM Private CA.
    The account collector reads acm-pca in every region of the account (aws_collect ``pca``); the Private CA source
    itself never runs, so without this its card could not say whether the CAs were read.  For each such source:
    None while its account is missing or was never collected, else ``{"account_source_id", "job_id", "run_id", "at",
    "status": read|partial|not_read, "cas", "reason", "regions": [{"region", "status", "cas", "error"}]}``: per region
    the acm-pca service status of the job's target rows (``not_read`` when the region was not reached) and the private
    CAs found (``arn:aws:acm-pca:`` assets of the job's current attempt; an RDS CA is a ``cloud_ca`` too, not one)."""
    from sqlmodel import col, select

    from backend.new_models import CbomCollectedAsset, CbomCollectionJob

    pcas = [s for s in sources if s.kind == "ca_connector" and (s.config or {}).get("provider") == "aws_private_ca"]
    if not pcas:
        return {}
    wanted = {int(a) for s in pcas if isinstance(a := (s.config or {}).get("aws_source_id"), int)}
    known = dict(accounts or {})
    missing = [i for i in wanted if i not in known]
    if missing:
        for row in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id,
                                                                   col(CbomCollectionSource.id).in_(missing))).all():
            known[int(row.id)] = row
    accounts_ok = {i for i in wanted if i in known and known[i].kind == "aws_account"}
    collects = last_collects(session, team_id, sorted(accounts_ok))
    jobs = {j.id: j for j in session.exec(select(CbomCollectionJob).where(
        col(CbomCollectionJob.id).in_([c["job_id"] for c in collects.values()]))).all()} if collects else {}
    per_job: dict[int, dict[str, int]] = {}
    for job in jobs.values():
        counts: dict[str, int] = {}
        for loc in session.exec(select(CbomCollectedAsset.location).where(
                CbomCollectedAsset.job_id == job.id, CbomCollectedAsset.attempt == max(int(job.attempts or 1), 1),
                CbomCollectedAsset.asset_type == "cloud_ca", col(CbomCollectedAsset.location).startswith(_PCA_ARN))).all():
            region = str(loc)[len(_PCA_ARN):].split(":", 1)[0]
            counts[region] = counts.get(region, 0) + 1
        per_job[job.id] = counts
    out: dict[int, dict[str, Any] | None] = {}
    for src in pcas:
        account_id = (src.config or {}).get("aws_source_id")
        collect = collects.get(account_id) if account_id in accounts_ok else None
        job = jobs.get(collect["job_id"]) if collect else None
        if job is None:
            out[int(src.id)] = None
            continue
        regions: dict[str, dict[str, Any]] = {}
        result = job.result if isinstance(job.result, dict) else {}
        for target in result.get("targets") or []:
            if not isinstance(target, dict):
                continue
            region = str(target.get("target") or "").rsplit("/", 1)[-1]
            if not region or region == "global" or "/" not in str(target.get("target") or ""):
                continue
            service = (target.get("services") or {}).get("acm-pca")
            status = str(service) if service else "not_read"
            row = regions.setdefault(region, {"region": region, "status": status, "cas": 0, "error": None})
            if row["status"] == "ok" and status != "ok":  # an organisation: one account's region not read is enough
                row["status"] = status
            if status != "ok" and not row["error"] and target.get("error"):
                row["error"] = str(target["error"])[:256]
        for region, n in per_job.get(job.id, {}).items():
            regions.setdefault(region, {"region": region, "status": "ok", "cas": 0, "error": None})["cas"] = n
        rows = [regions[r] for r in sorted(regions)]
        read = [r for r in rows if r["status"] in ("ok", "partial")]
        status = "read" if rows and len(read) == len(rows) and all(r["status"] == "ok" for r in rows) \
            else "partial" if read else "not_read"
        reason = None if read else (collect.get("summary") if not rows else None)
        out[int(src.id)] = {"account_source_id": int(account_id), "job_id": job.id, "run_id": job.run_id,
                            "at": collect["at"], "status": status, "cas": sum(r["cas"] for r in rows),
                            "reason": reason, "regions": rows}
    return out


def public_source(source: CbomCollectionSource, settings: CbomCollectionSettings, node: CbomScanNode | None,
                  now: _dt.datetime, last_collect: dict[str, Any] | None = None,
                  ranges: RangeContext | None = None) -> dict[str, Any]:
    """``ranges``: the request's planning.RangeContext when it lists several sources (built once per request)."""
    spec = KINDS.get(source.kind)
    info = source_targets(source, settings, ranges)
    config = dict(source.config or {})
    return {
        "id": source.id,
        "team_id": source.team_id,
        "owner_user_id": source.owner_user_id,
        "kind": source.kind,
        "kind_label": spec.label if spec else source.kind,
        "group": spec.group if spec else "other",
        "name": source.name,
        "node_id": source.node_id,
        "node_name": node.name if node else None,
        # the segment the source runs in: its node's (#225, the segment filter of the source tables), or, for a source
        # on a segment with no node (F1.1: any signed agentless node of that segment), its own
        "node_segment": (node.segment or None) if node else (getattr(source, "node_segment", None) or None),
        "node_status": node_status(node, now) if source.node_id else None,
        "enabled": source.enabled,
        "config": config,
        "secrets_set": sorted(source.secret_fields or []),
        "target_count": int(info["units"]),
        "target_unit": info["unit"],
        "last_test_status": source.last_test_status,
        "last_test_at": iso_z(source.last_test_at),
        "last_test_summary": source.last_test_summary,
        "last_test_job_id": source.last_test_job_id,
        "last_test_result": source.last_test_result or {},
        # the newest finished collection (last_collects); null when it was not looked up or there is none yet
        "last_collect": last_collect,
        "row_version": source.row_version,
        "created_at": iso_z(source.created_at),
        "last_updated": iso_z(source.last_updated),
        # F1.2 fleet: set when a policy manages this source (edit it through the policy), and its typed credential
        "managed_by_policy_id": source.managed_by_policy_id,
        "credential_id": source.credential_id,
    }


def _slice_progress(job: CbomCollectionJob) -> dict[str, Any] | None:
    """A fanned-out AWS collection while it runs: slices (account x region) done of total (``cbom_sources.slices``)."""
    slices = (job.result or {}).get("slices") if job.status == "claimed" and job.kind == "collect" else None
    if isinstance(slices, dict) and isinstance(slices.get("total"), int) and slices["total"] > 0:
        return {"done": int(slices.get("done") or 0), "total": slices["total"], "unit": "account-regions"}
    return None


def public_job(job: CbomCollectionJob, node: CbomScanNode | None, settings: CbomCollectionSettings,
               now: _dt.datetime, source: CbomCollectionSource | None = None) -> dict[str, Any]:
    params = dict(job.params or {})
    progress = (job.result or {}).get("progress")
    return {
        "id": job.id,
        "run_id": job.run_id,
        "source_id": job.source_id,
        "source_name": source.name if source else params.get("source_name"),
        "node_id": job.node_id,
        "node_name": node.name if node else None,
        "kind": job.kind,
        "status": job.status,
        "waiting_reason": job_waiting_reason(job, node, settings, now, source),
        "attempts": job.attempts,
        "credits": round(job.weight_c / 100, 2),
        "refunded": job.refunded,
        # what was given back (CB-14): all of "credits" for a failed or cancelled job, the runtime-skip share otherwise
        "credits_refunded": round((job.refunded_c or 0) / 100, 2),
        "created_at": iso_z(job.created_at),
        "claimed_at": iso_z(job.claimed_at),
        "finished_at": iso_z(job.finished_at),
        # per-target rows are served by /jobs/{id}/assets and /runs/{id}/assets, not on every poll
        "result": {k: v for k, v in (job.result or {}).items() if k not in ("targets", "progress")},
        # a network range while it runs ("N of M addresses"); null for older nodes, other jobs and ended jobs
        "progress": ({"done": progress["done"], "total": progress["total"]}
                     if job.status == "claimed" and isinstance(progress, dict) and progress.get("attempt") == job.attempts
                     else _slice_progress(job)),
        "error": job.error,
        "outcome": job.outcome,
        "asset_count": job.asset_count,
        "cancel_requested": job.cancel_requested_at is not None,
        "runner": "node" if job.node_id else ("cloud" if job.kind in ("collect", "slice") else "node"),
        "samples": params.get("samples") or [],
        "server_time": iso_z(now),
    }


def run_trigger(run: CbomCollectionRun) -> str:
    """"scheduled" or "manual" (S4): the stored ``trigger``, else what ``schedule_id`` says (a row read before the
    rsched1trig001 backfill, or built in memory)."""
    stored = getattr(run, "trigger", None)
    if stored in ("scheduled", "manual"):
        return "scheduled" if stored == "scheduled" or run.schedule_id is not None else "manual"
    return "scheduled" if run.schedule_id is not None else "manual"


def schedule_names(session: Any, team_id: int, ids: Any) -> dict[int, str]:
    """``{schedule id: name}`` of this team's schedules among ``ids`` (a deleted schedule is simply absent)."""
    from sqlmodel import select

    from backend.new_models import CbomCollectionSchedule

    wanted = sorted({int(i) for i in ids if i is not None})
    if not wanted:
        return {}
    return {int(i): str(n) for i, n in session.exec(select(CbomCollectionSchedule.id, CbomCollectionSchedule.name).where(
        CbomCollectionSchedule.team_id == team_id, CbomCollectionSchedule.id.in_(wanted))).all()}  # type: ignore[union-attr]


def public_run(run: CbomCollectionRun, jobs: list[dict[str, Any]] | None = None,
               risk_model: dict[str, Any] | None = None, schedule_name: str | None = None) -> dict[str, Any]:
    """``risk_model``: the team's Mosca now, so ``grades.inputs_changed`` can compare it with the run's snapshot
    (CB-19 PR-2); without it ``inputs_changed`` is null on a run that has a snapshot. ``schedule_name``: the name of
    the schedule that started the run, when the caller looked it up (null otherwise, and for a deleted schedule)."""
    from backend.utilities.cbom_sources.qgrade import run_grades

    out = {
        "id": run.id,
        "team_id": run.team_id,
        "owner_user_id": run.owner_user_id,
        "scan_id": run.scan_id,
        "status": run.status,
        "include": run.include or {},
        "breakdown": run.breakdown or {},
        "credits": run_credit_summary(run),
        "soc_ack_by": run.soc_ack_by,
        "soc_ack_at": iso_z(run.soc_ack_at),
        "cancelled_by": run.cancelled_by,
        "cancelled_at": iso_z(run.cancelled_at),
        # S4: what started the run; a scheduled run names its schedule (the id stays after the schedule is deleted)
        "trigger": run_trigger(run),
        "schedule_id": run.schedule_id,
        "schedule_name": schedule_name,
        "finished_at": iso_z(run.finished_at),
        "created_at": iso_z(run.created_at),
        "last_updated": iso_z(run.last_updated),
        # what judged the run when it was created (null on runs from before they were recorded)
        "versions": {"kb": run.kb_version, "classifier": run.classifier_version, "engine": run.engine_version},
        # the grade model and inputs the run recorded at Start, and whether the team's inputs differ now (CB-19)
        "grades": run_grades(run, risk_model),
    }
    if jobs is not None:
        out["jobs"] = jobs
        counts: dict[str, int] = {}
        for job in jobs:
            counts[job["status"]] = counts.get(job["status"], 0) + 1
        out["job_counts"] = counts
    return out


def _aws_configured() -> bool:
    from backend.utilities.cbom_sources.templates import aws_collection_configured

    return aws_collection_configured()


def _aws_lab() -> bool:
    from backend.utilities.cbom_sources.lab_mode import lab_same_account

    return lab_same_account()


def _ct_enabled() -> bool:
    from backend.utilities.cbom_sources.kinds import ct_discovery_enabled

    return ct_discovery_enabled()


def _ct_providers() -> list[str]:
    from backend.utilities.cbom_sources.ct_providers import provider_names

    return provider_names()


def public_settings(row: CbomCollectionSettings, now: _dt.datetime) -> dict[str, Any]:
    nxt = None
    try:
        nxt = next_window_start(row.scan_window, row.window_timezone, now)
    except Exception:
        nxt = None
    return {
        "aws_external_id": row.aws_external_id,
        "aws_collection_configured": _aws_configured(),
        # lab mode (lab_mode.py): AWS roles in this test deployment's own account are accepted; the form shows a banner
        "aws_lab_same_account": _aws_configured() and _aws_lab(),
        "cert_domains": row.cert_domains or [],
        # Certificate Transparency discovery: on only when the server sets CBOM_CT_DISCOVERY; the UI follows it
        "ct_discovery_enabled": _ct_enabled(),
        "ct_providers": _ct_providers(),
        "network_exclusions": row.network_exclusions or [],
        "sni_hostnames": row.sni_hostnames or [],
        "ports": row.ports or [],
        "zeek_span": row.zeek_span,
        "scan_window": row.scan_window or [],
        "window_timezone": row.window_timezone,
        "rate_conn_per_s": row.rate_conn_per_s,
        "rate_parallel_per_server": row.rate_parallel_per_server,
        "rate_handshakes_per_endpoint": row.rate_handshakes_per_endpoint,
        "soc_email": row.soc_email,
        "emergency_contact": row.emergency_contact,
        "stop_all_network": row.stop_all_network,
        "require_signed_nodes": bool(row.require_signed_nodes),
        "risk_model": {k: (row.risk_model or {}).get(k) for k in ("data_shelf_life_years", "migration_years", "threat_years")},
        "stop_all_changed_by": row.stop_all_changed_by,
        "stop_all_changed_at": iso_z(row.stop_all_changed_at),
        "next_window_start": iso_z(nxt),
        "in_window_now": nxt is not None and nxt <= now,
        "row_version": row.row_version,
        "last_updated": iso_z(row.last_updated),
    }


def public_area(row: CbomEvidenceArea, today: _dt.date, vendor_levels: list[str] | None = None) -> dict[str, Any]:
    """An evidence area. ``confidence`` is the level a user set, ``effective_confidence`` the level it counts at today
    (both E0..E3, whatever spelling is stored); ``q0_gap`` says why an E0 item is a Q0 gap (null otherwise);
    ``q0_gap_rollup``: the third-party-vendors area's gap only repeats its vendors' gaps (not counted)."""
    spec = AREAS.get(row.area_key, {})
    effective, gap, rollup = area_level(row, today, vendor_levels)
    overdue = bool(row.due_date and row.due_date < today.isoformat() and effective == "E0")
    return {
        "id": row.id,
        "area_key": row.area_key,
        "title": spec.get("title", row.area_key),
        "owner_hint": spec.get("owner_hint"),
        "questions": spec.get("questions", []),
        "owner": row.owner,
        "confidence": level(row.confidence),
        "effective_confidence": effective,
        "confidence_label": CONFIDENCE_LABEL.get(effective, "Unknown"),
        "confidence_set_by": row.confidence_set_by,
        "q0_gap": gap,
        "q0_gap_rollup": rollup,
        "answers": row.answers or {},
        "evidence_title": row.evidence_title,
        "evidence_url": row.evidence_url,
        "evidence_date": row.evidence_date,
        "due_date": row.due_date,
        "overdue": overdue,
        "row_version": row.row_version,
        "last_updated": iso_z(row.last_updated),
        **evidence_area_fields(row.area_key, row.answers),  # CB-24: fix class of the evidence item
    }


def public_vendor(row: CbomEvidenceVendor, now: _dt.datetime) -> dict[str, Any]:
    effective, gap = vendor_level(row, now)
    return {
        "id": row.id,
        "name": row.name,
        "contact_email": row.contact_email,
        "area_key": row.area_key,
        "status": vendor_status(row, now),
        "link_created_at": iso_z(row.link_created_at),
        "link_expires_at": iso_z(row.link_expires_at),
        "answered_at": iso_z(row.answered_at),
        "answers": row.answers or {},
        "confidence": level(row.confidence),  # the level a user set or the answer gave; it counts once answered
        "effective_confidence": effective,
        "confidence_label": CONFIDENCE_LABEL.get(effective, "Unknown"),
        "q0_gap": gap,
        "evidence_url": row.evidence_url,
        "row_version": row.row_version,
        "created_at": iso_z(row.created_at),
        **evidence_vendor_fields(),  # CB-24: a third-party vendor is vendor-fixed
    }
