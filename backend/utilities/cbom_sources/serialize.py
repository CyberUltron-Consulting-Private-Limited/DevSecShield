"""Browser-facing shapes.  Each function whitelists fields: secrets and token hashes never appear."""
from __future__ import annotations

import datetime as _dt
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
from backend.utilities.cbom_sources.evidence import AREAS, CONFIDENCE_LABEL, effective_confidence, vendor_status
from backend.utilities.cbom_sources.jobs import job_waiting_reason, run_credit_summary
from backend.utilities.cbom_sources.kinds import KINDS
from backend.utilities.cbom_sources.planning import node_status, source_targets
from backend.utilities.cbom_sources.settings import next_window_start


def public_node(node: CbomScanNode, now: _dt.datetime, *, assigned_targets: int = 0, sources: int = 0) -> dict[str, Any]:
    status = node_status(node, now)
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
        "status": status,
        "registration_issued_at": iso_z(node.registration_issued_at),
        "registration_expires_at": iso_z(node.registration_expires_at),
        "enrolled_at": iso_z(node.enrolled_at),
        "hostname": node.hostname,
        "node_version": node.node_version,
        "source_ips": node.source_ips or [],
        "ssh_public_key": node.ssh_public_key,
        "capabilities": node.capabilities or {},
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


def public_source(source: CbomCollectionSource, settings: CbomCollectionSettings, node: CbomScanNode | None,
                  now: _dt.datetime) -> dict[str, Any]:
    spec = KINDS.get(source.kind)
    info = source_targets(source, settings)
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
        "row_version": source.row_version,
        "created_at": iso_z(source.created_at),
        "last_updated": iso_z(source.last_updated),
    }


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
        "created_at": iso_z(job.created_at),
        "claimed_at": iso_z(job.claimed_at),
        "finished_at": iso_z(job.finished_at),
        # per-target rows are served by /jobs/{id}/assets and /runs/{id}/assets, not on every poll
        "result": {k: v for k, v in (job.result or {}).items() if k not in ("targets", "progress")},
        # a network range while it runs ("N of M addresses"); null for older nodes, other jobs and ended jobs
        "progress": ({"done": progress["done"], "total": progress["total"]}
                     if job.status == "claimed" and isinstance(progress, dict) and progress.get("attempt") == job.attempts
                     else None),
        "error": job.error,
        "outcome": job.outcome,
        "asset_count": job.asset_count,
        "cancel_requested": job.cancel_requested_at is not None,
        "runner": "node" if job.node_id else ("cloud" if job.kind == "collect" else "node"),
        "samples": params.get("samples") or [],
        "server_time": iso_z(now),
    }


def public_run(run: CbomCollectionRun, jobs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
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
        "finished_at": iso_z(run.finished_at),
        "created_at": iso_z(run.created_at),
        "last_updated": iso_z(run.last_updated),
        # what judged the run when it was created (null on runs from before they were recorded)
        "versions": {"kb": run.kb_version, "classifier": run.classifier_version, "engine": run.engine_version},
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
    spec = AREAS.get(row.area_key, {})
    effective = effective_confidence(row.confidence, row.evidence_date, today)
    if row.area_key == "third_party_vendors" and vendor_levels is not None:
        from backend.utilities.cbom_sources.evidence import lowest

        effective = lowest(vendor_levels) if vendor_levels else effective
    overdue = bool(row.due_date and row.due_date < today.isoformat() and effective == "Q0")
    return {
        "id": row.id,
        "area_key": row.area_key,
        "title": spec.get("title", row.area_key),
        "owner_hint": spec.get("owner_hint"),
        "questions": spec.get("questions", []),
        "owner": row.owner,
        "confidence": row.confidence,
        "effective_confidence": effective,
        "confidence_label": CONFIDENCE_LABEL.get(effective, "Unknown"),
        "confidence_set_by": row.confidence_set_by,
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
        "confidence": row.confidence,
        "evidence_url": row.evidence_url,
        "row_version": row.row_version,
        "created_at": iso_z(row.created_at),
        **evidence_vendor_fields(),  # CB-24: a third-party vendor is vendor-fixed
    }
