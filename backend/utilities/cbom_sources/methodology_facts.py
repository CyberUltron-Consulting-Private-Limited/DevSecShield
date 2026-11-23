"""Live facts D2 (Discovery Methodology and Evidence Plan) prints next to its authored method text.

``load(session, team_id)`` reads, for one team only, what the methodology must state as it is configured today:
the CBOM Sources by kind and by provider / engine / vendor, the probe port protocols, the scan window, rate limits
and signed-node policy, the scan nodes by mode and signing key, the schedules and how many runs each trigger started.
It never reads a secret (``secret_encrypted`` is not selected) and never creates a row (the settings row is read,
not created: a team that never opened CBOM Sources gets the product defaults, flagged ``settings_default``).

The result is plain JSON-able data stored on ``TeamCbomView.methodology``; the renderer stays a pure function of the
view.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectionRun,
    CbomCollectionSchedule,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomScanNode,
)

VARIANT_FIELDS = ("provider", "engine", "vendor")


def _window_hours(grid: Any) -> int | None:
    if not isinstance(grid, list) or not grid:
        return None
    return sum(1 for row in grid if isinstance(row, list) for cell in row if cell is True)


def _sources(session: Session, team_id: int) -> dict[str, Any]:
    by_kind: dict[str, dict[str, int]] = {}
    variants: dict[str, int] = {}
    variant_by_uid: dict[str, str] = {}
    rows = session.exec(select(CbomCollectionSource.kind, CbomCollectionSource.enabled, CbomCollectionSource.config,
                               CbomCollectionSource.source_uid)
                        .where(CbomCollectionSource.team_id == team_id)).all()
    for kind, enabled, config, uid in rows:
        bucket = by_kind.setdefault(str(kind), {"configured": 0, "enabled": 0})
        bucket["configured"] += 1
        bucket["enabled"] += 1 if enabled else 0
        cfg = config if isinstance(config, dict) else {}
        for name in VARIANT_FIELDS:
            value = cfg.get(name)
            if isinstance(value, str) and value:
                key = f"{kind}:{value}"
                variants[key] = variants.get(key, 0) + 1
                if uid:
                    variant_by_uid[str(uid)] = key
                break
    return {"by_kind": dict(sorted(by_kind.items())), "variants": dict(sorted(variants.items())),
            "variant_by_uid": variant_by_uid, "total": len(rows)}


def _settings(session: Session, team_id: int) -> dict[str, Any]:
    from backend.utilities.cbom_sources.settings import DEFAULT_PORTS, default_window

    row = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
    ports = (row.ports if row is not None and row.ports else None) or list(DEFAULT_PORTS)
    window = (row.scan_window if row is not None and row.scan_window else None) or default_window()
    return {
        "settings_default": row is None,
        "port_protocols": sorted({str(p.get("protocol")) for p in ports if isinstance(p, dict) and p.get("protocol")}),
        "window_hours": _window_hours(window),
        "window_timezone": row.window_timezone if row is not None else "Asia/Kolkata",
        "require_signed_nodes": bool(row.require_signed_nodes) if row is not None else None,
        "stop_all_network": bool(row.stop_all_network) if row is not None else False,
        "rate_conn_per_s": row.rate_conn_per_s if row is not None else None,
        "rate_parallel_per_server": row.rate_parallel_per_server if row is not None else None,
        "rate_handshakes_per_endpoint": row.rate_handshakes_per_endpoint if row is not None else None,
        "never_scan_entries": len(row.network_exclusions or []) if row is not None else 0,
        "mosca_set": bool(row is not None and isinstance(row.risk_model, dict) and all(
            row.risk_model.get(k) is not None
            for k in ("data_shelf_life_years", "migration_years", "threat_years"))),
    }


def _nodes(session: Session, team_id: int) -> dict[str, int]:
    out = {"agentless": 0, "agent": 0, "signing": 0, "legacy": 0}
    rows = session.exec(select(CbomScanNode.mode, CbomScanNode.signing_public_key, CbomScanNode.enrolled_at)
                        .where(CbomScanNode.team_id == team_id)).all()
    for mode, key, enrolled in rows:
        if enrolled is None:
            continue  # issued a token, never enrolled
        out["agent" if mode == "agent" else "agentless"] += 1
        out["signing" if key else "legacy"] += 1
    return out


def _schedules_and_runs(session: Session, team_id: int) -> dict[str, Any]:
    schedules = session.exec(select(CbomCollectionSchedule.enabled, func.count())
                             .where(CbomCollectionSchedule.team_id == team_id)
                             .group_by(CbomCollectionSchedule.enabled)).all()
    runs = session.exec(select(CbomCollectionRun.trigger, func.count())
                        .where(CbomCollectionRun.team_id == team_id)
                        .group_by(CbomCollectionRun.trigger)).all()
    by_trigger = {str(t or "manual"): int(n) for t, n in runs}
    return {"schedules": {"total": sum(int(n) for _e, n in schedules),
                          "enabled": sum(int(n) for e, n in schedules if e)},
            "runs": {"total": sum(by_trigger.values()), "scheduled": by_trigger.get("scheduled", 0),
                     "manual": by_trigger.get("manual", 0)}}


def load(session: Session, team_id: int) -> dict[str, Any]:
    """Everything D2 states live about the team's collection set-up (see the module docstring)."""
    return {"sources": _sources(session, team_id), "settings": _settings(session, team_id),
            "nodes": _nodes(session, team_id), **_schedules_and_runs(session, team_id)}


__all__ = ["VARIANT_FIELDS", "load"]
