"""Live facts D2 (Discovery Methodology and Evidence Plan) prints next to its authored method text.

``load(session, team_id)`` reads, for one team only, what the methodology must state as it is configured today:
the CBOM Sources by kind and by provider / engine / vendor, the probe port protocols, the scan window, rate limits
and signed-node policy, the scan nodes by mode and signing key, the schedules and how many runs each trigger started;
given the team's view, also whether its code scans read binaries and the CycloneDX type of its Sources "other" rows.
It never reads a secret (``secret_encrypted`` is not selected) and never creates a row (the settings row is read,
not created: a team that never opened CBOM Sources gets the product defaults, flagged ``settings_default``).

The result is plain JSON-able data stored on ``TeamCbomView.methodology``; the renderer stays a pure function of the
view.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import case, func, or_
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionRun,
    CbomCollectionSchedule,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomScanNode,
    Scan,
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
    # the same rule as serialize.run_trigger (review #486 nit 2): a run with a schedule_id is scheduled even when an
    # older pod inserted it with the column default 'manual' during a deploy
    trigger = case((or_(CbomCollectionRun.schedule_id.is_not(None),  # type: ignore[union-attr]
                        CbomCollectionRun.trigger == "scheduled"), "scheduled"), else_="manual")
    runs = session.exec(select(trigger, func.count())
                        .where(CbomCollectionRun.team_id == team_id)
                        .group_by(trigger)).all()
    by_trigger = {str(t or "manual"): int(n) for t, n in runs}
    return {"schedules": {"total": sum(int(n) for _e, n in schedules),
                          "enabled": sum(int(n) for e, n in schedules if e)},
            "runs": {"total": sum(by_trigger.values()), "scheduled": by_trigger.get("scheduled", 0),
                     "manual": by_trigger.get("manual", 0)}}


_CODE_KINDS = ("repo", "zip", "file", "scan")  # cbom_team_rollup SOURCE_* of code scans
_CHUNK = 500


def _code(session: Session, team_id: int, view: Any) -> dict[str, int]:
    """How many code sources the edition has, and how many of their current scans ran with the "scan binaries"
    option (only then are compiled binaries and firmware read: review #486 minor 5)."""
    ids = sorted({int(s.current_scan_id) for s in getattr(view, "sources", ()) or ()
                  if getattr(s, "kind", None) in _CODE_KINDS and getattr(s, "current_scan_id", None)})
    binaries = 0
    for start in range(0, len(ids), _CHUNK):
        for meta in session.exec(select(Scan.scan_metadata).where(
                Scan.team_id == team_id, Scan.id.in_(ids[start:start + _CHUNK]))).all():  # type: ignore[union-attr]
            binaries += 1 if isinstance(meta, dict) and meta.get("scan_binaries") else 0
    return {"sources": len(ids), "scan_binaries": binaries}


def _sources_other_types(session: Session, team_id: int, view: Any) -> dict[str, int]:
    """CBOM Sources assets the rollup types "other" (``collections_view.node_row``: a cdx_type outside the four), by
    the type the run CBOM export writes them as (``inventory.py``: a crypto library is a CycloneDX library component,
    anything else that is not a certificate, protocol or related crypto material an algorithm), so D2's asset-type
    table shows Sources rows under a CycloneDX type (review #486 minor 9). Read by the assets' own ids (bom_ref)."""
    ids = sorted({int(ref[len("zs-asset-"):]) for a in getattr(view, "assets", ()) or ()
                  if getattr(a, "current", False) and getattr(a, "asset_type", None) == "other"
                  and str(getattr(a, "source_key", "")).startswith("sources:")
                  for ref in [str(getattr(a, "bom_ref", "") or "")]
                  if ref.startswith("zs-asset-") and ref[len("zs-asset-"):].isdigit()})
    out = {"algorithm": 0, "library": 0}
    for start in range(0, len(ids), _CHUNK):
        for cdx in session.exec(select(CbomCollectedAsset.cdx_type).where(
                CbomCollectedAsset.team_id == team_id,
                CbomCollectedAsset.id.in_(ids[start:start + _CHUNK]))).all():  # type: ignore[union-attr]
            out["library" if cdx == "library" else "algorithm"] += 1
    return out


def load(session: Session, team_id: int, view: Any = None) -> dict[str, Any]:
    """Everything D2 states live about the team's collection set-up (see the module docstring). With the team's
    merged ``view``: also the code scans' "scan binaries" option and the CycloneDX type of Sources "other" rows."""
    out = {"sources": _sources(session, team_id), "settings": _settings(session, team_id),
           "nodes": _nodes(session, team_id), **_schedules_and_runs(session, team_id)}
    if view is not None:
        out["code"] = _code(session, team_id, view)
        out["sources_other_types"] = _sources_other_types(session, team_id, view)
    return out


__all__ = ["VARIANT_FIELDS", "load"]
