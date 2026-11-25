"""The team tile's one risk score: the current state, not the history (review 6064315680 of #505, finding 1).

The posture score grows with the number of findings, so summing every scan a team ever ran made the tile read 69 / D
for four rescans of one target that each read 20 / B on its row, and a team that fixed everything and rescanned kept
the old Highs on the tile forever. Like the CBOM tile (#500 ``cbom_team_rollup``: the current scan of each repository
and branch) and Dependency-Track's portfolio (the current version of each project), the tile scores the findings of
the latest successful scan of each target:

* SAST, SBOM / SCA, IaC: the repository and branch (an uploaded archive: its title);
* DAST: the target URL;
* LLM: the model (type and name);
* MCP: the server URL.

A scan whose target is not recorded is its own target. Only successful scans count (finding 2: a failed or running
scan's findings never reach a score). The counts per scan are the list row's (``scan_list_item``), so the tile of a team
with one target reads the row's score.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from backend.utilities.dashboard import risk_scale, sbom_rows

SEVERITIES = risk_scale.SEVERITIES


def _meta(scan: Any) -> Mapping[str, Any]:
    meta = getattr(scan, "scan_metadata", None)
    return meta if isinstance(meta, Mapping) else {}


def _data(scan: Any) -> Mapping[str, Any]:
    data = getattr(scan, "scan_data", None)
    return data if isinstance(data, Mapping) else {}


def _text(value: Any) -> str:
    return str(value or "").strip().lower().rstrip("/")


def target_key(scan_type: str, scan: Any) -> tuple:
    """The target a scan is of; ``("scan", id)`` when the scan records none."""
    meta = _meta(scan)
    key: tuple | None = None
    if scan_type in ("sast", "sbom_sca", "iac", "cbom", "ai_bom"):
        repo = _text(meta.get("repo_url"))
        if repo:
            key = ("repo", repo, _text(meta.get("branch")))
        elif meta.get("zip_file_used") and _text(getattr(scan, "title", None)):
            key = ("upload", _text(getattr(scan, "title", None)))
    elif scan_type == "dast":
        url = _text(meta.get("target_url"))
        key = ("url", url) if url else None
    elif scan_type == "llm":
        data_meta = _data(scan).get("metadata") if isinstance(_data(scan).get("metadata"), Mapping) else {}
        name = _text(meta.get("model_name") or data_meta.get("model_name"))
        key = ("model", _text(meta.get("model_type")), name) if name else None
    elif scan_type == "mcp":
        url = _text(meta.get("server_url"))
        key = ("server", url) if url else None
    return key or ("scan", getattr(scan, "id", None))


def _when(scan: Any) -> tuple:
    created = getattr(scan, "created_at", None)
    if isinstance(created, datetime):
        created = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
    else:
        created = datetime.min.replace(tzinfo=timezone.utc)
    return created, int(getattr(scan, "id", 0) or 0)


def latest_successful(scan_type: str, scans: Iterable[Any]) -> list[Any]:
    """The latest successful scan of each target, in target order."""
    latest: dict[tuple, Any] = {}
    for scan in scans:
        if getattr(scan, "scan_type", scan_type) != scan_type or getattr(scan, "scan_status", None) != "success":
            continue
        key = target_key(scan_type, scan)
        if key not in latest or _when(scan) > _when(latest[key]):
            latest[key] = scan
    return list(latest.values())


def _count(counts: dict[str, int], impact: Any) -> None:
    key = str(impact or "").strip().lower()
    if key in counts:
        counts[key] += 1


def scan_counts(scan_type: str, scan: Any) -> dict[str, int]:
    """A scan's findings per severity, counted as its list row counts them (confirmed SBOM versions only)."""
    counts = dict.fromkeys(SEVERITIES, 0)
    results = _data(scan).get("results")
    if scan_type == "sast":
        for item in results or []:
            for v in (item or {}).get("vulnerabilities") or [] if isinstance(item, Mapping) else []:
                if isinstance(v, Mapping):
                    _count(counts, v.get("impact"))
    elif scan_type == "llm":
        for v in (results or {}).get("vulnerabilities") or [] if isinstance(results, Mapping) else []:
            if isinstance(v, Mapping):
                _count(counts, v.get("impact"))
    elif scan_type == "mcp":
        res = results if isinstance(results, Mapping) else {}
        for group in ("tools", "prompts", "resources"):
            for asset in res.get(group) or []:
                for v in (asset or {}).get("vulnerabilities") or [] if isinstance(asset, Mapping) else []:
                    if isinstance(v, Mapping):
                        _count(counts, v.get("impact"))
    elif scan_type == "sbom_sca":
        for v in sbom_rows.severity_rows(results if isinstance(results, list) else []):
            _count(counts, v.get("impact"))
    else:  # dast, iac: one row per finding
        for v in results or [] if isinstance(results, list) else []:
            if isinstance(v, Mapping):
                _count(counts, v.get("impact"))
    return counts


def team_posture(scan_type: str, scans: Iterable[Any]) -> dict[str, Any]:
    """The tile's ``risk_posture`` / ``risk_posture_status`` (and, for SBOM, ``risk_unverified``) over the latest
    successful scan of each target, plus ``risk_posture_scope``: how many targets and which scans it read."""
    scans = list(scans)
    current = latest_successful(scan_type, scans)
    scope = {"basis": "latest successful scan per target", "targets": len(current),
             "scan_ids": sorted(int(getattr(s, "id", 0) or 0) for s in current)}
    if scan_type == "sbom_sca":
        complete = [s for s in current if not sbom_rows.is_incomplete(_data(s))]
        totals = dict.fromkeys(SEVERITIES, 0)
        guessed = dict.fromkeys(SEVERITIES, 0)
        for s in complete:
            for k, n in scan_counts(scan_type, s).items():
                totals[k] += n
            for k, n in sbom_rows.unverified_counts(_data(s)).items():
                guessed[k] += n
        return {**risk_scale.posture_field(totals, judged=bool(current), incomplete=bool(current) and not complete,
                                           unverified=guessed),
                "risk_posture_scope": scope}
    totals = dict.fromkeys(SEVERITIES, 0)
    for s in current:
        for k, n in scan_counts(scan_type, s).items():
            totals[k] += n
    return {**risk_scale.posture_field(totals, judged=bool(current)), "risk_posture_scope": scope}


__all__ = ["latest_successful", "scan_counts", "target_key", "team_posture"]
