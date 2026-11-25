"""The team tile's one risk score: the current state, not the history (review 6064315680 of #505, finding 1).

The posture score grows with the number of findings, so summing every scan a team ever ran made the tile read 69 / D
for four rescans of one target that each read 20 / B on its row, and a team that fixed everything and rescanned kept
the old Highs on the tile forever. Like the CBOM tile (#500 ``cbom_team_rollup``: the current scan of each repository
and branch) and Dependency-Track's portfolio (the current version of each project), the tile scores the findings of
the latest successful scan of each target:

* SAST, SBOM / SCA, IaC, CBOM, AI BOM: the repository (URL normalised: no scheme, credentials, ``.git`` or trailing
  slash, lower case) and branch. A scan with no branch is on the repository's default branch: the one the scan
  records (``default_branch``) when known, else its own target "the unnamed default branch" of that repository, one
  for every branch-less scan of it, so it is never merged with a named branch it may not be (review 6065663183 of
  #505, 4). An upload (archive or BOM file): its content (the SHA-256 the estimate measured,
  ``credit_estimate.file_sha256``), never its title; without a recorded hash, its own target;
* DAST: the target URL, scheme and host in lower case, the path as typed, no trailing slash;
* LLM: the model (type and name), and for a ``custom`` model its endpoint (``model_uri``, recorded without
  credentials or query): two endpoints serving a model of the same name are two targets. A custom model scanned
  before the endpoint was recorded is its own target;
* MCP: the server URL.

A scan whose target is not recorded is its own target. Only successful scans count (finding 2: a failed or running
scan's findings never reach a score). The counts per scan are the list row's (``scan_list_item``), so the tile of a team
with one target reads the row's score.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

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


_DEFAULT_PORTS = {"http": 80, "https": 443, "ssh": 22, "git": 9418}


def _url_parts(value: Any) -> tuple[str, str, str, str] | None:
    """``(scheme, host[:port], path, query)`` of a URL, scheme and host in lower case, no credentials; None for none.
    ``git@host:owner/repo`` (scp-like SSH) reads as ``ssh://host/owner/repo``."""
    raw = str(value or "").strip()
    if not raw:
        return None
    scp = re.match(r"^(?:[^@/\s]+@)?([^:/\s]+):(?!//)(?!\d+(?:/|$))(.+)$", raw)
    if scp and "://" not in raw:
        raw = f"ssh://{scp.group(1)}/{scp.group(2)}"
    if "://" not in raw:
        raw = f"https://{raw}"
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port and port != _DEFAULT_PORTS.get(scheme):
        host = f"{host}:{port}"
    return scheme, host, parts.path, parts.query


def repo_key(value: Any) -> str:
    """A repository URL as one key: host and path, lower case, without scheme, credentials, ``.git`` or trailing
    slash (``https://github.com/a/b.git``, ``git@github.com:a/b`` and ``HTTPS://GitHub.com/a/b/`` are one)."""
    parts = _url_parts(value)
    if parts is None:
        return ""
    _scheme, host, path, _query = parts
    path = path.rstrip("/")
    if path.lower().endswith(".git"):
        path = path[:-4].rstrip("/")
    return f"{host}{path}".lower()


def endpoint_key(value: Any) -> str:
    """A URL whose path may be case-sensitive (a DAST target, a model endpoint): scheme and host in lower case, the
    path as typed without a trailing slash, the query kept."""
    parts = _url_parts(value)
    if parts is None:
        return ""
    scheme, host, path, query = parts
    return f"{scheme}://{host}{path.rstrip('/')}" + (f"?{query}" if query else "")


def endpoint_for_record(value: Any) -> str | None:
    """A model endpoint as scan metadata records it: no credentials, query or fragment (an API key may sit there)."""
    parts = _url_parts(value)
    if parts is None or not parts[1]:
        return None
    scheme, host, path, _query = parts
    return f"{scheme}://{host}{path}"


UPLOAD_FLAGS = ("zip_file_used", "sbom_file_used", "cbom_file_used", "ai_bom_file_used")


def _upload_hash(scan: Any) -> str:
    estimate = getattr(scan, "credit_estimate", None)
    digest = estimate.get("file_sha256") if isinstance(estimate, Mapping) else None
    return str(digest or "").strip().lower()


def target_key(scan_type: str, scan: Any) -> tuple:
    """The target a scan is of; ``("scan", id)`` when the scan records none."""
    meta = _meta(scan)
    key: tuple | None = None
    if scan_type in ("sast", "sbom_sca", "iac", "cbom", "ai_bom"):
        repo = repo_key(meta.get("repo_url"))
        if repo:
            branch = _text(meta.get("branch")) or _text(meta.get("default_branch"))
            key = ("repo", repo, branch or None)
        elif any(meta.get(flag) for flag in UPLOAD_FLAGS) and _upload_hash(scan):
            key = ("upload", _upload_hash(scan))
    elif scan_type == "dast":
        url = endpoint_key(meta.get("target_url"))
        key = ("url", url) if url else None
    elif scan_type == "llm":
        data_meta = _data(scan).get("metadata") if isinstance(_data(scan).get("metadata"), Mapping) else {}
        name = _text(meta.get("model_name") or data_meta.get("model_name"))
        model_type = _text(meta.get("model_type"))
        if name and model_type == "custom":
            endpoint = endpoint_key(meta.get("model_uri"))
            key = ("model", model_type, name, endpoint) if endpoint else None
        elif name:
            key = ("model", model_type, name)
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
        return {**sbom_team_posture(current), "risk_posture_scope": scope}
    totals = dict.fromkeys(SEVERITIES, 0)
    for s in current:
        for k, n in scan_counts(scan_type, s).items():
            totals[k] += n
    return {**risk_scale.posture_field(totals, judged=bool(current)), "risk_posture_scope": scope}


def sbom_team_posture(current: list[Any]) -> dict[str, Any]:
    """The SBOM tile over the current scan of each target, each target scored by its row's rule first (review
    6065663183 of #505, 2): its confirmed findings, or, when its only vulnerabilities are matches on guessed versions,
    their worst case. The tile is the posture of those counts added up, so it is never in a better tier than its worst
    row (the score only rises with a count). It reads "unverified" when any target's row does, and carries the
    team's guessed-version matches (``risk_unverified``) whenever there are any."""
    complete = [s for s in current if not sbom_rows.is_incomplete(_data(s))]
    totals = dict.fromkeys(SEVERITIES, 0)
    confirmed_all = dict.fromkeys(SEVERITIES, 0)
    guessed_all = dict.fromkeys(SEVERITIES, 0)
    any_unverified = False
    for s in complete:
        confirmed = scan_counts("sbom_sca", s)
        guessed = sbom_rows.unverified_counts(_data(s))
        row = risk_scale.posture_field(confirmed, unverified=guessed)
        any_unverified = any_unverified or row[risk_scale.STATUS_KEY] == "unverified"
        for k in SEVERITIES:
            totals[k] += int(guessed.get(k, 0) or 0) if row[risk_scale.STATUS_KEY] == "unverified" else confirmed[k]
            confirmed_all[k] += confirmed[k]
            guessed_all[k] += int(guessed.get(k, 0) or 0)
    out = risk_scale.posture_field(totals, judged=bool(current), incomplete=bool(current) and not complete,
                                   unverified=guessed_all, confirmed=confirmed_all)
    if any_unverified and out[risk_scale.STATUS_KEY] == "scored":
        out[risk_scale.STATUS_KEY] = "unverified"
    return out


def cbom_scored_counts(rows: Iterable[Any]) -> dict[str, int]:
    """A CBOM's findings per severity as its risk score counts them (#500's ``CodeRowSummary.scored``): findings only
    (clean inventory is not one), and neither a finding in test, fixture or example code (``code_context: test``)
    nor a setting no crypto call is proven to read (``config_status: unconfirmed``). Those are listed, not scored."""
    from backend.utilities.cbom_sources.cbom_metrics import finding_severity
    from backend.utilities.cbom_sources.cbom_rows import display_row

    counts = dict.fromkeys(SEVERITIES, 0)
    for raw in rows or []:
        if not isinstance(raw, Mapping):
            continue
        row = display_row(dict(raw))
        severity = finding_severity(row)
        if severity is None or row.get("code_context") == "test" or row.get("config_status") == "unconfirmed":
            continue
        counts[severity] += 1
    return counts


__all__ = ["cbom_scored_counts", "endpoint_for_record", "endpoint_key", "latest_successful", "repo_key", "sbom_team_posture",
           "scan_counts", "target_key", "team_posture"]
