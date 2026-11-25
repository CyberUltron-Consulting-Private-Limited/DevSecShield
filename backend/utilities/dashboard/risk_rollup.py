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
  #505, 4). An upload (archive or BOM file): its project (review 6066492618 of #505, 1): the uploaded BOM's subject
  (``metadata.component.name``, version-less), else the upload title without extension or version, so each new
  upload of a project replaces the last; the file's SHA-256 (``credit_estimate.file_sha256``) only when neither names
  one; else its own target;
* DAST: the target URL: scheme and host in lower case, the path (case kept) and the query as typed, no trailing
  slash or default port;
* LLM: the model (type and name), and for a ``custom`` model its endpoint (``model_uri``, recorded without
  credentials or query): two endpoints serving a model of the same name are two targets. A custom model scanned
  before the endpoint was recorded groups by its name with the other such scans;
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
_BOM_KEYS = ("sbom_json", "cbom_json", "ai_bom_json")
# subjects a worker writes when the scan has no repository (an upload): not a project's name
_PLACEHOLDER_SUBJECTS = frozenset({"", "unknown", "untitled", "application", "target-application", "pip-lock",
                                   "scanned-application",
                                   "source", "src", "repo", "upload", "uploads", "workspace", "project", "scan"})
_EXTENSIONS = re.compile(r"(\.(zip|tar|tgz|gz|bz2|xz|7z|rar|jar|war|json|xml|spdx|cdx|bom|txt|yaml|yml))+$")
# a trailing version, build number or date: "-v1.2", " 1.3.0", "_2026-11-20", "@1.3.0", "-2"
_VERSION_TAIL = re.compile(r"(?:^|[\s@._-]+)(?:\d{4}-\d{2}-\d{2}|\d{8}|v?\d+(?:[._]\d+)*(?:[-+][0-9a-z.]+)?)$")


def project_name(value: Any, *, strip_extension: bool = False) -> str:
    """A project's name as one key: lower case, without a file extension (a title), without a trailing version,
    build number or date, separators collapsed to "-": "Acme Shop v1.3.ZIP", "acme_shop 2026-11-20.tar.gz" and
    "Acme-Shop@1.3.0" are all "acme-shop". "" when nothing is left (a title that is only a version)."""
    name = str(value or "").strip().lower()
    if strip_extension:
        name = _EXTENSIONS.sub("", name)
    previous = None
    while previous != name:
        previous, name = name, _VERSION_TAIL.sub("", name).strip()
    return re.sub(r"[\s._-]+", "-", name).strip("-")


def _bom_subject(scan: Any) -> str:
    """The name of the project an uploaded BOM describes: CycloneDX ``metadata.component.name``, or an SPDX document's
    described package (else the document name); "" for none, a worker placeholder or a clone path."""
    data = _data(scan)
    for key in _BOM_KEYS:
        bom = data.get(key)
        if not isinstance(bom, Mapping):
            continue
        name = None
        if bom.get("spdxVersion"):
            described = set(bom.get("documentDescribes") or [])
            packages = [p for p in bom.get("packages") or [] if isinstance(p, Mapping)]
            name = next((p.get("name") for p in packages if p.get("SPDXID") in described), None) or bom.get("name")
        else:
            meta = bom.get("metadata")
            comp = meta.get("component") if isinstance(meta, Mapping) else None
            name = comp.get("name") if isinstance(comp, Mapping) else None
        raw = str(name or "").strip()
        if not raw or raw.startswith("/") or "\\" in raw or re.match(r"^tmp[a-z0-9_]{4,}$", raw.lower()):
            continue
        cleaned = project_name(raw)
        if cleaned and cleaned not in _PLACEHOLDER_SUBJECTS:
            return cleaned
    return ""


def _upload_hash(scan: Any) -> str:
    estimate = getattr(scan, "credit_estimate", None)
    digest = estimate.get("file_sha256") if isinstance(estimate, Mapping) else None
    return str(digest or "").strip().lower()


def upload_key(scan: Any) -> tuple | None:
    """An upload's target: its project (review 6066492618 of #505, 1), so this week's zip of a project replaces last
    week's on the tile: the uploaded BOM's subject, else the upload title without extension or version; the file's
    SHA-256 only when neither names a project; None (its own target) without any of them."""
    name = _bom_subject(scan) or project_name(getattr(scan, "title", None), strip_extension=True)
    if name and name not in _PLACEHOLDER_SUBJECTS:
        return ("upload", name)
    digest = _upload_hash(scan)
    return ("upload-file", digest) if digest else None


def target_key(scan_type: str, scan: Any) -> tuple:
    """The target a scan is of; ``("scan", id)`` when the scan records none."""
    meta = _meta(scan)
    key: tuple | None = None
    if scan_type in ("sast", "sbom_sca", "iac", "cbom", "ai_bom"):
        repo = repo_key(meta.get("repo_url"))
        if repo:
            branch = _text(meta.get("branch")) or _text(meta.get("default_branch"))
            key = ("repo", repo, branch or None)
        elif any(meta.get(flag) for flag in UPLOAD_FLAGS):
            key = upload_key(scan)
    elif scan_type == "dast":
        url = endpoint_key(meta.get("target_url"))
        key = ("url", url) if url else None
    elif scan_type == "llm":
        data_meta = _data(scan).get("metadata") if isinstance(_data(scan).get("metadata"), Mapping) else {}
        name = _text(meta.get("model_name") or data_meta.get("model_name"))
        model_type = _text(meta.get("model_type"))
        endpoint = endpoint_key(meta.get("model_uri")) if model_type == "custom" else ""
        if name and endpoint:
            key = ("model", model_type, name, endpoint)
        elif name:  # a custom model scanned before the endpoint was recorded groups by its name
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


def cbom_counts(rows: Iterable[Any]) -> tuple[dict[str, int], dict[str, int], int]:
    """``(scored, unconfirmed, in_test)`` of a CBOM's rows: findings per severity as its risk score counts them (#500's
    ``CodeRowSummary.scored``: findings only, clean inventory is not one, nor a finding in test, fixture or example code
    ``code_context: test``), the settings no crypto call is proven to read (``config_status: unconfirmed``) per
    severity, which are "unverified" (the cross-product rule: their worst case when they are all there is, else a
    note), and how many findings are in test code (listed, never scored)."""
    from backend.utilities.cbom_sources.cbom_metrics import finding_severity
    from backend.utilities.cbom_sources.cbom_rows import display_row

    scored = dict.fromkeys(SEVERITIES, 0)
    unconfirmed = dict.fromkeys(SEVERITIES, 0)
    in_test = 0
    for raw in rows or []:
        if not isinstance(raw, Mapping):
            continue
        row = display_row(dict(raw))
        severity = finding_severity(row)
        if severity is None:
            continue
        if row.get("code_context") == "test":
            in_test += 1
        elif row.get("config_status") == "unconfirmed":
            unconfirmed[severity] += 1
        else:
            scored[severity] += 1
    return scored, unconfirmed, in_test


def cbom_scored_counts(rows: Iterable[Any]) -> dict[str, int]:
    """The scored part of ``cbom_counts``: no test code, no unconfirmed setting."""
    return cbom_counts(rows)[0]


def cbom_posture_field(rows: Iterable[Any]) -> dict[str, Any]:
    """A judged CBOM's ``risk_posture`` / ``risk_posture_status`` / ``risk_unverified`` from its rows (``cbom_counts``):
    the scored findings' posture, or, when unconfirmed settings are all it has, their worst case "unverified"; a mixed
    one keeps its scored posture with the note "unverified: N unconfirmed settings (worst: …)". The Board Report
    grades the same way (review 6066492618 of #505, 3)."""
    scored, unconfirmed, _in_test = cbom_counts(rows)
    return risk_scale.posture_field(scored, unverified=unconfirmed, unverified_kind=risk_scale.KIND_UNCONFIRMED)


__all__ = ["cbom_counts", "cbom_posture_field", "cbom_scored_counts", "project_name", "upload_key", "endpoint_for_record", "endpoint_key", "latest_successful", "repo_key", "sbom_team_posture",
           "scan_counts", "target_key", "team_posture"]
