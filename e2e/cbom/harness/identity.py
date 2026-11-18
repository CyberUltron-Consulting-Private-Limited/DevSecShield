"""Stable identities of judged checks across gate runs (ledger v3 pins; review 5878413538 major 3).

Every gate run is a new customer on a regenerated lab, so the product's ids (asset, job, team, run, node) and the lab's
fresh material (certificate dates, serials, fingerprints, SSH host keys, the lab run id) differ between two runs of the
same SHA. A ledger row pins the failures it tolerates by identity, never by count, so both the check id and its
expected/observed values are normalised here, using only the run's own evidence:

  check ids  asset id -> ``<type>@<location>`` (api/assets-run<k>.json), job id -> ``job:<source name>``
             (api ``targets``), team/run/node ids -> ``team:A`` / ``run:1`` / ``node`` (flow-state, MANIFEST);
  values     ISO times -> offset from the lab's ``generated_at`` (``gen+397d``: the lab plants dates relative to the
             run, O-2), hex digests and serials of 12+ characters -> ``<hex:N>``, OpenSSH ``SHA256:`` fingerprints ->
             ``<ssh-fp>``, the lab's run id -> ``lab-<run>``, the product's ids as above where a value is an id field.

What survives normalisation is what a regression changes: which check fails, on which asset, and what the oracle and
the product said (a worse sample, a different wrong value, a swap of one failure for another).
"""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

from .rundir import parse_ts, read_json

# a bare number that may be a run, team or node id; never a port (":22"), an address part or an index ("[0]")
_NUM = re.compile(r"(?<![\w.:@#\[/-])(\d+)(?![\w.\]])")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?")
_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{12,}(?![0-9A-Za-z])")
_SSH_FP = re.compile(r"SHA256:[A-Za-z0-9+/]{43}=?")
_LAB_RUN = re.compile(r"lab-\d{8}T\d{6}Z")
ID_FIELDS = {"job_id": "job", "asset_id": "asset"}


def id_maps(run: Path) -> dict[str, Any]:
    """The run's own ids -> stable names (assets, jobs, teams, runs, node) and the lab's time anchor."""
    run = Path(run)
    assets: dict[str, str] = {}
    jobs: dict[str, str] = {}
    for doc_path in sorted((run / "api").glob("assets-run*.json")):
        doc = read_json(doc_path) or {}
        for item in doc.get("items") or []:
            assets[str(item.get("id"))] = f"{item.get('type')}@{item.get('location')}"
        for job in doc.get("targets") or []:
            jobs[str(job.get("job_id"))] = f"job:{job.get('source_name')}"
    man = read_json(run / "MANIFEST.json", {}) or {}
    state = read_json(run / "flow-state.json", {}) or {}
    other: dict[str, str] = {}
    for key, team in (man.get("teams") or state.get("teams") or {}).items():
        other[str(team)] = f"team:{key}"
    for k, rid in enumerate(state.get("runs") or [], 1):
        other[str(rid)] = f"run:{k}"
    if (state.get("node") or {}).get("id"):
        other[str(state["node"]["id"])] = "node"
    anchor = None
    for p in sorted((run / "oracle").glob("run*.json")):
        anchor = parse_ts((read_json(p) or {}).get("generated_at"))
        if anchor:
            break
    return {"asset": assets, "job": jobs, "other": other, "anchor": anchor}


def normalise_id(check_id: str, maps: dict[str, Any]) -> str:
    """A check id with the product's ids replaced by stable names (the same rules as CB-05's compare)."""
    out = re.sub(r"/asset/(\d+)/", lambda m: f"/asset/{maps['asset'].get(m.group(1), 'asset?')}/", check_id)
    out = re.sub(r"/(extra|unattributed|out-of-scope)/(\d+)$",
                 lambda m: f"/{m.group(1)}/{maps['asset'].get(m.group(2), 'asset?')}", out)
    out = re.sub(r"job_(\d+)", lambda m: maps["job"].get(m.group(1), "job?"), out)
    out = re.sub(r"_(\d+)_skipped$", lambda m: f"_{maps['job'].get(m.group(1), 'job?')}_skipped", out)
    # G16 "<job>-<attempt>-<line index>": the job by its source, the attempt kept, the log-line index dropped
    out = re.sub(r"assets-stored/(\d+)-(\d+)-\d+$",
                 lambda m: f"assets-stored/{maps['job'].get(m.group(1), 'job?')}-{m.group(2)}", out)
    out = re.sub(r"/job-(\d+)-", lambda m: f"/{maps['job'].get(m.group(1), 'job?')}-", out)
    return _NUM.sub(lambda m: maps["other"].get(m.group(1), m.group(1)), out)


def _time(text: str, anchor: dt.datetime | None) -> str:
    ts = parse_ts(text if "T" in text or " " in text else f"{text}T00:00:00Z")
    if ts is None:
        return text
    if anchor is None:
        return "<time>"
    secs = int(round((ts - anchor).total_seconds()))
    sign = "+" if secs >= 0 else "-"
    days, rest = divmod(abs(secs), 86400)
    return f"gen{sign}{days}d" + (f"{rest}s" if rest else "")


def _string(text: str, maps: dict[str, Any]) -> str:
    out = _SSH_FP.sub("<ssh-fp>", text)
    out = _LAB_RUN.sub("lab-<run>", out)
    out = _TIME.sub(lambda m: _time(m.group(0), maps.get("anchor")), out)
    return _HEX.sub(lambda m: f"<hex:{len(m.group(0))}>", out)


def normalise_value(value: Any, maps: dict[str, Any], field: str | None = None) -> Any:
    """A check's expected/observed value with the run-specific parts made stable (see the module doc)."""
    if field in ID_FIELDS and isinstance(value, (int, str)) and str(value).isdigit():
        return maps[ID_FIELDS[field]].get(str(value), f"{ID_FIELDS[field]}?")
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return _string(value, maps)
    if isinstance(value, dict):
        return {_string(str(k), maps): normalise_value(v, maps, str(k)) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple, set)):
        items = [normalise_value(v, maps, field) for v in value]
        return items if isinstance(value, (list, tuple)) else sorted(items, key=lambda v: json.dumps(v, sort_keys=True))
    return _string(str(value), maps)


def identity(check: Any, maps: dict[str, Any]) -> dict[str, Any]:
    """The pinned form of a judged check: id, verdict (FAIL / NOT-JUDGED / NOT-RUN), expected and observed."""
    field = (check.subject or {}).get("field")
    out: dict[str, Any] = {"id": normalise_id(check.id, maps), "verdict": check.verdict}
    if check.verdict != "NOT-RUN":
        out["expected"] = normalise_value(check.expected, maps, field)
        out["observed"] = normalise_value(check.observed, maps, field)
    elif check.observed is not None:  # a NOT-RUN(no-expectation) records what the customer was shown
        out["observed"] = normalise_value(check.observed, maps, field)
    return out


def key(ident: dict[str, Any]) -> str:
    """A canonical string for an identity (multiset comparison)."""
    return json.dumps({k: ident.get(k) for k in ("id", "verdict", "expected", "observed") if k in ident},
                      sort_keys=True, default=str)
