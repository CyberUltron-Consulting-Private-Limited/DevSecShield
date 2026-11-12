"""Logs (G16): ``assets stored`` lines, the 5xx <-> ref matcher, and unexplained FAILED lines.

Inputs: ``logs/<container>.log`` written with ``docker logs --timestamps`` (each line starts with an RFC 3339 time),
and the HAR files under ``har/``.

* every ``cbom sources assets stored`` line of the run's teams has ``rejected=0 dropped=0``;
* every HTTP 5xx the browser saw is explained: its body carries ``(ref <hex>)`` and a backend line carries ``ref=<hex>``,
  or (no ref: a proxy error) an nginx line within +-5 s has the same method, path and status;
* every ``FAILED`` line of the run's teams is explained by a 5xx the browser saw (its ref), or listed in the ledger.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .checks import Checks
from .rundir import parse_ts

GATE = "G16"
KV = re.compile(r"(\w+)=(\S+)")
REF_BODY = re.compile(r"\(ref ([0-9a-f]{6,16})\)")
NGINX = re.compile(r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[\d.]+" (?P<status>\d{3})')
WINDOW = dt.timedelta(seconds=5)
# the containers whose logs every gate run must carry (collect-evidence.sh names them without the stack prefix)
REQUIRED_LOGS = ("backend", "cbom-cloud-worker", "nginx", "postgres")


def read_log(path: Path) -> list[tuple[dt.datetime | None, str]]:
    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        stamp, _, rest = line.partition(" ")
        ts = parse_ts(stamp)
        out.append((ts, rest if ts else line))
    return out


def load_logs(run: Path) -> dict[str, list[tuple[dt.datetime | None, str]]]:
    return {p.stem: read_log(p) for p in sorted((Path(run) / "logs").glob("*.log"))}


def har_entries(run: Path) -> list[dict[str, Any]]:
    entries = []
    for path in sorted((Path(run) / "har").glob("*.har")):
        try:
            har = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        for entry in har.get("log", {}).get("entries", []):
            entry["_har"] = path.name
            entries.append(entry)
    return entries


def _team_of(text: str) -> str | None:
    m = re.search(r"\bteam=(\d+)", text)
    return m.group(1) if m else None


def judge(run: Path, checks: Checks, teams: list[int | str]) -> dict[str, Any]:
    run = Path(run)
    logs = load_logs(run)
    teams_s = {str(t) for t in teams}
    out: dict[str, Any] = {"files": sorted(logs)}
    if not logs:
        checks.not_run(f"{GATE}/logs", GATE, "log", "logs/ is empty (collect-evidence.sh not run)", {})
        return out
    all_lines = [(name, ts, text) for name, lines in logs.items() for ts, text in lines]
    for needed in REQUIRED_LOGS:
        checks.verdict(f"{GATE}/collected/{needed}", GATE, "log", needed in logs, "log-missing",
                       {"kind": "log", "check": "collected", "log": needed}, expected=f"logs/{needed}.log",
                       observed=f"{len(logs.get(needed, []))} lines" if needed in logs else "absent")

    stored = [(n, ts, t) for n, ts, t in all_lines if "cbom sources assets stored" in t and _team_of(t) in teams_s]
    out["assets_stored_lines"] = len(stored)
    for i, (name, ts, text) in enumerate(stored):
        kv = dict(KV.findall(text))
        ok = kv.get("rejected") == "0" and kv.get("dropped") == "0"
        checks.verdict(f"{GATE}/assets-stored/{kv.get('job', i)}-{kv.get('attempt', '')}-{i}", GATE, "log", ok,
                       "assets-rejected-or-dropped", {"kind": "log", "check": "assets_stored", "job": kv.get("job")},
                       expected="rejected=0 dropped=0",
                       observed={k: kv.get(k) for k in ("accepted", "duplicate", "rejected", "dropped", "total")},
                       evidence=[f"logs/{name}.log"])

    refs_logged = {m.group(1) for _, _, t in all_lines for m in re.finditer(r"\bref=([0-9a-f]{6,16})", t)}
    nginx = [(ts, NGINX.search(t)) for n, ts, t in all_lines if "nginx" in n]
    seen_refs: set[str] = set()
    entries = har_entries(run)
    out["har_entries"] = len(entries)
    n5xx = 0
    for entry in entries:
        status = int((entry.get("response") or {}).get("status") or 0)
        if status < 500:
            continue
        n5xx += 1
        req = entry.get("request") or {}
        body = ((entry.get("response") or {}).get("content") or {}).get("text") or ""
        url = urlsplit(req.get("url", ""))
        when = parse_ts(entry.get("startedDateTime"))
        m = REF_BODY.search(body)
        cid = f"{GATE}/5xx/{entry['_har']}/{req.get('method')}{url.path}@{entry.get('startedDateTime')}"
        subject = {"kind": "log", "check": "5xx", "status": status, "path": url.path}
        if m:
            seen_refs.add(m.group(1))
            checks.verdict(cid, GATE, "log", m.group(1) in refs_logged, "5xx-ref-not-logged", subject,
                           expected=f"a log line with ref={m.group(1)}", observed="found" if m.group(1) in refs_logged
                           else "no such log line")
            continue
        near = [mm for ts, mm in nginx if mm and when and ts and abs(ts - when) <= WINDOW
                and mm.group("method") == req.get("method") and mm.group("path").split("?")[0] == url.path
                and int(mm.group("status")) == status]
        checks.verdict(cid, GATE, "log", bool(near), "5xx-without-log-ref", subject,
                       expected="a (ref ...) in the body or an nginx line within 5 s", observed="none")
    out["http_5xx"] = n5xx

    failed = [(n, ts, t) for n, ts, t in all_lines if " FAILED" in t and "cbom sources" in t
              and _team_of(t) in teams_s]
    out["failed_lines"] = len(failed)
    for i, (name, ts, text) in enumerate(failed):
        kv = dict(KV.findall(text))
        explained = kv.get("ref") in seen_refs
        action = re.sub(r"^.*cbom sources (.*?) FAILED.*$", r"\1", text)
        checks.verdict(f"{GATE}/failed/{name}/{i}", GATE, "log", explained, "unexplained-failed-line",
                       {"kind": "log", "check": "failed_line", "action": action, "error": kv.get("error")},
                       expected="explained by a 5xx the customer saw", observed=text[:300],
                       evidence=[f"logs/{name}.log"])
    return out
