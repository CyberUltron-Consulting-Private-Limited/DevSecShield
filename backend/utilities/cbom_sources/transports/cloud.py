"""The cloud worker's half of ``ssm_hosts`` (the node's ``collectors/fleet.py`` for AWX and Salt is the other half).

``collect_ssm`` turns a claimed job into ``CollectTarget``s, applies the never-scan list before anything is sent (any
of a target's inventory addresses, or its name, listed: ``skipped_never_scan``; SSM never sees it), runs the SSM
transport, and emits each validated document's assets with ``target`` set to the inventory address, exactly as the
node posts AWX/Salt results.  Returns the job result the worker stores (``summary``, ``targets`` rows).
"""
from __future__ import annotations

import ipaddress
import secrets as _secrets
import time
from typing import Any, Callable

from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.transports import zsdoc
from backend.utilities.cbom_sources.transports.base import (CollectOptions, CollectTarget, TargetResult,
                                                            TransportCredential, TransportError)

Emit = Callable[[dict[str, Any]], None]
_FIELDS = ("type", "target", "location", "name", "algorithm", "key_size", "protocol", "facts")


class SsmRefused(Exception):
    """A reason that is safe to show the customer."""


def never_scan(lines: list[str]) -> T.ParsedTargets:
    try:
        return T.parse_exclusions(lines or [])
    except T.TargetError:
        return T.ParsedTargets()


def blocked(target: CollectTarget, excl: T.ParsedTargets) -> str | None:
    hosts = {h.lower().rstrip(".") for h in excl.hostnames}
    for raw in (target.label, *target.addresses):
        text = str(raw or "").strip().strip("[]")
        if not text:
            continue
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            if text.lower().rstrip(".") in hosts:
                return f"{text} is on the never-scan list"
            continue
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if any(v == addr.version and lo <= int(addr) <= hi for v, lo, hi in excl.intervals):
            return f"{text} is on the never-scan list"
    return None


def collect_ssm(job: dict, config: dict, exclusions: list[str], transport, emit: Emit,
                should_stop: Callable[[], str | None], deadline: float) -> dict[str, Any]:
    if config.get("transport") is None:
        raise SsmRefused(config.get("transport_problem") or "The transport of this source is missing")
    zs = config.get("zs_collect") or {}
    if not zs.get("version"):
        raise SsmRefused("No verified zs-collect release is active in ZeroShield: import and verify one first")
    handles = config.get("handles") or {}
    addresses = config.get("addresses") or {}
    labels = [str(x) for x in ((job.get("params") or {}).get("samples") if job.get("kind") == "test_connection"
                               else None) or config.get("targets") or []]
    excl = never_scan(exclusions)
    rows: list[dict[str, Any]] = []
    todo: list[CollectTarget] = []
    for label in labels:
        t = CollectTarget(label=label, handle=str(handles.get(label) or label),
                          addresses=tuple(str(a) for a in (addresses.get(label) or [])))
        reason = blocked(t, excl)
        if reason:
            rows.append({"target": label, "status": "skipped_never_scan", "error": reason, "assets": 0})
        else:
            todo.append(t)
    nonce = f"zs-{int(job.get('id') or 0)}-{int(job.get('attempt') or 1)}-{_secrets.token_hex(8)}"
    options = CollectOptions(tier=2 if int(config.get("tier") or 1) == 2 else 1, run_nonce=nonce, deadline=deadline,
                             timeout_per_target_s=int(config.get("timeout_s") or 300),
                             max_concurrency=str(config["transport"].get("max_concurrency") or "10%"),
                             zs_collect_sha256=dict(zs.get("sha256") or {}), should_stop=should_stop,
                             collector_version=str(zs["version"]))
    credential = TransportCredential("aws_role", dict(config["transport"]), {})
    done: set[str] = set()
    started = time.monotonic()
    try:
        for res in transport.run_collect(todo, credential, options):
            if res.target.label in done:
                continue
            done.add(res.target.label)
            try:
                rows.append(_post(res, emit, started))
            except Exception as exc:  # one instance's document is that instance's error row, never the job's
                rows.append({"target": res.target.label, "status": "error", "assets": 0,
                             "error": f"the zs-collect document could not be stored ({exc.__class__.__name__})"})
            started = time.monotonic()
    except TransportError as exc:
        for t in todo:
            if t.label not in done:
                done.add(t.label)
                rows.append({"target": t.label, "status": exc.status, "error": exc.detail[:256], "assets": 0})
    except Exception as exc:  # the transport itself broke: the instances it reported keep their rows
        for t in todo:
            if t.label not in done:
                done.add(t.label)
                rows.append({"target": t.label, "status": "error", "assets": 0,
                             "error": f"the SSM transport failed before this instance was reported "
                                      f"({exc.__class__.__name__})"})
    for t in todo:
        if t.label not in done:
            rows.append({"target": t.label, "status": should_stop() or "error",
                         "error": None if should_stop() else "SSM reported nothing for this instance", "assets": 0})
    ok = sum(1 for r in rows if r["status"] == "ok")
    failed = sum(1 for r in rows if r["status"] != "ok" and not r["status"].startswith("skipped_"))
    return {"summary": f"{ok} of {len(rows)} instances collected through SSM, {failed} failed",
            "targets": rows, "transport": "ssm"}


def _post(res: TargetResult, emit: Emit, started: float) -> dict[str, Any]:
    t = res.target
    ms = int((time.monotonic() - started) * 1000)
    if res.document is None:
        return {"target": t.label, "status": res.status, "error": (res.error or "")[:256] or None, "assets": 0,
                "duration_ms": ms}
    n = 0
    for a in zsdoc.relabel(res.document, t.label):
        emit({k: a.get(k) for k in _FIELDS if k in a or k in ("facts",)})
        n += 1
    status, error, counted = zsdoc.target_outcome(res.document)
    return {"target": t.label, "status": status, "error": error, "assets": n if counted is None else counted,
            "duration_ms": ms}
