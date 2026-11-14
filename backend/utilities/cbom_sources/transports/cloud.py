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
SKIP_STATUSES = ("skipped_deadline", "skipped_cancelled", "skipped_stop", "skipped_window")


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

    def stop_status() -> str | None:
        """The transports' ``should_stop`` answers a skip status; the cloud worker's answers why it stops ("Stopped
        at the maximum run time", a lease or store problem).  Rows carry the status, never that text."""
        reason = should_stop()
        if not reason:
            return None
        if reason in SKIP_STATUSES:
            return reason
        return "skipped_deadline" if time.monotonic() >= deadline else "skipped_cancelled"

    options = CollectOptions(tier=2 if int(config.get("tier") or 1) == 2 else 1, run_nonce=nonce, deadline=deadline,
                             timeout_per_target_s=int(config.get("timeout_s") or 300),
                             max_concurrency=str(config["transport"].get("max_concurrency") or "10%"),
                             zs_collect_sha256=dict(zs.get("sha256") or {}), should_stop=stop_status,
                             collector_version=str(zs["version"]))
    credential = TransportCredential("aws_role", dict(config["transport"]), {})
    done: set[str] = set()
    started = time.monotonic()

    def reported():  # the transport's call itself, not only its iteration, is inside the guard below
        yield from transport.run_collect(todo, credential, options)

    def fail_the_rest(status: str, error: str) -> None:
        for t in todo:
            if t.label not in done:
                done.add(t.label)
                rows.append({"target": t.label, "status": status, "error": error[:256], "assets": 0})

    results = reported()
    try:
        while True:
            try:  # guarded: the transport's own step only (storing assets happens in _take, outside this)
                res = next(results)
            except StopIteration:
                break
            except TransportError as exc:
                fail_the_rest(exc.status, exc.detail)
                break
            except Exception as exc:  # the transport itself broke: the instances it reported keep their rows
                fail_the_rest("error", f"the SSM transport failed before this instance was reported "
                                       f"({exc.__class__.__name__})")
                break
            if res.target.label in done:
                continue
            done.add(res.target.label)
            rows.append(_take(res, emit, started))
            started = time.monotonic()
    finally:
        results.close()  # whatever ended the loop (a failed store too) ends the transport's run: no next command
    for t in todo:
        if t.label not in done:
            stop = stop_status()
            rows.append({"target": t.label, "status": stop or "error",
                         "error": None if stop else "SSM reported nothing for this instance", "assets": 0})
    ok = sum(1 for r in rows if r["status"] == "ok")
    failed = sum(1 for r in rows if r["status"] != "ok" and not r["status"].startswith("skipped_"))
    return {"summary": f"{ok} of {len(rows)} instances collected through SSM, {failed} failed",
            "targets": rows, "transport": "ssm"}


def _assets(res: TargetResult) -> tuple[list[dict[str, Any]], tuple[str, str | None, int | None]]:
    """One instance's assets as they are stored, and its outcome (status, error, zs-collect's count).  Pure: stores
    nothing, so whatever it raises is about this instance's document, never about the database or the job."""
    assets = [{k: a.get(k) for k in _FIELDS if k in a or k in ("facts",)}
              for a in zsdoc.relabel(res.document, res.target.label)]
    return assets, zsdoc.target_outcome(res.document)


def _take(res: TargetResult, emit: Emit, started: float) -> dict[str, Any]:
    """One reported instance's row, with its assets stored.  Only reading its document is guarded (one instance's
    document is that instance's error row, never the job's).  Storing is not: an infrastructure failure in ``emit``
    (the database, the lease) fails the job, as it does for every other cloud collector, instead of rows that say
    ``ok`` for assets that were never stored."""
    t = res.target
    ms = int((time.monotonic() - started) * 1000)
    if res.document is None:
        return {"target": t.label, "status": res.status, "error": (res.error or "")[:256] or None, "assets": 0,
                "duration_ms": ms}
    try:
        assets, (status, error, counted) = _assets(res)
    except Exception as exc:
        return {"target": t.label, "status": "error", "assets": 0, "duration_ms": ms,
                "error": f"the zs-collect document could not be read ({exc.__class__.__name__})"}
    for a in assets:
        emit(a)
    return {"target": t.label, "status": status, "error": error, "assets": len(assets) if counted is None else counted,
            "duration_ms": ms}
