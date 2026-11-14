"""AWS organisation walk and the cloud pool's unit of work: one slice per account x region (F1).

* ``member_accounts``: every member account of the organisation (``organizations:ListAccounts`` paged to the end, no
  cap; it used to stop at 200), then each ACTIVE member's reader role assumed in parallel on a bounded thread pool
  (``CBOM_AWS_ORG_WORKERS``, default 16).  Throttling (``ThrottlingException`` / ``TooManyRequestsException`` ...)
  is retried with capped exponential backoff and jitter on every call (``with_backoff``); a member whose role cannot
  be assumed becomes one ``auth_failed`` target per region, exactly the rows the serial walk always produced.
* ``plan_slices``: the safety checks of ``aws_collect.open_account`` plus the walk, turned into the list of
  (account, role, region) slices the cloud worker queues (``cbom_sources.slices.fan_out``).
* ``collect_slice``: read one slice (``aws_collect.read_target``) and summarise it.  The assets are the same rows,
  with the same asset keys, as the serial walk's, so drift and identities are unchanged.

The pool threads only call AWS; ``emit`` and ``should_stop`` (the worker's asset buffer and lease) are called from the
caller's thread only.
"""
from __future__ import annotations

import os
import random
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable

from backend.utilities.cbom_sources import aws_collect as AC
from backend.utilities.cbom_sources.aws_validate import _code
from backend.utilities.cbom_sources.common import log

THROTTLED = frozenset({
    "Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded", "RequestThrottled",
    "RequestThrottledException", "ThrottledException", "SlowDown", "PriorRequestNotComplete",
})
PAGE_SIZE = 20  # ListAccounts' maximum
_sleep = time.sleep  # tests replace it


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(os.environ.get(name, "") or default)
    except ValueError:
        value = default
    return max(lo, min(hi, value))


def org_workers() -> int:
    return _env_int("CBOM_AWS_ORG_WORKERS", 16, 1, 64)


def with_backoff(fn: Callable[[], Any], *, what: str, attempts: int | None = None, base_s: float = 0.5,
                 cap_s: float = 20.0, sleep: Callable[[float], None] | None = None) -> Any:
    """Call ``fn``; on an AWS throttling error wait (capped exponential, half jitter) and call again.  Any other
    error, or the last throttle, is raised.  botocore's own adaptive retries run first inside ``fn``; this outer loop
    covers what they give up on (an organisation-wide ListAccounts burst, STS under a 1,000-account walk)."""
    tries = attempts or _env_int("CBOM_AWS_THROTTLE_RETRIES", 6, 1, 20)
    for attempt in range(1, tries + 1):
        try:
            return fn()
        except Exception as exc:
            code = _code(exc)
            if code not in THROTTLED or attempt == tries:
                raise
            delay = min(cap_s, base_s * (2 ** (attempt - 1))) * (0.5 + random.random() / 2)
            log("aws throttled; backing off", what=what, code=code, attempt=attempt, delay_ms=int(delay * 1000))
            (sleep or _sleep)(delay)
    raise AssertionError("unreachable")  # pragma: no cover


def list_accounts(org, should_stop: Callable[[], str | None]) -> tuple[list[dict[str, Any]], str | None]:
    """Every account of the organisation, one page per call (each page retried on throttling on its own, so a throttle
    on page 40 does not restart the walk).  Pages are resumed with botocore's own resume token, which works whatever
    the service's NextToken looks like.  Returns (accounts, stop reason or None)."""
    paginator = org.get_paginator("list_accounts")
    out: list[dict[str, Any]] = []
    token: str | None = None

    def page() -> tuple[list[dict[str, Any]], str | None]:
        config: dict[str, Any] = {"PageSize": PAGE_SIZE, "MaxItems": PAGE_SIZE}
        if token:
            config["StartingToken"] = token
        iterator = paginator.paginate(PaginationConfig=config)
        items = [account for p in iterator for account in (p.get("Accounts") or [])]
        return items, iterator.resume_token

    while True:
        reason = should_stop()
        if reason:
            return out, reason
        items, token = with_backoff(page, what="organizations:ListAccounts")
        out.extend(items)
        if not token:
            return out, None


@dataclass
class Walk:
    reachable: list[Any] = field(default_factory=list)  # aws_collect._Account, role assumed
    targets: list[dict[str, Any]] = field(default_factory=list)  # organisation and unreachable-account rows
    listed: int = 0  # every account ListAccounts returned
    unreachable: int = 0  # ACTIVE members whose role could not be assumed (or were not tried: stop)
    duration_ms: int = 0


def member_accounts(mgmt, base, boto_cfg, role_arn: str, external_id: str, team_id: int, regions: list[str],
                    emit: AC.Emit, should_stop: Callable[[], str | None], *, workers: int | None = None) -> Walk:
    """The organisation's other ACTIVE accounts whose reader role could be assumed, plus target rows for the rest."""
    started = time.monotonic()
    walk = Walk()
    org_label = f"aws:{mgmt.account}"
    org_where = f"arn:aws:organizations::{mgmt.account}:accounts"
    try:
        org = mgmt.client("organizations", "global")
        members, stopped = list_accounts(org, should_stop)
    except Exception as exc:
        # The member list decides which accounts are read at all: when it fails the accounts that were not listed are
        # unknown, so this is a failed target of its own (the job is partial and never compared), not a note.
        emit(AC._gap(org_label, org_where, "organization member accounts", "error", _code(exc)))
        walk.targets.append({"target": f"{org_label}/organization", "status": "error", "assets": 0,
                             "error": f"organization member accounts not listed: {_code(exc)}"[:256]})
        walk.duration_ms = int((time.monotonic() - started) * 1000)
        return walk
    walk.listed = len(members)
    if stopped:
        emit(AC._gap(org_label, org_where, "organization member accounts", "truncated",
                     f"Stopped after {len(members)} member accounts: {stopped}"[:256]))
        walk.targets.append({"target": f"{org_label}/organization", "status": "error", "assets": 0,
                             "error": f"Stopped after {len(members)} member accounts were listed"[:256]})
    role_name = role_arn.split(":role/", 1)[1]
    partition = role_arn.split(":")[1]
    candidates = [AC._Account(base, boto_cfg, f"arn:{partition}:iam::{m['Id']}:role/{role_name}", external_id, team_id)
                  for m in members if m.get("Status") == "ACTIVE" and m.get("Id") != mgmt.account]
    first = regions[0] if regions else "us-east-1"
    halt = threading.Event()

    def check(acct) -> tuple[Any, str | None]:
        if halt.is_set():
            return acct, "skipped"
        try:
            with_backoff(lambda: acct.check(first), what="sts:AssumeRole")
            return acct, None
        except AC.AwsCollectError as exc:
            return acct, str(exc)[:256]
        except Exception as exc:
            return acct, _code(exc)[:256]

    failed: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=workers or org_workers(), thread_name_prefix="aws-org") as pool:
        futures = [pool.submit(check, acct) for acct in candidates]
        for future in as_completed(futures):
            acct, error = future.result()
            if error is None:
                walk.reachable.append(acct)
            else:
                failed[acct.account] = error
            if not halt.is_set() and should_stop():  # the caller's lease and stop flags, from the caller's thread
                halt.set()
    order = {a.account: i for i, a in enumerate(candidates)}
    walk.reachable.sort(key=lambda a: order[a.account])  # the organisation's order, whatever finished first
    reason = should_stop() if halt.is_set() else None
    for acct in candidates:
        error = failed.get(acct.account)
        if error is None:
            continue
        walk.unreachable += 1
        for region in ["global", *regions]:
            if error == "skipped":
                walk.targets.append({"target": f"aws:{acct.account}/{region}", "status": "skipped_cancelled",
                                     "error": (reason or "Stopped")[:256], "assets": 0})
            else:  # the serial walk's row for a member whose AssumeRole failed
                walk.targets.append({"target": f"aws:{acct.account}/{region}", "status": "auth_failed",
                                     "error": error, "assets": 0})
    walk.duration_ms = int((time.monotonic() - started) * 1000)
    log("aws organisation walked", team=team_id, listed=walk.listed, reachable=len(walk.reachable),
        unreachable=walk.unreachable, workers=workers or org_workers(), ms=walk.duration_ms)
    return walk


def plan_slices(team_id: int, cfg: dict[str, Any], external_id: str, emit: AC.Emit,
                should_stop: Callable[[], str | None]) -> dict[str, Any]:
    """Safety checks, then the slices of one AWS source: [{account_id, role_arn, region}], management account first,
    "global" before the regions of each account (the serial walk's order).  Raises AwsCollectError (safe to show)."""
    regions = list(cfg.get("regions") or ["us-east-1"])
    base, boto_cfg, mgmt = AC.open_account(team_id, cfg, external_id)
    accounts = [mgmt]
    out: dict[str, Any] = {"targets": [], "accounts": 1}
    if cfg.get("scope") == "organization":
        walk = member_accounts(mgmt, base, boto_cfg, cfg["role_arn"], external_id, team_id, regions, emit, should_stop)
        accounts += walk.reachable
        out.update(targets=walk.targets, accounts=1 + len(walk.reachable) + walk.unreachable,
                   org={"listed": walk.listed, "reachable": len(walk.reachable), "unreachable": walk.unreachable,
                        "ms": walk.duration_ms})
    out["slices"] = [{"account_id": a.account, "role_arn": a.role_arn, "region": region}
                     for a in accounts for region in ["global", *regions]]
    _remember(accounts)
    return out


# Assumed sessions a process reuses across its slices (consecutive slices are mostly regions of the same account).
_CACHE: "OrderedDict[tuple[int, str, str], Any]" = OrderedDict()
_CACHE_LOCK = threading.Lock()


def _cache_size() -> int:
    return _env_int("CBOM_AWS_SESSION_CACHE", 64, 1, 1024)


def _remember(accounts: list[Any]) -> None:
    with _CACHE_LOCK:
        for acct in accounts:
            _CACHE[(acct.team_id, acct.role_arn, acct.external_id)] = acct
            _CACHE.move_to_end((acct.team_id, acct.role_arn, acct.external_id))
        while len(_CACHE) > _cache_size():
            _CACHE.popitem(last=False)


def _account(team_id: int, role_arn: str, external_id: str):
    key = (team_id, role_arn, external_id)
    with _CACHE_LOCK:
        acct = _CACHE.get(key)
        if acct is not None:
            _CACHE.move_to_end(key)
            return acct
    base, boto_cfg = _base()
    acct = AC._Account(base, boto_cfg, role_arn, external_id, team_id)
    _remember([acct])
    return acct


_BASE: dict[str, Any] = {}


def _base() -> tuple[Any, Any]:
    """ZeroShield's own session, one per process for an hour: every slice's clients come from it (one model loader)."""
    with _CACHE_LOCK:
        if _BASE and time.monotonic() - _BASE["at"] < 3600:
            return _BASE["base"], _BASE["cfg"]
    try:
        base, boto_cfg = AC._boto(retries=5, mode="adaptive")
    except Exception as exc:
        raise AC.AwsCollectError("ZeroShield AWS credentials are not configured") from exc
    with _CACHE_LOCK:
        _BASE.update(base=base, cfg=boto_cfg, at=time.monotonic())
    return base, boto_cfg


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
        _BASE.clear()


def collect_slice(team_id: int, cfg: dict[str, Any], external_id: str, role_arn: str, region: str, emit: AC.Emit,
                  should_stop: Callable[[], str | None]) -> dict[str, Any]:
    """Read one account x region.  The role ARN must be the source's role or a member role of the same name (the
    parent planned it); the identity check of ``_Account.assume`` still runs on every (re-)assume."""
    started = time.monotonic()
    acct = _account(team_id, role_arn, external_id)
    target = AC.read_target(acct, region, cfg, emit, should_stop)
    return AC.summary([target], team_id, started, quiet=True, account=acct.account, region=region)
