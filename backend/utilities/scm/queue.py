"""Runs, credits, and the bounded fair queue of repository scans.

Credits per run
* ``estimate`` prices every repository x product of a request (``pricing``), says what is skipped and why (already
  queued, a language SAST cannot read, no policy), the total, the balance and whether it is affordable.
* ``create_run`` re-plans, refuses with ``EstimateChanged`` when the price is not the one the customer saw, then
  charges the WHOLE run in one conditional UPDATE in the same transaction as the run and its requests (so a run is
  charged once and fully, or not at all). The same ``client_request_id`` is the same run (a retried click is free).
* A queued request that is cancelled or skipped is refunded by this module, once (compare-and-set on ``refunded``).
  From the moment a Scan row exists its ``credit_charged`` is the charge, and the existing paths refund it: a worker
  failure (``get_status_and_update_db``) or a cancel (``cancel_scan``). A Scan that could not be sent loses its
  ``credit_charged`` before this module refunds, so no charge is ever refunded twice.
* A dispatched scan is a Scan row exactly like one ``/start`` charged: ``credit_consumed`` (the estimate),
  ``credit_estimate`` (``credit_estimate.input_digest`` of the payload without its token, plus the price and the
  minimum) and ``credit_charged`` (what was taken). The minimum charge per type comes from ``credit_estimate`` too.
  When the scan path refunds it (a worker failure, a cancel on the scan page), ``poll_tick`` records that refund on
  the request and the run without moving credits again, so a run's charged and refunded totals match the balance.
* A launcher that raised AFTER the scan reached a worker (its ``task_id`` is stored) leaves a dispatched scan, not a
  failed one: refunding it would make a running scan free (and its later failure refund would pay twice).

The queue (``scmscanrequest``) and the dispatcher
* Priority: push (0) > manual (1) > schedule (2), then age.
* Bounded: at most ``REPO_SCAN_MAX_INFLIGHT`` (default 8) repository scans in Celery at once, so bulk runs never
  fill ``scan_worker_queue`` ahead of the scans people start by hand. ``REPO_SCAN_TEAM_MAX_INFLIGHT`` (default: half the
  global cap, at least 1; 0: no limit) bounds one team's parallelism, so one tenant's long scans never hold every slot.
* Fair and work-conserving: each free slot goes to the waiting team with the FEWEST scans in flight (ties: the team
  served least recently, then the lower team id). A team alone uses every slot; when another team queues work it takes
  the next slots that free up until both have the same number in flight. A team with 1,000 queued repositories gets
  the same share as a team with 3 while both are waiting, so the small team is never behind the big one's backlog.
* One decider at a time: on PostgreSQL the tick holds an advisory lock (so two dispatchers cannot both see a free
  slot), and every claim is a compare-and-set (``queued -> dispatching``), so no request is ever sent twice.
* A dispatcher that died mid-claim leaves ``dispatching`` rows; after ``DISPATCH_LEASE`` they are adopted when the
  task id the queue chose (stored before sending) is known to a worker, else withdrawn and re-queued (or failed and
  refunded after ``MAX_ATTEMPTS``): never sent twice, never run uncharged.
* A dispatched scan no worker picked up within ``REPO_SCAN_START_TIMEOUT_MIN`` (60) or that has not finished within
  ``REPO_SCAN_RUN_TIMEOUT_MIN`` (180) is reconciled with the worker, then stopped and refunded by the cancel path
  (``expire_lost_scan``), so a lost task frees its slot.

Completion: ``poll_tick`` reads each in-flight scan through ``get_status_and_update_db`` (results, Mongo findings and
the failure refund are unchanged), closes the request, records the repository's last scan and folds the roll-up.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import os
import uuid
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, insert, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.new_models import Scan, Team
from backend.utilities.scan import credit_estimate
from backend.utilities.scm import pricing, rollup
from backend.utilities.scm.common import log, redact_urls
from backend.utilities.scm.inventory import filter_input
from backend.utilities.scm.models import ScmConnection, ScmRepository, ScmScanPolicy, ScmScanRequest, ScmScanRun
from backend.utilities.scm.policies import team_policies, winning_policy

PRIORITY = {"push": 0, "manual": 1, "schedule": 2}
ACTIVE = ("queued", "dispatching", "dispatched")
FINAL = ("done", "failed", "skipped", "cancelled")
DISPATCH_LEASE = dt.timedelta(minutes=10)
MAX_ATTEMPTS = 3
LOCK_KEY = 0x53434D51  # "SCMQ"
SAST_LANGS = {"python": "python", "java": "java", "javascript": "javascript", "typescript": "javascript",
              "php": "php", "c": "c", "c++": "c", "ruby": "ruby", "rust": "rust", "swift": "swift", "c#": "csharp",
              "kotlin": "kotlin"}
DEFAULT_IAC_MODES = ["terraform", "k8s", "helm", "aws_cloudformation", "ansible", "pulumi", "aws_cdk"]


def env_max_inflight() -> int:
    return max(1, int(os.environ.get("REPO_SCAN_MAX_INFLIGHT", "8") or 8))


def env_team_max_inflight(cap: int | None = None) -> int:
    """At most this many of one team's repository scans in flight. Unset: half the global cap (at least 1), so one
    team's long scans can never hold every slot; ``0``: no per-team limit (water-filling alone shares the slots)."""
    raw = os.environ.get("REPO_SCAN_TEAM_MAX_INFLIGHT")
    if raw is None or not raw.strip():
        return max(1, (cap or env_max_inflight()) // 2)
    return max(0, int(raw))


def env_start_timeout() -> dt.timedelta:
    """A dispatched scan no worker has picked up (still ``pending``) after this long is treated as lost."""
    return dt.timedelta(minutes=max(1, int(os.environ.get("REPO_SCAN_START_TIMEOUT_MIN", "60") or 60)))


def env_run_timeout() -> dt.timedelta:
    """A dispatched scan not finished after this long is treated as lost: the longest scan task's hard time limit
    (``scan_worker.py``: 9,000 s) plus a margin."""
    return dt.timedelta(minutes=max(1, int(os.environ.get("REPO_SCAN_RUN_TIMEOUT_MIN", "180") or 180)))


class EstimateChanged(Exception):
    def __init__(self, estimate: dict[str, Any]):
        super().__init__("The price changed")
        self.estimate = estimate


class InsufficientCredits(Exception):
    def __init__(self, estimate: dict[str, Any]):
        super().__init__("Not enough credits")
        self.estimate = estimate


class NothingToScan(Exception):
    def __init__(self, estimate: dict[str, Any]):
        super().__init__("Nothing to scan")
        self.estimate = estimate


class QueueInputError(ValueError):
    """Bad input; ``str(err)`` is safe to show."""


@dataclass
class PlanItem:
    repo_id: int
    product: str
    branch: str
    credits_c: int


@dataclass
class Plan:
    items: list[PlanItem] = field(default_factory=list)
    skipped: list[tuple[int, str, str]] = field(default_factory=list)

    @property
    def credits_c(self) -> int:
        return sum(i.credits_c for i in self.items)


def sast_language(language: str | None) -> str | None:
    return SAST_LANGS.get(str(language or "").strip().lower())


def _active_keys(session: Session, team_id: int, statuses: Iterable[str] = ACTIVE) -> set[tuple[int, str, str]]:
    rows = session.exec(select(ScmScanRequest.repo_id, ScmScanRequest.product, ScmScanRequest.branch)
                        .where(ScmScanRequest.team_id == team_id,
                               ScmScanRequest.status.in_(tuple(statuses)))).all()  # type: ignore[union-attr]
    return {(r, p, b) for r, p, b in rows}


def _check_products(products: Iterable[str]) -> list[str]:
    out = []
    for p in products:
        if p not in pricing.PRODUCTS:
            raise QueueInputError(f"Products: {str(p)[:20]} cannot scan a repository (use "
                                  f"{', '.join(pricing.PRODUCTS)})")
        if p not in out:
            out.append(p)
    return out


def plan(session: Session, team_id: int, *, repo_ids: Iterable[int] | None = None, policy_id: int | None = None,
         products: Iterable[str] | None = None, branch: str | None = None) -> Plan:
    out = Plan()
    policies = team_policies(session, team_id)
    chosen = _check_products(products) if products else None
    if policy_id is not None:
        policy = next((p for p in policies if p.id == policy_id), None)
        if policy is None:
            raise QueueInputError("Policy not found")
        repos = session.exec(select(ScmRepository).where(ScmRepository.team_id == team_id,
                                                         ScmRepository.in_scope == True,  # noqa: E712
                                                         ScmRepository.removed_at == None)  # noqa: E711
                             .order_by(ScmRepository.id)).all()
        pairs = []
        for repo in repos:
            winner, _why = winning_policy(filter_input(repo), policies, repo.policy_id)
            if winner is not None and winner.id == policy_id:
                pairs.append((repo, chosen or _check_products(policy.products), branch or policy.branch))
    else:
        ids = sorted({int(i) for i in (repo_ids or [])})
        if not ids:
            raise QueueInputError("Choose at least one repository")
        repos = session.exec(select(ScmRepository).where(ScmRepository.team_id == team_id,
                                                         ScmRepository.id.in_(ids),  # type: ignore[union-attr]
                                                         ScmRepository.removed_at == None)  # noqa: E711
                             .order_by(ScmRepository.id)).all()
        pairs = []
        for repo in repos:
            if chosen:
                pairs.append((repo, chosen, branch or ""))
                continue
            winner, _why = winning_policy(filter_input(repo), policies, repo.policy_id)
            if winner is None:
                out.skipped.append((repo.id, "*", "no_policy"))
                continue
            pairs.append((repo, _check_products(winner.products), branch or winner.branch))
    active = _active_keys(session, team_id)
    for repo, prods, br in pairs:
        target = (br or repo.default_branch or "main")[:255]
        for product in prods:
            if (repo.id, product, target) in active:
                out.skipped.append((repo.id, product, "already_queued"))
            elif product == "sast" and sast_language(repo.language) is None:
                out.skipped.append((repo.id, product, "sast_language"))
            else:
                out.items.append(PlanItem(repo.id, product, target, pricing.price_c(product, repo.size_kb)))
    return out


def _balance(session: Session, team_id: int) -> float:
    team = session.get(Team, team_id)
    return round(float(team.credit_balance if team else 0.0), 2)


def describe_plan(session: Session, team_id: int, p: Plan) -> dict[str, Any]:
    per_product: dict[str, dict[str, Any]] = {}
    for item in p.items:
        slot = per_product.setdefault(item.product, {"scans": 0, "credits_c": 0})
        slot["scans"] += 1
        slot["credits_c"] += item.credits_c
    credits = pricing.as_credits(p.credits_c)
    balance = _balance(session, team_id)
    return {"scans": len(p.items), "repos": len({i.repo_id for i in p.items}), "credits": credits,
            "per_product": {k: {"scans": v["scans"], "credits": pricing.as_credits(v["credits_c"])}
                            for k, v in sorted(per_product.items())},
            "skipped": list(p.skipped), "skipped_counts": dict(Counter(r for _i, _p, r in p.skipped)),
            "balance": balance, "affordable": balance >= credits, "formula": pricing.FORMULA}


def estimate(session: Session, team_id: int, **kw: Any) -> dict[str, Any]:
    return describe_plan(session, team_id, plan(session, team_id, **kw))


def _charge(session: Session, team_id: int, cents: int) -> bool:
    if cents <= 0:
        return True
    amount = cents / 100
    return session.exec(update(Team).where(Team.id == team_id, Team.credit_balance >= amount)  # type: ignore[call-overload]
                        .values(credit_balance=Team.credit_balance - amount)
                        .execution_options(synchronize_session=False)).rowcount == 1


def _refund(session: Session, team_id: int, cents: int) -> None:
    if cents > 0:
        session.exec(update(Team).where(Team.id == team_id)  # type: ignore[call-overload]
                     .values(credit_balance=Team.credit_balance + cents / 100)
                     .execution_options(synchronize_session=False))


def _key(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def _run_summary(run: ScmScanRun, queued: int | None = None) -> dict[str, Any]:
    totals = run.totals or {}
    return {"run_id": run.id, "status": run.status, "trigger": run.trigger, "policy_id": run.policy_id,
            "queued": totals.get("scans", 0) if queued is None else queued, "credits": pricing.as_credits(run.credits_c),
            "refunded": pricing.as_credits(run.refunded_c), "skipped_counts": totals.get("skipped_counts", {})}


def create_run(engine: Engine, team_id: int, user_id: int, *, trigger: str, expected_credits: float | None,
               client_request_id: str, now: dt.datetime, repo_ids: Iterable[int] | None = None,
               policy_id: int | None = None, products: Iterable[str] | None = None,
               branch: str | None = None) -> dict[str, Any]:
    if trigger not in PRIORITY:
        raise QueueInputError("Unknown trigger")
    client_request_id = str(client_request_id)[:64]
    with Session(engine) as session:
        existing = session.exec(select(ScmScanRun).where(ScmScanRun.team_id == team_id,
                                                         ScmScanRun.client_request_id == client_request_id)).first()
        if existing is not None:
            return _run_summary(existing)
        p = plan(session, team_id, repo_ids=repo_ids, policy_id=policy_id, products=products, branch=branch)
        est = describe_plan(session, team_id, p)
        if expected_credits is not None and round(float(expected_credits), 2) != est["credits"]:
            raise EstimateChanged(est)
        if not p.items:
            raise NothingToScan(est)
        if not _charge(session, team_id, p.credits_c):
            session.rollback()
            raise InsufficientCredits(est)
        run = ScmScanRun(team_id=team_id, owner_user_id=user_id, trigger=trigger, policy_id=policy_id,
                         client_request_id=client_request_id, status="queued", credits_c=p.credits_c,
                         totals={"scans": len(p.items), "repos": est["repos"], "skipped_counts": est["skipped_counts"],
                                 "per_product": est["per_product"]},
                         created_at=now, last_updated=now)
        session.add(run)
        try:
            session.flush()
        except IntegrityError:  # the same request id raced in: that run stands, this charge is rolled back
            session.rollback()
            with Session(engine) as again:
                return _run_summary(again.exec(select(ScmScanRun).where(
                    ScmScanRun.team_id == team_id, ScmScanRun.client_request_id == client_request_id)).one())
        priority = PRIORITY[trigger]
        rows = [{"team_id": team_id, "run_id": run.id, "repo_id": i.repo_id, "owner_user_id": user_id,
                 "product": i.product, "branch": i.branch, "trigger": trigger, "priority": priority,
                 "status": "queued", "dedupe_key": _key(i.repo_id, i.product, i.branch, f"run:{run.id}"),
                 "credits_c": i.credits_c, "refunded": False, "attempts": 0, "enqueued_at": now}
                for i in p.items]
        for start in range(0, len(rows), 1000):
            session.exec(insert(ScmScanRequest), params=rows[start:start + 1000])  # type: ignore[call-overload]
        session.commit()
        session.refresh(run)
        log("run created", team=team_id, run=run.id, trigger=trigger, scans=len(p.items), credits_c=p.credits_c)
        return _run_summary(run, len(p.items))


def enqueue_push(session: Session, repo: ScmRepository, *, products: Iterable[str], branch: str, commit_sha: str,
                 owner_user_id: int, now: dt.datetime) -> dict[str, Any]:
    """Queue a push's scans in the caller's transaction: one run per (repository, branch, commit), charged once.
    A redelivered or replayed push finds its run and queues nothing; a scan of the same branch that is still waiting
    in the queue covers the new commit too (it clones the branch when it starts)."""
    prods = _check_products(products)
    sha = str(commit_sha or "")[:64]
    client_id = f"push-{_key(repo.id, branch, sha)[:48]}"
    out: dict[str, Any] = {"queued": [], "duplicates": 0, "skipped": [], "insufficient": False, "run_id": None}
    if session.exec(select(ScmScanRun.id).where(ScmScanRun.team_id == repo.team_id,
                                                ScmScanRun.client_request_id == client_id)).first() is not None:
        out["duplicates"] = len(prods)
        return out
    waiting = _active_keys(session, repo.team_id, ("queued",))
    items: list[PlanItem] = []
    for product in prods:
        if (repo.id, product, branch) in waiting:
            out["skipped"].append((repo.id, product, "already_queued"))
        elif product == "sast" and sast_language(repo.language) is None:
            out["skipped"].append((repo.id, product, "sast_language"))
        else:
            items.append(PlanItem(repo.id, product, branch, pricing.price_c(product, repo.size_kb)))
    if not items:
        return out
    cents = sum(i.credits_c for i in items)
    if not _charge(session, repo.team_id, cents):
        out["insufficient"] = True
        return out
    run = ScmScanRun(team_id=repo.team_id, owner_user_id=owner_user_id, trigger="push", client_request_id=client_id,
                     status="queued", credits_c=cents, totals={"scans": len(items), "repos": 1, "commit": sha},
                     created_at=now, last_updated=now)
    session.add(run)
    session.flush()
    for item in items:
        req = ScmScanRequest(team_id=repo.team_id, run_id=run.id, repo_id=repo.id, owner_user_id=owner_user_id,
                             product=item.product, branch=item.branch, trigger="push", priority=PRIORITY["push"],
                             dedupe_key=_key(repo.id, item.product, item.branch, f"push:{sha}"), commit_sha=sha or None,
                             credits_c=item.credits_c, enqueued_at=now)
        session.add(req)
        session.flush()
        out["queued"].append(req.id)
    out["run_id"] = run.id
    return out


def _refund_requests(session: Session, team_id: int, request_ids: list[int], status: str, error: str | None,
                     now: dt.datetime, *, from_status: tuple[str, ...]) -> int:
    """Move requests to a final ``status`` and refund those not refunded yet, once (CAS). Returns the cents."""
    cents = 0
    for rid in request_ids:
        req = session.get(ScmScanRequest, rid)
        if req is None:
            continue
        won = session.exec(update(ScmScanRequest)  # type: ignore[call-overload]
                           .where(ScmScanRequest.id == rid, ScmScanRequest.status.in_(from_status),  # type: ignore[union-attr]
                                  ScmScanRequest.refunded == False)  # noqa: E712
                           .values(status=status, refunded=True, finished_at=now, error=(error or None) and error[:255])
                           .execution_options(synchronize_session=False)).rowcount == 1
        if won:
            cents += req.credits_c
            if req.run_id:
                session.exec(update(ScmScanRun).where(ScmScanRun.id == req.run_id)  # type: ignore[call-overload]
                             .values(refunded_c=ScmScanRun.refunded_c + req.credits_c)
                             .execution_options(synchronize_session=False))
    _refund(session, team_id, cents)
    return cents


def cancel_run(engine: Engine, team_id: int, run_id: int, now: dt.datetime | None = None) -> float:
    """Cancel what is still queued (refunded); dispatched scans run to the end (cancel them on their scan page)."""
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    with Session(engine) as session:
        run = session.exec(select(ScmScanRun).where(ScmScanRun.id == run_id, ScmScanRun.team_id == team_id)).first()
        if run is None:
            raise QueueInputError("Run not found")
        ids = list(session.exec(select(ScmScanRequest.id).where(ScmScanRequest.run_id == run_id,
                                                                ScmScanRequest.status == "queued")).all())
        cents = _refund_requests(session, team_id, ids, "cancelled", "Cancelled before it started", now,
                                 from_status=("queued",))
        if run.status in ("queued", "running"):
            run.status = "cancelled"
            run.last_updated = now
            session.add(run)
        session.commit()
    log("run cancelled", team=team_id, run=run_id, refunded_c=cents)
    return pricing.as_credits(cents)


# ---------------------------------------------------------------------------- dispatch
TokenFor = Callable[[ScmConnection], str]
Launcher = Callable[..., str]  # (engine, scan_type, scan_id, team_id, payload, *, task_id) -> the Celery task id
StatusReader = Callable[[Engine, Scan], None]
TaskState = Callable[[str], str]  # a Celery task id -> its state (PENDING, STARTED, SUCCESS, ...)
Withdraw = Callable[[str], None]  # a Celery task id -> revoked and marked so no worker ever runs it


def celery_task_state(task_id: str) -> str:
    from backend.utilities.celery.celery_connection import get_celery_app

    return str(get_celery_app().AsyncResult(task_id).state).upper()


def celery_withdraw(task_id: str) -> None:
    """The cancel path's own revoke + mark (``cancel_scan.tell_workers``): a worker that picks the task up later,
    even after a restart, sees the mark and never runs it."""
    from backend.utilities.scan.cancel_scan import tell_workers

    tell_workers(task_id)


def default_token_for(connection: ScmConnection) -> str:
    from backend.utilities.scm.providers import provider_for_connection

    provider = provider_for_connection(connection, max_wait_s=30)
    try:
        return provider.clone_token()
    finally:
        provider.close()


def celery_launcher(engine: Engine, scan_type: str, scan_id: int, team_id: int, payload: Any, *,
                    task_id: str | None = None) -> str:
    """Send the scan exactly as /start does (``start_scan_and_update_db``) under the task id the queue chose and
    stored first, and return the Celery task id."""
    from backend.utilities.scan.start_scan import start_scan_and_update_db

    asyncio.run(start_scan_and_update_db(scan_type=scan_type, engine=engine, scan_id=scan_id, team_id=team_id,
                                         start_scan_payload=payload, task_id=task_id))
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None or not scan.task_id:
            raise RuntimeError("the scan has no task id after it was sent")
        return scan.task_id


def celery_status(engine: Engine, scan: Scan) -> None:
    from backend.utilities.celery.celery_connection import get_status_and_update_db

    get_status_and_update_db(scan_id=scan.id, task_id=scan.task_id, table=Scan, engine=engine)


def options_for(session: Session, req: ScmScanRequest, repo: ScmRepository) -> dict[str, Any]:
    run = session.get(ScmScanRun, req.run_id) if req.run_id else None
    policy = session.get(ScmScanPolicy, run.policy_id) if run is not None and run.policy_id else None
    if policy is None:
        winner, _ = winning_policy(filter_input(repo), team_policies(session, repo.team_id), repo.policy_id)
        return dict(winner.options) if winner else {}
    return dict(policy.options or {})


def build_payload(provider: str, product: str, repo: ScmRepository, branch: str, token: str,
                  options: dict[str, Any]):
    """The StartScanPayload /start would receive for this repository: validated by the API's own schema, so the
    repository URL goes through the same host allow-list (github.com, gitlab.com, bitbucket.org or GIT_ALLOWED_HOSTS)."""
    from backend.utilities.db.schemas import StartScanPayload

    context = {"mode": provider, "repo_url": repo.web_url, "PAT": token, "branch": branch}
    if product == "sast":
        section: dict[str, Any] = {"repo_context": context, "app_lang": sast_language(repo.language)}
    elif product == "iac":
        modes = [m for m in (options.get("iac_modes") or DEFAULT_IAC_MODES) if m in DEFAULT_IAC_MODES] or DEFAULT_IAC_MODES
        section = {"repo_context": context, "iac_contexts": [{"mode": m} for m in modes],
                   "environment": options.get("environment") if options.get("environment") in
                   ("production", "staging", "development") else "development"}
    elif product == "cbom":
        section = {"repo_context": context, "scan_binaries": bool(options.get("cbom_scan_binaries")),
                   "include_vendored": bool(options.get("cbom_include_vendored")),
                   "scan_history": bool(options.get("cbom_scan_history"))}
    else:
        section = {"repo_context": context}
    return StartScanPayload.model_validate({product: section})


def _safe_reason(exc: BaseException) -> str:
    """A reason that never echoes input (a ValidationError's text can contain the token)."""
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            first = errors()[0]
            return str(first.get("msg", "invalid input")).replace("Value error, ", "")[:160]
        except Exception:
            return "invalid input"
    detail = getattr(exc, "detail", None)
    if isinstance(detail, str):
        return detail[:160]
    from backend.utilities.scm.providers import ScmError

    if isinstance(exc, ScmError):
        return str(exc)[:160]
    return type(exc).__name__


def _fail_unsent_scan(session: Session, scan_id: int, reason: str) -> None:
    """A Scan that never reached Celery: failed, and its charge taken off it (this module refunds the request)."""
    session.exec(update(Scan).where(Scan.id == scan_id, Scan.task_id == None)  # type: ignore[call-overload]  # noqa: E711
                 .values(scan_status="failure", credit_charged=None, info={"error": reason[:500]})
                 .execution_options(synchronize_session=False))


def _dispatch_one(engine: Engine, request_id: int, now: dt.datetime, launcher: Launcher,
                  token_for: TokenFor, withdraw: Withdraw) -> str:
    with Session(engine) as session:
        won = session.exec(update(ScmScanRequest)  # type: ignore[call-overload]
                           .where(ScmScanRequest.id == request_id, ScmScanRequest.status == "queued")
                           .values(status="dispatching", dispatched_at=now, attempts=ScmScanRequest.attempts + 1)
                           .execution_options(synchronize_session=False)).rowcount == 1
        session.commit()
        if not won:
            return "lost"
        req = session.get(ScmScanRequest, request_id)
        repo = session.get(ScmRepository, req.repo_id)
        connection = session.get(ScmConnection, repo.connection_id) if repo else None
        if repo is None or repo.removed_at is not None:
            _refund_requests(session, req.team_id, [req.id], "skipped", "The repository is no longer visible", now,
                             from_status=("dispatching",))
            session.commit()
            return "skipped"
        if connection is None or not connection.enabled:
            _refund_requests(session, req.team_id, [req.id], "skipped", "The connection is disabled or deleted", now,
                             from_status=("dispatching",))
            session.commit()
            return "skipped"
        options = options_for(session, req, repo)
        try:
            token = token_for(connection)
            payload = build_payload(connection.provider, req.product, repo, req.branch, token, options)
        except Exception as exc:
            reason = f"The repository cannot be scanned: {_safe_reason(exc)}"
            _refund_requests(session, req.team_id, [req.id], "failed", reason, now, from_status=("dispatching",))
            session.commit()
            return "failed"
        from backend.utilities.db.metadata import get_scan_metadata_for_type

        scm_meta = {"repo_id": repo.id, "connection_id": connection.id, "request_id": req.id, "run_id": req.run_id,
                    "trigger": req.trigger, "full_name": repo.full_name, "commit": req.commit_sha}
        metadata = {**get_scan_metadata_for_type(req.product, payload), "scm": scm_meta}
        credits = pricing.as_credits(req.credits_c)
        # what /estimate stores for a scan (credit_estimate.input_digest: the payload minus its token), priced by
        # the SCM-size formula; credit_charged is what the run took for it, so every existing refund path gives
        # back exactly this
        measured = credit_estimate.input_digest(req.product, getattr(payload, req.product).model_dump(mode="json"),
                                                None)
        scan = Scan(team_id=req.team_id, owner_user_id=req.owner_user_id, scan_type=req.product,
                    title=f"{repo.full_name}@{req.branch} ({req.trigger})"[:250], scan_status="pending",
                    credit_consumed=credits, credit_charged=credits,
                    credit_estimate={**measured, "credits": credits, "minimum": pricing.minimum(req.product),
                                     "pricing": pricing.FORMULA, "size_kb": repo.size_kb},
                    scan_metadata=metadata)
        session.add(scan)
        session.flush()
        # the Celery task id is chosen and stored BEFORE anything is sent: a dispatcher that dies right after
        # sending leaves a request whose task can be found (adopted) or withdrawn, never sent a second time
        req.scan_id, req.task_id = scan.id, str(uuid.uuid4())
        session.add(req)
        if req.run_id:
            session.exec(update(ScmScanRun).where(ScmScanRun.id == req.run_id, ScmScanRun.status == "queued")  # type: ignore[call-overload]
                         .values(status="running", last_updated=now).execution_options(synchronize_session=False))
        session.commit()
        scan_id, team_id, product, rid, chosen_id = scan.id, req.team_id, req.product, req.id, req.task_id
    try:
        task_id = launcher(engine, product, scan_id, team_id, payload, task_id=chosen_id)
    except Exception as exc:
        reason = f"The scan could not be sent to a worker ({_safe_reason(exc)})"
        with Session(engine) as session:
            sent_task = session.exec(select(Scan.task_id).where(Scan.id == scan_id)).first()
        if sent_task:
            # the scan reached a worker before the launcher failed: it runs and stays charged (refunding it here
            # would make it free, and its own failure refund would then pay twice)
            log("dispatch raised after the scan was sent", team=team_id, request=rid, scan=scan_id,
                error=type(exc).__name__)
            task_id = sent_task
        else:
            # it may have reached the broker before the launcher failed (e.g. storing its id raised): withdrawn, so
            # it can never run uncharged once this request is refunded
            _withdraw_quietly(withdraw, chosen_id)
            with Session(engine) as session:
                _fail_unsent_scan(session, scan_id, reason)
                _refund_requests(session, team_id, [rid], "failed",
                                 f"The scan could not be sent: {_safe_reason(exc)}", now, from_status=("dispatching",))
                session.commit()
            log("dispatch FAILED", team=team_id, request=rid, scan=scan_id, error=type(exc).__name__)
            return "failed"
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is not None:  # /start's helper rewrites scan_metadata; keep the repository link on it
            scan.scan_metadata = {**(scan.scan_metadata or {}), "scm": scm_meta}
            session.add(scan)
        session.exec(update(ScmScanRequest).where(ScmScanRequest.id == rid)  # type: ignore[call-overload]
                     .values(status="dispatched", task_id=str(task_id)[:64]).execution_options(synchronize_session=False))
        session.commit()
    return "dispatched"


def _withdraw_quietly(withdraw: Withdraw, task_id: str | None) -> None:
    if not task_id:
        return
    try:
        withdraw(task_id)
    except Exception as exc:  # noqa: BLE001  # best effort, like the cancel path: the request is settled anyway
        log("withdraw FAILED", task=task_id, error=type(exc).__name__)


def _recover(session: Session, now: dt.datetime, task_state: TaskState, withdraw: Withdraw) -> int:
    """Requests a dead dispatcher left in ``dispatching``. Exactly once, never free:

    * the scan has its task id: it was sent and stored -> dispatched;
    * the task id the queue chose is known to Celery (a worker started or finished it) -> adopted: dispatched under
      that id, still charged, and the poll reads its real result;
    * otherwise the chosen task is withdrawn (revoked and marked, so a copy still in the broker never runs) and the
      request is re-queued under a new id, or failed and refunded after MAX_ATTEMPTS."""
    stuck = session.exec(select(ScmScanRequest).where(ScmScanRequest.status == "dispatching",
                                                      ScmScanRequest.dispatched_at < now - DISPATCH_LEASE)).all()
    for req in stuck:
        scan = session.get(Scan, req.scan_id) if req.scan_id else None
        if scan is not None and scan.task_id:
            req.status, req.task_id = "dispatched", scan.task_id
            session.add(req)
            continue
        if scan is not None and req.task_id:
            try:
                state = task_state(req.task_id)
            except Exception as exc:  # noqa: BLE001  # the broker or result backend is down: decide on a later tick
                log("recover deferred", request=req.id, error=type(exc).__name__)
                continue
            if state != "PENDING":  # a worker has it: the scan was sent before the dispatcher died
                won = session.exec(update(Scan).where(Scan.id == scan.id, Scan.task_id == None)  # type: ignore[call-overload]
                                   .values(task_id=req.task_id).execution_options(synchronize_session=False)).rowcount
                if won:
                    req.status = "dispatched"
                    session.add(req)
                    log("recover adopted a sent scan", request=req.id, scan=scan.id, state=state)
                    continue
            _withdraw_quietly(withdraw, req.task_id)
        if scan is not None:
            _fail_unsent_scan(session, scan.id, "The scan was not sent (the dispatcher stopped)")
        if req.attempts >= MAX_ATTEMPTS:
            _refund_requests(session, req.team_id, [req.id], "failed", "Could not be dispatched after "
                             f"{MAX_ATTEMPTS} attempts", now, from_status=("dispatching",))
        else:
            req.status, req.scan_id, req.task_id = "queued", None, None
            session.add(req)
    return len(stuck)


class _PgLock:
    """``pg_try_advisory_lock`` on a dedicated connection for the tick (no-op on SQLite)."""

    def __init__(self, engine: Engine):
        self.engine, self.conn, self.got = engine, None, True

    def __enter__(self) -> bool:
        if self.engine.dialect.name == "postgresql":
            self.conn = self.engine.connect()
            self.got = bool(self.conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": LOCK_KEY}).scalar())
        return self.got

    def __exit__(self, *_exc: Any) -> None:
        if self.conn is not None:
            try:
                if self.got:
                    self.conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK_KEY})
            finally:
                self.conn.close()


def _task_ops(launcher: Launcher | None, task_state: TaskState | None,
              withdraw: Withdraw | None) -> tuple[Launcher, TaskState, Withdraw]:
    """Celery by default; a stand-in launcher (tests, benches) brings its own ``task_state`` / ``withdraw`` or none."""
    if launcher is None:
        return celery_launcher, task_state or celery_task_state, withdraw or celery_withdraw
    return (launcher, task_state or getattr(launcher, "task_state", lambda _t: "PENDING"),
            withdraw or getattr(launcher, "withdraw", lambda _t: None))


def dispatch_tick(engine: Engine, now: dt.datetime, *, launcher: Launcher | None = None,
                  token_for: TokenFor | None = None, max_inflight: int | None = None,
                  team_max: int | None = None, task_state: TaskState | None = None,
                  withdraw: Withdraw | None = None) -> list[int]:
    """Fill the free slots fairly. Returns the ids of the requests sent this tick."""
    launcher, task_state, withdraw = _task_ops(launcher, task_state, withdraw)
    token_for = token_for or default_token_for
    cap = max_inflight or env_max_inflight()
    per_team = env_team_max_inflight(cap) if team_max is None else team_max
    sent: list[int] = []
    with _PgLock(engine) as locked:
        if not locked:
            return sent
        with Session(engine) as session:
            _recover(session, now, task_state, withdraw)
            session.commit()
            inflight = Counter({t: n for t, n in session.exec(
                select(ScmScanRequest.team_id, func.count()).where(
                    ScmScanRequest.status.in_(("dispatching", "dispatched")))  # type: ignore[union-attr]
                .group_by(ScmScanRequest.team_id)).all()})
            free = cap - sum(inflight.values())
            if free <= 0:
                return sent
            waiting = list(session.exec(select(ScmScanRequest.team_id).where(
                ScmScanRequest.status == "queued").group_by(ScmScanRequest.team_id)).all())
            last_served = {t: s for t, s in session.exec(
                select(ScmScanRequest.team_id, func.max(ScmScanRequest.dispatched_at))
                .where(ScmScanRequest.team_id.in_(waiting))  # type: ignore[union-attr]
                .group_by(ScmScanRequest.team_id)).all()} if waiting else {}
        backlog: dict[int, list[int]] = {}
        exhausted: set[int] = set()
        floor = dt.datetime.min
        tick_order = 0
        while free > 0:
            # water-filling is the fairness; the optional per-team cap (0: none) only bounds one team's parallelism
            eligible = [t for t in waiting if t not in exhausted and (per_team <= 0 or inflight[t] < per_team)]
            if not eligible:
                break
            team = min(eligible, key=lambda t: (inflight[t], last_served.get(t) or floor, t))
            if not backlog.get(team):
                with Session(engine) as session:
                    backlog[team] = list(session.exec(
                        select(ScmScanRequest.id).where(ScmScanRequest.team_id == team,
                                                        ScmScanRequest.status == "queued")
                        .order_by(ScmScanRequest.priority, ScmScanRequest.id).limit(max(per_team, free, 1) * 2)).all())
                if not backlog[team]:
                    exhausted.add(team)
                    continue
            request_id = backlog[team].pop(0)
            outcome = _dispatch_one(engine, request_id, now, launcher, token_for, withdraw)
            if outcome == "dispatched":
                sent.append(request_id)
                inflight[team] += 1
                free -= 1
                tick_order += 1
                last_served[team] = now + dt.timedelta(microseconds=tick_order)
    if sent:
        log("dispatched", count=len(sent), teams=len({t for t in inflight}))
    return sent


# ---------------------------------------------------------------------------- completion
def _close_runs(session: Session, run_ids: set[int], now: dt.datetime) -> None:
    for run_id in run_ids:
        open_count = session.exec(select(func.count()).select_from(ScmScanRequest).where(
            ScmScanRequest.run_id == run_id, ScmScanRequest.status.in_(ACTIVE))).one()  # type: ignore[union-attr]
        if open_count:
            continue
        run = session.get(ScmScanRun, run_id)
        if run is not None and run.status in ("queued", "running"):
            run.status, run.finished_at, run.last_updated = "done", now, now
            session.add(run)


def scan_path_refund(scan: Scan) -> float:
    """What the scan's own path gave back when it ended: a worker failure refunds ``credit_charged``
    (``get_status_and_update_db``); a cancel on the scan page refunds it and records ``info.refunded_credits``
    (``cancel_scan``). A scan that never reached a worker has no ``credit_charged`` left (``_fail_unsent_scan``)."""
    if scan.scan_status == "cancelled":
        info = scan.info if isinstance(scan.info, dict) else {}
        return round(float(info.get("refunded_credits") or 0), 2)
    if scan.scan_status == "failure" and scan.credit_charged:
        return round(float(scan.credit_charged), 2)
    return 0.0


def _record_scan_path_refund(session: Session, req: ScmScanRequest, scan: Scan) -> None:
    """Book on the request and its run a refund the scan path already paid (no credit moves here). Compare-and-set
    on ``refunded``, so it is booked once and this module can never refund the same request afterwards."""
    cents = min(round(scan_path_refund(scan) * 100), int(req.credits_c or 0))
    if cents <= 0 or req.refunded:
        return
    won = session.exec(update(ScmScanRequest)  # type: ignore[call-overload]
                       .where(ScmScanRequest.id == req.id, ScmScanRequest.refunded == False)
                       .values(refunded=True).execution_options(synchronize_session=False)).rowcount == 1
    if not won:
        return
    req.refunded = True
    if req.run_id:
        session.exec(update(ScmScanRun).where(ScmScanRun.id == req.run_id)  # type: ignore[call-overload]
                     .values(refunded_c=ScmScanRun.refunded_c + cents).execution_options(synchronize_session=False))


Expirer = Callable[[Engine, Scan, str], bool]  # (engine, scan, reason) -> True when this call stopped and refunded it


def expire_lost_scan(engine: Engine, scan: Scan, reason: str) -> bool:
    """Stop a scan no worker finished in time through the cancel path a customer's Cancel uses (``cancel_scan``): it
    reads the worker's real state first (a scan that finished meanwhile is kept, never refunded), then in one
    compare-and-set marks it cancelled and refunds ``credit_charged`` once, and withdraws the task so a worker that
    picks it up later never runs it. The reason is kept on the scan."""
    from backend.utilities.scan.cancel_scan import CancelRefused, cancel_scan

    try:
        cancel_scan(engine, scan_id=scan.id, team_id=scan.team_id, scan_type=scan.scan_type,
                    user_id=None)  # type: ignore[arg-type]  # the queue, not a person
    except CancelRefused:
        return False
    with Session(engine) as session:
        row = session.get(Scan, scan.id)
        if row is not None and isinstance(row.info, dict):
            row.info = {**row.info, "timed_out": True, "error": reason[:500]}
            session.add(row)
            session.commit()
    return True


def _lost_reason(req: ScmScanRequest, scan: Scan, now: dt.datetime) -> str | None:
    """Why a dispatched scan counts as lost (its worker died, the task was dropped), or None while it may still end."""
    if req.dispatched_at is None:
        return None
    age = now - req.dispatched_at
    start, run = env_start_timeout(), env_run_timeout()
    if (scan.scan_status or "pending") in ("pending", "received") and age > start:
        return (f"No scan worker picked this scan up within {int(start.total_seconds() // 60)} minutes; "
                "it was stopped and its credits refunded")
    if age > run:
        return (f"The scan did not finish within {int(run.total_seconds() // 60)} minutes; "
                "it was stopped and its credits refunded")
    return None


def poll_tick(engine: Engine, now: dt.datetime, *, status_reader: StatusReader | None = None,
              limit: int = 500, expirer: Expirer | None = None) -> dict[str, int]:
    """Close finished scans and free their slots. A scan still pending past ``REPO_SCAN_START_TIMEOUT_MIN`` or
    unfinished past ``REPO_SCAN_RUN_TIMEOUT_MIN`` (its worker died, the task was lost) is reconciled with the worker
    first and then stopped and refunded (``expire_lost_scan``), so a lost task never holds a slot for ever."""
    if status_reader is None:
        status_reader, expirer = celery_status, expirer or expire_lost_scan
    else:
        expirer = expirer or getattr(status_reader, "expire", None)
    counts: Counter = Counter()
    with Session(engine) as session:
        ids = list(session.exec(select(ScmScanRequest.id).where(ScmScanRequest.status == "dispatched")
                                .order_by(ScmScanRequest.dispatched_at).limit(limit)).all())
    runs: set[int] = set()
    for rid in ids:
        with Session(engine) as session:
            req = session.get(ScmScanRequest, rid)
            scan = session.get(Scan, req.scan_id) if req and req.scan_id else None
            if req is None:
                continue
            if scan is None:
                req.status, req.finished_at, req.error = "failed", now, "The scan was deleted"
                session.add(req)
                session.commit()
                counts["failed"] += 1
                continue
            if scan.scan_status not in ("success", "failure", "cancelled") and scan.task_id:
                try:
                    status_reader(engine, scan)
                except Exception as exc:  # the broker or result backend is down: try again next tick
                    log("poll FAILED", request=rid, scan=scan.id, error=type(exc).__name__)
                    continue
                session.expire_all()
                scan = session.get(Scan, req.scan_id)
            final = {"success": "done", "failure": "failed", "cancelled": "cancelled"}.get(scan.scan_status or "")
            lost = None
            if final is None:
                lost = _lost_reason(req, scan, now) if expirer is not None else None
                if lost is None:
                    continue
                stopped = expirer(engine, scan, lost)
                session.expire_all()
                scan = session.get(Scan, req.scan_id)
                final = {"success": "done", "failure": "failed", "cancelled": "cancelled"}.get(scan.scan_status or "")
                if final is None:
                    continue
                if stopped:
                    final = "failed"
                    log("lost scan stopped", team=req.team_id, request=rid, scan=scan.id)
                else:
                    lost = None  # it ended on its own meanwhile: closed with its real outcome
            req.status, req.finished_at = final, now
            _record_scan_path_refund(session, req, scan)
            if lost is not None:
                req.error = lost[:255]
            elif final == "failed":
                # the worker's sentence, with the user info of any URL in it dropped (a clone URL carries the token)
                req.error = redact_urls(str((scan.info or {}).get("error") or "The scan failed"))[:255] \
                    if isinstance(scan.info, dict) else "The scan failed"
            repo = session.get(ScmRepository, req.repo_id)
            summary: dict[str, Any] = {"scan_id": scan.id, "status": scan.scan_status, "at": now.isoformat() + "Z",
                                       "branch": req.branch}
            if final == "done" and repo is not None:
                summary["findings"] = rollup.fold_scan(session, team_id=req.team_id, repo_id=repo.id,
                                                       product=req.product, scan_id=scan.id,
                                                       scan_data=scan.scan_data, now=now)
            if repo is not None:
                repo.last_scan_summary = {**(repo.last_scan_summary or {}), req.product: summary}
                repo.last_scan_at = now
                session.add(repo)
            session.add(req)
            if req.run_id:
                runs.add(req.run_id)
            session.commit()
            counts[final] += 1
    if runs:
        with Session(engine) as session:
            _close_runs(session, runs, now)
            session.commit()
    return dict(counts)


def tick(engine: Engine, now: dt.datetime, **kw: Any) -> dict[str, Any]:
    polled = poll_tick(engine, now, status_reader=kw.pop("status_reader", None))
    sent = dispatch_tick(engine, now, **kw)
    return {"closed": polled, "dispatched": len(sent)}


def queue_stats(session: Session, team_id: int) -> dict[str, Any]:
    rows = session.exec(select(ScmScanRequest.status, ScmScanRequest.trigger, func.count())
                        .where(ScmScanRequest.team_id == team_id)
                        .group_by(ScmScanRequest.status, ScmScanRequest.trigger)).all()
    by_status: Counter = Counter()
    waiting_by_trigger: Counter = Counter()
    for status, trig, n in rows:
        by_status[status] += n
        if status == "queued":
            waiting_by_trigger[trig] += n
    teams_waiting = session.exec(select(func.count(func.distinct(ScmScanRequest.team_id)))
                                 .where(ScmScanRequest.status == "queued")).one()
    return {"by_status": dict(by_status), "queued_by_trigger": dict(waiting_by_trigger),
            "max_inflight": env_max_inflight(), "team_max_inflight": env_team_max_inflight(),
            "teams_waiting": int(teams_waiting or 0)}


__all__ = ["ACTIVE", "EstimateChanged", "FINAL", "InsufficientCredits", "NothingToScan", "PRIORITY", "Plan",
           "QueueInputError", "build_payload", "cancel_run", "celery_launcher", "celery_status", "create_run",
           "dispatch_tick", "enqueue_push", "estimate", "plan", "poll_tick", "queue_stats", "sast_language", "tick"]
