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

The queue (``scmscanrequest``) and the dispatcher
* Priority: push (0) > manual (1) > schedule (2), then age.
* Caps: at most ``REPO_SCAN_MAX_INFLIGHT`` (default 8) repository scans in Celery at once, and at most
  ``REPO_SCAN_TEAM_MAX_INFLIGHT`` (default 4) per team, so bulk runs never fill ``scan_worker_queue`` ahead of the
  scans people start by hand.
* Fairness: free slots are filled by water-filling. Each slot goes to the team with the FEWEST scans in flight (ties:
  the team served least recently, then the lower team id) that is under its cap. A team with 1,000 queued repositories
  gets the same share as a team with 3 while both are waiting; the small team is never behind the big one's backlog.
* One decider at a time: on PostgreSQL the tick holds an advisory lock (so two dispatchers cannot both see a free
  slot), and every claim is a compare-and-set (``queued -> dispatching``), so no request is ever sent twice.
* A dispatcher that died mid-claim leaves ``dispatching`` rows; after ``DISPATCH_LEASE`` they are re-queued (or
  failed and refunded after ``MAX_ATTEMPTS``).

Completion: ``poll_tick`` reads each in-flight scan through ``get_status_and_update_db`` (results, Mongo findings and
the failure refund are unchanged), closes the request, records the repository's last scan and folds the roll-up.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import os
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, insert, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.new_models import Scan, Team
from backend.utilities.scm import pricing, rollup
from backend.utilities.scm.common import log
from backend.utilities.scm.filters import RepoFilters
from backend.utilities.scm.inventory import filter_input
from backend.utilities.scm.models import ScmConnection, ScmRepository, ScmScanPolicy, ScmScanRequest, ScmScanRun
from backend.utilities.scm.policies import PolicyView, team_policies, winning_policy

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


def env_team_max_inflight() -> int:
    return max(1, int(os.environ.get("REPO_SCAN_TEAM_MAX_INFLIGHT", "4") or 4))


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
Launcher = Callable[[Engine, str, int, int, Any], str]
StatusReader = Callable[[Engine, Scan], None]


def default_token_for(connection: ScmConnection) -> str:
    from backend.utilities.scm.providers import provider_for_connection

    provider = provider_for_connection(connection, max_wait_s=30)
    try:
        return provider.clone_token()
    finally:
        provider.close()


def celery_launcher(engine: Engine, scan_type: str, scan_id: int, team_id: int, payload: Any) -> str:
    """Send the scan exactly as /start does (``start_scan_and_update_db``) and return its Celery task id."""
    from backend.utilities.scan.start_scan import start_scan_and_update_db

    asyncio.run(start_scan_and_update_db(scan_type=scan_type, engine=engine, scan_id=scan_id, team_id=team_id,
                                         start_scan_payload=payload))
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
                  token_for: TokenFor) -> str:
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
        scan = Scan(team_id=req.team_id, owner_user_id=req.owner_user_id, scan_type=req.product,
                    title=f"{repo.full_name}@{req.branch} ({req.trigger})"[:250], scan_status="pending",
                    credit_consumed=credits, credit_charged=credits,
                    credit_estimate={"formula": pricing.FORMULA, "credits": credits, "size_kb": repo.size_kb},
                    scan_metadata=metadata)
        session.add(scan)
        session.flush()
        req.scan_id = scan.id
        session.add(req)
        if req.run_id:
            session.exec(update(ScmScanRun).where(ScmScanRun.id == req.run_id, ScmScanRun.status == "queued")  # type: ignore[call-overload]
                         .values(status="running", last_updated=now).execution_options(synchronize_session=False))
        session.commit()
        scan_id, team_id, product, rid = scan.id, req.team_id, req.product, req.id
    try:
        task_id = launcher(engine, product, scan_id, team_id, payload)
    except Exception as exc:
        reason = f"The scan could not be sent to a worker ({_safe_reason(exc)})"
        with Session(engine) as session:
            _fail_unsent_scan(session, scan_id, reason)
            _refund_requests(session, team_id, [rid], "failed", f"The scan could not be sent: {_safe_reason(exc)}",
                             now, from_status=("dispatching",))
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


def _recover(session: Session, now: dt.datetime) -> int:
    """Requests a dead dispatcher left in ``dispatching``: re-queued, or failed and refunded after MAX_ATTEMPTS."""
    stuck = session.exec(select(ScmScanRequest).where(ScmScanRequest.status == "dispatching",
                                                      ScmScanRequest.dispatched_at < now - DISPATCH_LEASE)).all()
    for req in stuck:
        scan = session.get(Scan, req.scan_id) if req.scan_id else None
        if scan is not None and scan.task_id:
            req.status, req.task_id = "dispatched", scan.task_id
            session.add(req)
            continue
        if scan is not None:
            _fail_unsent_scan(session, scan.id, "The scan was not sent (the dispatcher stopped)")
        if req.attempts >= MAX_ATTEMPTS:
            _refund_requests(session, req.team_id, [req.id], "failed", "Could not be dispatched after "
                             f"{MAX_ATTEMPTS} attempts", now, from_status=("dispatching",))
        else:
            req.status, req.scan_id = "queued", None
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


def dispatch_tick(engine: Engine, now: dt.datetime, *, launcher: Launcher | None = None,
                  token_for: TokenFor | None = None, max_inflight: int | None = None,
                  team_max: int | None = None) -> list[int]:
    """Fill the free slots fairly. Returns the ids of the requests sent this tick."""
    launcher = launcher or celery_launcher
    token_for = token_for or default_token_for
    cap = max_inflight or env_max_inflight()
    per_team = team_max or env_team_max_inflight()
    sent: list[int] = []
    with _PgLock(engine) as locked:
        if not locked:
            return sent
        with Session(engine) as session:
            _recover(session, now)
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
            eligible = [t for t in waiting if t not in exhausted and inflight[t] < per_team]
            if not eligible:
                break
            team = min(eligible, key=lambda t: (inflight[t], last_served.get(t) or floor, t))
            if not backlog.get(team):
                with Session(engine) as session:
                    backlog[team] = list(session.exec(
                        select(ScmScanRequest.id).where(ScmScanRequest.team_id == team,
                                                        ScmScanRequest.status == "queued")
                        .order_by(ScmScanRequest.priority, ScmScanRequest.id).limit(max(per_team, free) * 2)).all())
                if not backlog[team]:
                    exhausted.add(team)
                    continue
            request_id = backlog[team].pop(0)
            outcome = _dispatch_one(engine, request_id, now, launcher, token_for)
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


def poll_tick(engine: Engine, now: dt.datetime, *, status_reader: StatusReader | None = None,
              limit: int = 500) -> dict[str, int]:
    status_reader = status_reader or celery_status
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
            if final is None:
                continue
            req.status, req.finished_at = final, now
            if final == "failed":
                req.error = str((scan.info or {}).get("error") or "The scan failed")[:255] \
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
