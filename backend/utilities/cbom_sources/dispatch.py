"""Server-paced job dispatch for scan nodes (F1.1, devil's-advocate review D2).

Every heartbeat, claim and result answer carries ``claim: n``, the number of claims the node may make now.  The
permits come from ONE token bucket per worker process (``CBOM_DISPATCH_PER_WORKER_S`` a second, a burst of one second
of rate), so a 10,000-node fleet told about a 10,000-job run cannot turn every node into a closed-loop requester: the
claims a deployment serves are bounded by rate x workers, whatever the fleet size.

* ``grant(node, team, want)``: takes up to ``want`` permits for the node (the answer's ``n``).  The answer also carries
  ``claim_ticket`` (``ticket``): an HMAC over (node, n, the jobs the node held, expiry) with a key every worker and
  replica derives from the same deployment secret.  The node sends it back with its claims, so ANY worker honours a
  claim another worker already paid for.  Nothing is remembered in the process (grant locality, EC2 E2a run 3:
  12,045 grants given, 3,452 taken, 5,632 claims denied because two of three landed on a worker that did not hold the
  grant).  A ticket is good for ``GRANT_TTL_S`` and for ``n`` claims: the jobs this node claimed after the ticket
  was issued (one indexed count, ``ix_cbomcollectionjob_node_claimed_at``) are the claims already used, so replaying
  it buys nothing.  The node also sends its ticket with heartbeats and results, so an answer tops a grant up instead
  of paying for it twice (the claims still unused count towards the new ``n``).
* ``admit(node, team, granted)``: ``/jobs/claim`` asks before ``claim_next`` runs, for every node version (a 1.0 node
  polls every 5 s and sends no ticket): a valid ticket (``granted``), else a fresh permit, else no (the claim answers
  204 without touching the queue).  ``give_back`` returns a fresh permit when the claim then found nothing, so a 204
  costs none.
* Fairness (max-min, per worker): while the bucket holds less than ``RESERVE`` of its burst, a permit goes only to a
  team whose use in the last second is below rate / active teams.  A team with one job waiting therefore gets it
  within a heartbeat even while another team's 10,000-node run drains the bucket.

* Headroom: the rate is a ceiling, not a promise.  While this worker's node requests wait for a thread (``busy``), it
  gives no NEW permits (grants already given stay valid), so the claim rate follows what the worker actually serves.
  EC2 round 7: at 25/s per worker the bucket granted 75 claims/s while the box served about 24 jobs/s of the 5.2
  mix; the surplus queued in front of the node threads until clients timed out (E2a, E4a).

No database, no queue, no per-node memory: a lock around a few floats, and an HMAC per answer that grants.  Load
shaping only: a node that claims without a permit simply gets
204, and every correctness rule (leases, guards, SKIP LOCKED) is unchanged.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import deque
from typing import Callable

from backend.utilities.cbom_sources import limits as LIM
from backend.utilities.cbom_sources.common import log

GRANT_TTL_S = 15.0
RESERVE = 0.25  # of the burst
ACTIVE_TEAM_S = 2.0


class Dispatcher:
    def __init__(self, rate: float, burst: float | None = None, clock: Callable[[], float] = time.monotonic,
                 start_full: bool = True, busy: Callable[[], bool] | None = None) -> None:
        self.rate = float(rate)
        self.busy = busy
        self.burst = float(burst if burst is not None else max(1.0, rate))
        self.clock = clock
        self.lock = threading.Lock()
        self.tokens = self.burst if start_full else 0.0
        self.last = clock()
        self.team_use: dict[int, deque] = {}
        self.team_seen: dict[int, float] = {}
        self.counters = {"dispatch_granted": 0, "dispatch_taken": 0, "dispatch_returned": 0,
                         "dispatch_denied": 0, "dispatch_204_after_grant": 0, "dispatch_held_busy": 0}

    # -- bucket
    def _refill(self, now: float) -> None:
        if now > self.last:
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
            self.last = now

    def level(self) -> float:
        with self.lock:
            self._refill(self.clock())
            return self.tokens

    def _active(self, now: float) -> int:
        for team, seen in list(self.team_seen.items()):
            if now - seen > ACTIVE_TEAM_S:
                del self.team_seen[team]
                self.team_use.pop(team, None)
        return max(1, len(self.team_seen))

    def _used(self, team: int, now: float) -> int:
        q = self.team_use.get(team)
        if not q:
            return 0
        while q and now - q[0] > 1.0:
            q.popleft()
        return len(q)

    def _saturated(self) -> bool:
        if self.busy is not None and self.busy():
            self.counters["dispatch_held_busy"] += 1
            return True
        return False

    def _permit(self, team: int, now: float) -> bool:
        """Take one permit for ``team`` if the bucket and the team's fair share allow it (lock held)."""
        if self.tokens < 1.0:
            return False
        if self.tokens < RESERVE * self.burst + 1.0:
            share = self.rate / self._active(now)
            if self._used(team, now) >= share:
                return False
        self.tokens -= 1.0
        self.team_use.setdefault(team, deque()).append(now)
        return True

    # -- API
    def grant(self, node_id: int, team_id: int, want: int) -> int:
        """Permits for up to ``want`` claims by this node now (the answer's ``claim``; ``ticket`` carries them)."""
        if want <= 0:
            return 0
        with self.lock:
            now = self.clock()
            self._refill(now)
            self.team_seen[team_id] = now
            n = 0
            if not self._saturated():
                while n < want and self._permit(team_id, now):
                    n += 1
            self.counters["dispatch_granted"] += n
            return n

    def admit(self, node_id: int, team_id: int, granted: bool = False) -> str | None:
        """May this node claim now?  'grant' (a valid ticket: paid by an earlier answer, on any worker), 'permit' (paid
        now) or None (answer 204)."""
        with self.lock:
            now = self.clock()
            self._refill(now)
            self.team_seen[team_id] = now
            if granted:
                self.counters["dispatch_taken"] += 1
                return "grant"
            if not self._saturated() and self._permit(team_id, now):
                self.counters["dispatch_taken"] += 1
                return "permit"
            self.counters["dispatch_denied"] += 1
            return None

    def give_back(self, how: str | None = "permit") -> None:
        """An admitted claim found nothing to run.  A fresh permit goes back to this worker's bucket; a ticket's permit
        was taken from the bucket of the worker that granted it, so it is not credited here (never more than paid)."""
        with self.lock:
            self._refill(self.clock())
            if how == "permit":
                self.tokens = min(self.burst, self.tokens + 1.0)
                self.counters["dispatch_returned"] += 1
            else:
                self.counters["dispatch_204_after_grant"] += 1

    def take_counters(self) -> dict[str, int]:
        with self.lock:
            out = dict(self.counters)
            out["teams_active"] = len(self.team_seen)
            for key in self.counters:
                self.counters[key] = 0
        return out


# ----------------------------------------------------------------------------- claim tickets (stateless grants)
_TICKET = re.compile(r"^g1\.([0-9]{1,10})\.([0-9])\.([0-9]{16})\.([A-Za-z0-9_-]{22})$")
_KEY: list[bytes | None] = [None]
TICKET_ENV = "CBOM_DISPATCH_KEY"
_EPOCH = _dt.datetime(1970, 1, 1)


def _key() -> bytes:
    """The ticket key every worker and replica of a deployment shares: ``CBOM_DISPATCH_KEY`` if set, else derived from
    ``JWT_SECRET_KEY`` (required by the backend).  Neither set (a bare test process): a random per-process key, so a
    ticket is honoured only by the worker that gave it (the old behaviour), and the claim falls back to a permit."""
    if _KEY[0] is None:
        base = os.environ.get(TICKET_ENV) or os.environ.get("JWT_SECRET_KEY") or ""
        if not base:
            log("job dispatch: no shared key, claim tickets are worker-local", level="warn")
            base = secrets.token_hex(32)
        _KEY[0] = hashlib.sha256(b"zs-cbom-claim-ticket-v1|" + base.encode("utf-8")).digest()
    return _KEY[0]  # type: ignore[return-value]


def _mac(body: str) -> str:
    raw = hmac.new(_key(), body.encode("ascii"), hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _us(moment: _dt.datetime) -> int:
    return int((moment - _EPOCH).total_seconds() * 1_000_000)


def ticket(node_id: int, n: int, issued: _dt.datetime) -> str | None:
    """The claim ticket for a grant of ``n`` claims to a node, issued at ``issued`` (the request's ``now``, UTC naive,
    the clock ``claimed_at`` is written with).  None when n is 0."""
    if n <= 0:
        return None
    body = f"g1.{int(node_id)}.{min(int(n), 9)}.{_us(issued):016d}"
    return f"{body}.{_mac(body)}"


def read_ticket(value: object, node_id: int, now: _dt.datetime) -> tuple[int, _dt.datetime] | None:
    """(n, issued) of a valid, unexpired ticket given to this node, else None.  Constant-time MAC check.  How many of
    its n claims are used is the caller's one indexed count (jobs this node claimed after ``issued``)."""
    if not isinstance(value, str) or len(value) > 80:
        return None
    m = _TICKET.match(value)
    if not m or int(m.group(1)) != int(node_id):
        return None
    if not hmac.compare_digest(_mac(value[:value.rindex(".")]), m.group(4)):
        return None
    issued = _EPOCH + _dt.timedelta(microseconds=int(m.group(3)))
    if not issued - _dt.timedelta(seconds=5) <= now <= issued + _dt.timedelta(seconds=GRANT_TTL_S):
        return None
    return int(m.group(2)), issued


_INSTANCE: list[Dispatcher | None] = [None]
_INSTANCE_LOCK = threading.Lock()


def get() -> Dispatcher:
    if _INSTANCE[0] is None:
        with _INSTANCE_LOCK:
            if _INSTANCE[0] is None:
                rate = LIM.dispatch_per_worker()
                from backend.utilities.cbom_sources import node_obs as OBS

                _INSTANCE[0] = Dispatcher(rate, busy=OBS.threads_queued)
                import os

                workers = os.environ.get("BACKEND_WORKERS") or os.environ.get("WEB_CONCURRENCY")
                log("job dispatch", per_worker_per_s=rate, burst=rate, workers=workers,
                    deployment_per_s=(rate * int(workers)) if (workers or "").isdigit() else None)
    return _INSTANCE[0]  # type: ignore[return-value]


def reset(dispatcher: Dispatcher | None = None) -> None:
    """Replace (tests) or forget (re-read the rate and the ticket key at next use) the worker's dispatcher."""
    with _INSTANCE_LOCK:
        _INSTANCE[0] = dispatcher
        _KEY[0] = None
