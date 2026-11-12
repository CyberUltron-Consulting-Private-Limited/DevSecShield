"""Server-paced job dispatch for scan nodes (F1.1, devil's-advocate review D2).

Every heartbeat, claim and result answer carries ``claim: n``, the number of claims the node may make now.  The
permits come from ONE token bucket per worker process (``CBOM_DISPATCH_PER_WORKER_S`` a second, a burst of one second
of rate), so a 10,000-node fleet told about a 10,000-job run cannot turn every node into a closed-loop requester: the
claims a deployment serves are bounded by rate x workers, whatever the fleet size.

* ``grant(node, team, want)``: takes up to ``want`` permits for the node (the answer's ``n``) and remembers them for
  ``GRANT_TTL_S``, so the claims that follow on this worker are already paid for.
* ``admit(node, team)``: ``/jobs/claim`` asks before ``claim_next`` runs, for every node version (a 1.0 node polls
  every 5 s and ignores grants): a remembered grant, else a fresh permit, else no (the claim answers 204 without
  touching the queue).  ``give_back`` returns the permit when the claim then found nothing, so a 204 costs none.
* Fairness (max-min, per worker): while the bucket holds less than ``RESERVE`` of its burst, a permit goes only to a
  team whose use in the last second is below rate / active teams.  A team with one job waiting therefore gets it
  within a heartbeat even while another team's 10,000-node run drains the bucket.

No database, no queue, a lock around a few floats.  Load shaping only: a node that claims without a permit simply gets
204, and every correctness rule (leases, guards, SKIP LOCKED) is unchanged.
"""
from __future__ import annotations

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
                 start_full: bool = True) -> None:
        self.rate = float(rate)
        self.burst = float(burst if burst is not None else max(1.0, rate))
        self.clock = clock
        self.lock = threading.Lock()
        self.tokens = self.burst if start_full else 0.0
        self.last = clock()
        self.grants: dict[int, tuple[int, float]] = {}
        self.team_use: dict[int, deque] = {}
        self.team_seen: dict[int, float] = {}
        self.counters = {"dispatch_granted": 0, "dispatch_taken": 0, "dispatch_returned": 0,
                         "dispatch_denied": 0, "dispatch_204_after_grant": 0}

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
        """Permits for up to ``want`` claims by this node now (the answer's ``claim``)."""
        if want <= 0:
            return 0
        with self.lock:
            now = self.clock()
            self._refill(now)
            self.team_seen[team_id] = now
            held, expires = self.grants.get(node_id, (0, 0.0))
            held = held if expires > now else 0
            n = min(held, want)
            while n < want and self._permit(team_id, now):
                n += 1
            if n > held:
                self.counters["dispatch_granted"] += n - held
            if n:
                self.grants[node_id] = (n, now + GRANT_TTL_S)
            else:
                self.grants.pop(node_id, None)
            return n

    def admit(self, node_id: int, team_id: int) -> str | None:
        """May this node claim now?  'grant' (paid by an earlier answer), 'permit' (paid now) or None (answer 204)."""
        with self.lock:
            now = self.clock()
            self._refill(now)
            self.team_seen[team_id] = now
            held, expires = self.grants.get(node_id, (0, 0.0))
            if held > 0 and expires > now:
                if held > 1:
                    self.grants[node_id] = (held - 1, expires)
                else:
                    self.grants.pop(node_id, None)
                self.counters["dispatch_taken"] += 1
                return "grant"
            self.grants.pop(node_id, None)
            if self._permit(team_id, now):
                self.counters["dispatch_taken"] += 1
                return "permit"
            self.counters["dispatch_denied"] += 1
            return None

    def give_back(self) -> None:
        """An admitted claim found nothing to run: its permit goes back to the bucket."""
        with self.lock:
            self._refill(self.clock())
            self.tokens = min(self.burst, self.tokens + 1.0)
            self.counters["dispatch_returned"] += 1
            self.counters["dispatch_204_after_grant"] += 1

    def forget(self, node_id: int) -> None:
        with self.lock:
            self.grants.pop(node_id, None)

    def take_counters(self) -> dict[str, int]:
        with self.lock:
            out = dict(self.counters)
            out["teams_active"] = len(self.team_seen)
            for key in self.counters:
                self.counters[key] = 0
        return out


_INSTANCE: list[Dispatcher | None] = [None]
_INSTANCE_LOCK = threading.Lock()


def get() -> Dispatcher:
    if _INSTANCE[0] is None:
        with _INSTANCE_LOCK:
            if _INSTANCE[0] is None:
                rate = LIM.dispatch_per_worker()
                _INSTANCE[0] = Dispatcher(rate)
                import os

                workers = os.environ.get("BACKEND_WORKERS") or os.environ.get("WEB_CONCURRENCY")
                log("job dispatch", per_worker_per_s=rate, burst=rate, workers=workers,
                    deployment_per_s=(rate * int(workers)) if (workers or "").isdigit() else None)
    return _INSTANCE[0]  # type: ignore[return-value]


def reset(dispatcher: Dispatcher | None = None) -> None:
    """Replace (tests) or forget (re-read the rate at next use) the worker's dispatcher."""
    with _INSTANCE_LOCK:
        _INSTANCE[0] = dispatcher
