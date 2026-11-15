"""Refused certificate requests leave a trace (sec M3, PR #65 review round 7).

Every refusal of the node route (``POST /cbom/node/jobs/{id}/ssh-cert``) after the node authenticated, and every
refusal of the claim plugin, writes one ``sshca.cert.denied`` audit row (actor: the node; object: the job;
``changed_fields``: ``reason:<code>`` plus the job, source and CA ids, never a key or a certificate) and one log line
``ssh certificate refused reason=<code> team= node= job=``.  So the team sees a node token probing other jobs, a member's
source being refused, a revoked CA still asked for, or a KMS outage.

Bounded: at most one row and one line per (node, job, reason) per ``WINDOW_S`` in this worker; the refusals in
between are counted into the next line (``suppressed=N``), so a node retrying in a loop cannot fill the audit table.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict

from sqlmodel import Session

from backend.utilities.cbom_sources.common import audit, log

WINDOW_S = 60.0
MAX_KEYS = 10_000
_seen: OrderedDict[tuple[int, int, str], tuple[float, int]] = OrderedDict()
_lock = threading.Lock()


def reset() -> None:
    with _lock:
        _seen.clear()


def _admit(key: tuple[int, int, str], now: float) -> int | None:
    """None: suppressed (counted); else the number suppressed since the last recorded one."""
    with _lock:
        last = _seen.get(key)
        if last is not None and now - last[0] < WINDOW_S:
            _seen[key] = (last[0], last[1] + 1)
            return None
        suppressed = last[1] if last else 0
        _seen[key] = (now, 0)
        _seen.move_to_end(key)
        while len(_seen) > MAX_KEYS:
            _seen.popitem(last=False)
        return suppressed


def record(session: Session, *, team_id: int, node_id: int, job_id: int | None, code: str, via: str,
           source_id: int | None = None, ca_id: int | None = None, status: int | None = None) -> bool:
    """Add the audit row to ``session`` (the caller commits; on the route it is a fresh transaction after the
    rollback) and log the line.  False when suppressed by the window."""
    suppressed = _admit((int(node_id), int(job_id or 0), code), time.monotonic())
    if suppressed is None:
        return False
    fields = [f"reason:{code}", f"via:{via}"]
    fields += [f"{name}:{value}" for name, value in (("job", job_id), ("source", source_id), ("ca", ca_id),
                                                     ("status", status)) if value is not None]
    audit(session, team_id=team_id, actor_type="node", actor_id=node_id, action="sshca.cert.denied",
          object_type="ssh_cert", object_id=job_id, changed_fields=fields)
    log("ssh certificate refused", reason=code, team=team_id, node=node_id, job=job_id, source=source_id, ca=ca_id,
        via=via, status=status, suppressed=suppressed or None)
    return True
