"""One judged check, and the collector every judge writes into.

A check has a stable ``id`` (``<gate>/<kind>/...``), the ``gate`` step it belongs to (G0..G17), a ``subject`` (the
keys the known-fail ledger matches on), a verdict and the evidence paths a reviewer opens.

Verdicts:
  PASS            every view and the oracle agree
  FAIL            a disagreement; ``reason`` names it (``export-missing``, ``mismatch``, ``missing``, ``extra`` ...)
  NOT-JUDGED      the lab's own self-check disagreed with the oracle (O-3): a lab bug, never a product pass
  NOT-RUN         the step did not run (no data); the ledger decides whether that is allowed
The ledger (ledger.py) turns a listed FAIL into KNOWN-FAIL; nothing else changes a verdict.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

PASS, FAIL, NOT_JUDGED, NOT_RUN, KNOWN_FAIL = "PASS", "FAIL", "NOT-JUDGED", "NOT-RUN", "KNOWN-FAIL"
VERDICTS = (PASS, FAIL, NOT_JUDGED, NOT_RUN, KNOWN_FAIL)


@dataclass
class Check:
    id: str
    gate: str
    kind: str
    verdict: str
    subject: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    expected: Any = None
    observed: Any = None
    evidence: list[str] = field(default_factory=list)
    ledger_row: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        return {k: v for k, v in out.items() if v not in (None, "", [], {}) or k in ("verdict", "id", "gate", "kind")}


class Checks:
    """Ordered, de-duplicated by id (a second check with the same id is a harness bug and raises)."""

    def __init__(self) -> None:
        self._items: dict[str, Check] = {}

    def add(self, check: Check) -> Check:
        if check.verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {check.verdict!r} for {check.id}")
        if check.id in self._items:
            raise ValueError(f"duplicate check id {check.id}")
        self._items[check.id] = check
        return check

    def ok(self, id: str, gate: str, kind: str, subject: dict[str, Any] | None = None, **kw: Any) -> Check:
        return self.add(Check(id=id, gate=gate, kind=kind, verdict=PASS, subject=subject or {}, **kw))

    def fail(self, id: str, gate: str, kind: str, reason: str, subject: dict[str, Any] | None = None,
             **kw: Any) -> Check:
        return self.add(Check(id=id, gate=gate, kind=kind, verdict=FAIL, reason=reason, subject=subject or {}, **kw))

    def verdict(self, id: str, gate: str, kind: str, passed: bool, reason: str = "",
                subject: dict[str, Any] | None = None, **kw: Any) -> Check:
        if passed:
            return self.ok(id, gate, kind, subject, **kw)
        return self.fail(id, gate, kind, reason or "mismatch", subject, **kw)

    def not_run(self, id: str, gate: str, kind: str, reason: str, subject: dict[str, Any] | None = None) -> Check:
        return self.add(Check(id=id, gate=gate, kind=kind, verdict=NOT_RUN, reason=reason, subject=subject or {}))

    def not_judged(self, id: str, gate: str, kind: str, reason: str, subject: dict[str, Any] | None = None,
                   **kw: Any) -> Check:
        return self.add(Check(id=id, gate=gate, kind=kind, verdict=NOT_JUDGED, reason=reason,
                              subject=subject or {}, **kw))

    def extend(self, other: "Checks") -> None:
        for check in other:
            self.add(check)

    def __iter__(self):
        return iter(self._items.values())

    def __len__(self) -> int:
        return len(self._items)

    def get(self, id: str) -> Check | None:
        return self._items.get(id)

    def by_verdict(self) -> dict[str, int]:
        out = {v: 0 for v in VERDICTS}
        for check in self:
            out[check.verdict] += 1
        return out
