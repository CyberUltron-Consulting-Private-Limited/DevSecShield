"""The strict known-fail ledger, v2 (DEVILS-ADVOCATE §4.1; INTERFACES.md §9 and v7 §B).

    - row: KF-9
      gate: [G11]
      match: {kind: join, view: export, field: [key_size, curve], reason: export-missing}
      expect_failing: 24          # FAIL + NOT-JUDGED checks this row covers on the current dev run
      expect_not_run: 0           # NOT-RUN checks it covers (needs not_run_ok)
      issue: "#NN"
      owner: CB-06
      why: "export lacks key size and curve"
      not_run_ok: "<why these checks may be NOT-RUN>"   # only with expect_not_run > 0

Matching. Every ``match`` key must be in ``MATCH_KEYS`` (a check subject key, or the check's ``kind`` / ``reason``);
``verdict``, ``id`` and any ``*_prefix`` are refused, so a row can only be narrowed, never widened by a pattern. A list
means "any of", compared as exact strings. A row matches only checks whose gate step is in its ``gate``. Each row must
name at least one narrowing key (``NARROWING``).

Outcome.
* a FAIL or NOT-JUDGED check a row matches becomes KNOWN-FAIL(row); a NOT-RUN check it matches is covered when the row
  has ``not_run_ok``;
* a FAIL / NOT-JUDGED / NOT-RUN check no row covers fails the gate (never silently skipped);
* the number of FAIL/NOT-JUDGED checks a row matched must equal ``expect_failing`` and the number of NOT-RUN checks must
  equal ``expect_not_run``: a fix (fewer) or a new defect under the row (more) both fail the gate until the row is
  edited, in the same PR, backed by a live run (CI cannot see a run);
* status: ``holds`` (counts as pinned), ``stale`` (pinned failures but none now: delete the row), ``moved`` (counts
  differ), ``not-run-ok`` (only NOT-RUN checks, as pinned).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .checks import FAIL, KNOWN_FAIL, NOT_JUDGED, NOT_RUN, PASS, Check, Checks

REQUIRED = ("row", "gate", "match", "issue", "owner", "why", "expect_failing")
MATCH_KEYS = frozenset({"kind", "check", "oracle_id", "target_id", "field", "reason", "view", "step", "part",
                        "listener", "source", "code", "asset_type", "probe"})
TOP_LEVEL = ("kind", "reason")
NARROWING = frozenset({"check", "oracle_id", "part", "field", "step", "probe"})
FORBIDDEN = frozenset({"verdict", "id", "gate"})
ROW_KEYS = frozenset(REQUIRED) | {"expect_not_run", "not_run_ok"}


class LedgerError(ValueError):
    pass


@dataclass
class RowResult:
    row: str
    status: str  # holds | stale | moved | not-run-ok
    matched: int = 0
    failing: int = 0
    passing: int = 0
    not_run: int = 0
    expect_failing: int = 0
    expect_not_run: int = 0
    owner: str = ""
    issue: str = ""
    why: str = ""
    examples: list[str] = field(default_factory=list)


def _count(row: dict[str, Any], key: str, path: Path) -> int:
    value = row.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LedgerError(f"{path}: row {row['row']}: {key} must be a whole number >= 0")
    return value


def load(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise LedgerError(f"{path}: the ledger must be a YAML list of rows")
    seen = set()
    for i, row in enumerate(data):
        if not isinstance(row, dict):
            raise LedgerError(f"{path}: entry {i} is not a mapping")
        missing = [k for k in REQUIRED if k not in row or (k != "expect_failing" and row[k] in (None, "", [], {}))]
        if missing:
            raise LedgerError(f"{path}: row {row.get('row', i)} lacks {', '.join(missing)}")
        unknown = set(row) - ROW_KEYS
        if unknown:
            raise LedgerError(f"{path}: row {row['row']}: unknown keys {sorted(unknown)}")
        if row["row"] in seen:
            raise LedgerError(f"{path}: duplicate row {row['row']}")
        seen.add(row["row"])
        match = row["match"]
        if not isinstance(match, dict) or not match:
            raise LedgerError(f"{path}: row {row['row']}: match must be a non-empty mapping")
        bad = sorted(k for k in match if k in FORBIDDEN or k.endswith("_prefix") or k not in MATCH_KEYS)
        if bad:
            raise LedgerError(f"{path}: row {row['row']}: match keys {bad} are not allowed (allowed: "
                              f"{', '.join(sorted(MATCH_KEYS))}; never verdict, id or *_prefix)")
        if not NARROWING & set(match):
            raise LedgerError(f"{path}: row {row['row']}: match must name one of {sorted(NARROWING)}")
        for key, value in match.items():
            values = value if isinstance(value, list) else [value]
            if not values or any(v in (None, "") or isinstance(v, (dict, list)) for v in values):
                raise LedgerError(f"{path}: row {row['row']}: match.{key} must be a value or a list of values")
        if isinstance(row["gate"], str):
            row["gate"] = [row["gate"]]
        exp_f, exp_n = _count(row, "expect_failing", path), _count(row, "expect_not_run", path)
        if exp_n and not row.get("not_run_ok"):
            raise LedgerError(f"{path}: row {row['row']}: expect_not_run needs not_run_ok (why they may not run)")
        if row.get("not_run_ok") and not exp_n:
            raise LedgerError(f"{path}: row {row['row']}: not_run_ok without expect_not_run")
        if not exp_f and not exp_n:
            raise LedgerError(f"{path}: row {row['row']}: a row must pin at least one failing or not-run check")
    return data


def _value(check: Check, key: str) -> Any:
    if key in TOP_LEVEL:
        return getattr(check, key)
    return check.subject.get(key)


def matches(row: dict[str, Any], check: Check) -> bool:
    if check.gate not in row["gate"]:
        return False
    for key, want in row["match"].items():
        got = _value(check, key)
        if got is None:
            return False
        wanted = [str(w) for w in (want if isinstance(want, list) else [want])]
        if str(got) not in wanted:
            return False
    return True


def apply(rows: list[dict[str, Any]], checks: Checks) -> tuple[list[RowResult], list[Check]]:
    """Mark known failures; return the per-row results and the checks that fail the gate."""
    results = []
    covered: set[str] = set()
    for row in rows:
        res = RowResult(row=row["row"], status="", owner=str(row["owner"]), issue=str(row["issue"]),
                        why=str(row["why"]), expect_failing=int(row.get("expect_failing", 0)),
                        expect_not_run=int(row.get("expect_not_run", 0)))
        for check in checks:
            if check.ledger_row or not matches(row, check):
                continue
            res.matched += 1
            if check.verdict in (FAIL, NOT_JUDGED):
                res.failing += 1
                check.verdict, check.ledger_row = KNOWN_FAIL, row["row"]
                covered.add(check.id)
                if len(res.examples) < 3:
                    res.examples.append(check.id)
            elif check.verdict == PASS:
                res.passing += 1
            elif check.verdict == NOT_RUN:
                res.not_run += 1
                check.ledger_row = row["row"]
                if row.get("not_run_ok"):
                    covered.add(check.id)
        if (res.failing, res.not_run) == (res.expect_failing, res.expect_not_run):
            res.status = "holds" if res.failing else "not-run-ok"
        elif res.expect_failing and not res.failing and not res.not_run:
            res.status = "stale"
        else:
            res.status = "moved"
        results.append(res)
    blocking = [c for c in checks
                if c.verdict in (FAIL, NOT_JUDGED) or (c.verdict == NOT_RUN and c.id not in covered)]
    return results, blocking


def verdict(results: list[RowResult], blocking: list[Check]) -> bool:
    return not blocking and all(r.status in ("holds", "not-run-ok") for r in results)
