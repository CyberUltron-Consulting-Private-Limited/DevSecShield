"""The strict known-fail ledger (DEVILS-ADVOCATE §4.1, INTERFACES.md §9).

    - row: KF-9
      gate: [G11]
      match: {kind: join, view: export, field: [key_size, curve, signature_algorithm, groups, pqc_class, provenance]}
      issue: "#NN" or "cbom/issues/<file>.md"
      owner: CB-06
      why: "export lacks key size, curve, ..."
      not_run_ok: "<reason>"        # optional: the row may match only NOT-RUN checks

Matching: every ``match`` key must equal the check's subject value (or a top-level field: id, gate, kind, reason,
verdict); a list means any of; a key ending in ``_prefix`` matches a string prefix (``id_prefix: G13/``).

Outcome:
  * a FAIL or NOT-JUDGED check matched by a row becomes KNOWN-FAIL(row);
  * a FAIL / NOT-JUDGED / NOT-RUN check no row matches fails the gate (never silently skipped);
  * a row whose matched checks include a PASS and no failure is STALE and fails the gate: the PR that fixed it must
    remove the row;
  * a row that matched nothing, or only NOT-RUN checks, fails the gate unless it carries ``not_run_ok``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .checks import FAIL, KNOWN_FAIL, NOT_JUDGED, NOT_RUN, PASS, Check, Checks

REQUIRED = ("row", "gate", "match", "issue", "owner", "why")
TOP_LEVEL = ("id", "gate", "kind", "reason", "verdict")


class LedgerError(ValueError):
    pass


@dataclass
class RowResult:
    row: str
    status: str  # holds | stale | not-run | not-run-ok
    matched: int = 0
    failing: int = 0
    passing: int = 0
    not_run: int = 0
    owner: str = ""
    issue: str = ""
    why: str = ""
    examples: list[str] = field(default_factory=list)


def load(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise LedgerError(f"{path}: the ledger must be a YAML list of rows")
    seen = set()
    for i, row in enumerate(data):
        if not isinstance(row, dict):
            raise LedgerError(f"{path}: entry {i} is not a mapping")
        missing = [k for k in REQUIRED if not row.get(k)]
        if missing:
            raise LedgerError(f"{path}: row {row.get('row', i)} lacks {', '.join(missing)}")
        if row["row"] in seen:
            raise LedgerError(f"{path}: duplicate row {row['row']}")
        seen.add(row["row"])
        if not isinstance(row["match"], dict) or not row["match"]:
            raise LedgerError(f"{path}: row {row['row']}: match must be a non-empty mapping")
        if isinstance(row["gate"], str):
            row["gate"] = [row["gate"]]
    return data


def _value(check: Check, key: str) -> Any:
    if key in TOP_LEVEL:
        return getattr(check, key)
    return check.subject.get(key)


def matches(row: dict[str, Any], check: Check) -> bool:
    if check.gate not in row["gate"]:
        return False
    for key, want in row["match"].items():
        if key.endswith("_prefix"):
            got = _value(check, key[: -len("_prefix")])
            prefixes = want if isinstance(want, list) else [want]
            if not isinstance(got, str) or not any(got.startswith(str(p)) for p in prefixes):
                return False
            continue
        got = _value(check, key)
        if isinstance(want, list):
            if got not in want and str(got) not in [str(w) for w in want]:
                return False
        elif got != want and str(got) != str(want):
            return False
    return True


def apply(rows: list[dict[str, Any]], checks: Checks) -> tuple[list[RowResult], list[Check]]:
    """Mark known failures; return the per-row results and the checks that fail the gate."""
    results = []
    covered: set[str] = set()
    for row in rows:
        res = RowResult(row=row["row"], status="", owner=str(row["owner"]), issue=str(row["issue"]),
                        why=str(row["why"]))
        for check in checks:
            if not matches(row, check):
                continue
            res.matched += 1
            if check.verdict in (FAIL, NOT_JUDGED, KNOWN_FAIL):
                res.failing += 1
                if check.verdict != KNOWN_FAIL:
                    check.verdict, check.ledger_row = KNOWN_FAIL, row["row"]
                covered.add(check.id)
                if len(res.examples) < 3:
                    res.examples.append(check.id)
            elif check.verdict == PASS:
                res.passing += 1
                if len(res.examples) < 3 and not res.failing:
                    res.examples.append(check.id)
            elif check.verdict == NOT_RUN:
                res.not_run += 1
                check.ledger_row = row["row"]
                covered.add(check.id)
        if res.failing:
            res.status = "holds"
        elif res.passing:
            res.status = "stale"
        else:
            res.status = "not-run-ok" if row.get("not_run_ok") else "not-run"
            if res.status == "not-run-ok":
                for check in checks:
                    if check.verdict == NOT_RUN and check.ledger_row == row["row"]:
                        covered.add(check.id)
        results.append(res)
    # NOT-RUN checks are covered only by a not_run_ok row or a row that is otherwise holding
    ok_rows = {r.row for r in results if r.status in ("holds", "not-run-ok")}
    blocking = [c for c in checks
                if (c.verdict in (FAIL, NOT_JUDGED))
                or (c.verdict == NOT_RUN and not (c.id in covered and c.ledger_row in ok_rows))]
    return results, blocking


def verdict(results: list[RowResult], blocking: list[Check]) -> bool:
    return not blocking and all(r.status in ("holds", "not-run-ok") for r in results)
