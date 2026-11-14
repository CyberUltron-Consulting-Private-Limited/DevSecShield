"""The strict known-fail ledger, v3: rows pin identities, not counts (DEVILS-ADVOCATE §4.1; INTERFACES.md §9, v7 §B,
v7.3; review 5878413538 major 3).

    - row: KF-16
      gate: [G11]
      match: {kind: join, view: export, field: protocol_versions, reason: mismatch}
      expect:                                   # every check this row tolerates, by identity (harness/identity.py)
        - {"id": "G11/join/run1/asset/tls_endpoint@10.231.0.18:443/protocol_versions/export",
           "expected": ["TLSv1", "TLSv1.1", "TLSv1.2"], "observed": ["TLSv1.2"]}
        - {"id": "G11/oracle/run1/z05b/tls/quantum_vulnerable", "verdict": "NOT-JUDGED", "expected": false,
           "observed": false}                   # verdict: FAIL (default), NOT-JUDGED or NOT-RUN
      issue: "#NN"
      owner: CB-06
      why: "..."
      not_run_ok: "<why these checks may be NOT-RUN>"   # only when a NOT-RUN identity is pinned

    python3 -m harness.ledger pin <judged-or-not run> [--ledger L] [--write]   print / rewrite every row's expect

Matching. Every ``match`` key must be in ``MATCH_KEYS`` (a check subject key, or the check's ``kind`` / ``reason``);
``verdict``, ``id`` and any ``*_prefix`` are refused, so a row can only be narrowed, never widened by a pattern. A list
means "any of", compared as exact strings. A row matches only checks whose gate step is in its ``gate``. Each row must
name at least one narrowing key (``NARROWING``). The first matching row claims a check.

Outcome.
* a FAIL or NOT-JUDGED check a row claims becomes KNOWN-FAIL(row); a NOT-RUN check it claims is covered when the row
  has ``not_run_ok``;
* a FAIL / NOT-JUDGED / NOT-RUN check no row covers fails the gate (never silently skipped);
* the identities (normalised id, verdict, expected, observed) of the checks a row claims must equal its ``expect``
  multiset exactly: a fix, a further regression under the same check, a different wrong value, or a fix plus a new
  defect that keeps the count all change the set and fail the gate until the row is re-pinned in the same PR, backed by
  a live run (CI cannot see a run). ``expect_failing`` / ``expect_not_run`` are optional and, when present, must equal
  the pinned FAIL+NOT-JUDGED / NOT-RUN counts;
* status: ``holds`` (identities as pinned), ``stale`` (nothing claimed: delete the row), ``moved`` (identities differ;
  ``unexpected`` / ``missing`` say how), ``not-run-ok`` (only NOT-RUN checks, as pinned).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import identity as ID
from .checks import FAIL, KNOWN_FAIL, NOT_JUDGED, NOT_RUN, PASS, Check, Checks

REQUIRED = ("row", "gate", "match", "issue", "owner", "why", "expect")
MATCH_KEYS = frozenset({"kind", "check", "oracle_id", "target_id", "field", "reason", "view", "step", "part",
                        "listener", "source", "code", "asset_type", "probe"})
TOP_LEVEL = ("kind", "reason")
NARROWING = frozenset({"check", "oracle_id", "part", "field", "step", "probe"})
FORBIDDEN = frozenset({"verdict", "id", "gate"})
ROW_KEYS = frozenset(REQUIRED) | {"expect_failing", "expect_not_run", "not_run_ok"}
PIN_KEYS = frozenset({"id", "verdict", "expected", "observed"})
PIN_VERDICTS = (FAIL, NOT_JUDGED, NOT_RUN)


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
    unexpected: list[dict[str, Any]] = field(default_factory=list)  # claimed now, not pinned
    missing: list[dict[str, Any]] = field(default_factory=list)  # pinned, not claimed now
    actual: list[dict[str, Any]] = field(default_factory=list)  # what `pin` writes


def _pin(row: dict[str, Any], i: int, entry: Any, path: Path) -> dict[str, Any]:
    if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
        raise LedgerError(f"{path}: row {row['row']}: expect[{i}] must be a mapping with a string id")
    unknown = set(entry) - PIN_KEYS
    if unknown:
        raise LedgerError(f"{path}: row {row['row']}: expect[{i}] unknown keys {sorted(unknown)}")
    pin = {"id": entry["id"], "verdict": entry.get("verdict", FAIL)}
    if pin["verdict"] not in PIN_VERDICTS:
        raise LedgerError(f"{path}: row {row['row']}: expect[{i}] verdict must be one of {', '.join(PIN_VERDICTS)}")
    if pin["verdict"] != NOT_RUN:
        pin["expected"] = entry.get("expected")
        pin["observed"] = entry.get("observed")
    elif "expected" in entry:
        raise LedgerError(f"{path}: row {row['row']}: expect[{i}] a NOT-RUN pin carries no expected value")
    elif entry.get("observed") is not None:
        pin["observed"] = entry["observed"]
    return pin


def load(path: Path, pinning: bool = False) -> list[dict[str, Any]]:
    """Read and validate the ledger. ``pinning`` (the pin tool only) accepts rows without ``expect`` and ignores their
    count lines, so a v2 ledger or a new row can be pinned from a run."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise LedgerError(f"{path}: the ledger must be a YAML list of rows")
    seen = set()
    for i, row in enumerate(data):
        if not isinstance(row, dict):
            raise LedgerError(f"{path}: entry {i} is not a mapping")
        if pinning:
            row.setdefault("expect", [])
            row.pop("expect_failing", None)
            row.pop("expect_not_run", None)
        missing = [k for k in REQUIRED if k not in row or (row[k] in (None, "", [], {}) and not (pinning and k == "expect"))]
        if missing:
            hint = " (ledger v3 pins identities: run `python3 -m harness.ledger pin <run>`)" if "expect" in missing else ""
            raise LedgerError(f"{path}: row {row.get('row', i)} lacks {', '.join(missing)}{hint}")
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
        if not isinstance(row["expect"], list):
            raise LedgerError(f"{path}: row {row['row']}: expect must be a list of pinned identities")
        row["expect"] = [_pin(row, j, e, path) for j, e in enumerate(row["expect"])]
        n_fail = sum(1 for p in row["expect"] if p["verdict"] != NOT_RUN)
        n_run = len(row["expect"]) - n_fail
        for key, n in (("expect_failing", n_fail), ("expect_not_run", n_run)):
            if key in row:
                value = row[key]
                if isinstance(value, bool) or not isinstance(value, int) or value != n:
                    raise LedgerError(f"{path}: row {row['row']}: {key} is {value!r} but expect pins {n}")
        row["expect_failing"], row["expect_not_run"] = n_fail, n_run
        if n_run and not row.get("not_run_ok"):
            raise LedgerError(f"{path}: row {row['row']}: a pinned NOT-RUN needs not_run_ok (why it may not run)")
        if row.get("not_run_ok") and not n_run and not pinning:
            raise LedgerError(f"{path}: row {row['row']}: not_run_ok without a pinned NOT-RUN")
    return data


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


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


def _canonical(pin: dict[str, Any]) -> str:
    """Pins and identities compare as canonical JSON (a YAML/JSON round trip keeps the same text)."""
    return ID.key(json.loads(json.dumps(pin, default=str)))


def apply(rows: list[dict[str, Any]], checks: Checks, maps: dict[str, Any] | None = None
          ) -> tuple[list[RowResult], list[Check]]:
    """Mark known failures; return the per-row results and the checks that fail the gate."""
    maps = maps or {"asset": {}, "job": {}, "other": {}, "anchor": None}
    results = []
    covered: set[str] = set()
    for row in rows:
        res = RowResult(row=row["row"], status="", owner=str(row["owner"]), issue=str(row["issue"]),
                        why=str(row["why"]), expect_failing=int(row.get("expect_failing", 0)),
                        expect_not_run=int(row.get("expect_not_run", 0)))
        actual: list[dict[str, Any]] = []
        for check in checks:
            if check.ledger_row or not matches(row, check):
                continue
            res.matched += 1
            if check.verdict in (FAIL, NOT_JUDGED):
                actual.append(ID.identity(check, maps))
                res.failing += 1
                check.verdict, check.ledger_row = KNOWN_FAIL, row["row"]
                covered.add(check.id)
                if len(res.examples) < 3:
                    res.examples.append(check.id)
            elif check.verdict == PASS:
                res.passing += 1
            elif check.verdict == NOT_RUN:
                actual.append(ID.identity(check, maps))
                res.not_run += 1
                check.ledger_row = row["row"]
                if row.get("not_run_ok"):
                    covered.add(check.id)
        res.actual = actual
        have = Counter(_canonical(a) for a in actual)
        want = Counter(_canonical(p) for p in row["expect"])
        res.unexpected = [json.loads(k) for k in (have - want).elements()]
        res.missing = [json.loads(k) for k in (want - have).elements()]
        if have == want:
            res.status = "holds" if res.failing else "not-run-ok"
        elif not actual:
            res.status = "stale"
        else:
            res.status = "moved"
        results.append(res)
    blocking = [c for c in checks
                if c.verdict in (FAIL, NOT_JUDGED) or (c.verdict == NOT_RUN and c.id not in covered)]
    return results, blocking


def verdict(results: list[RowResult], blocking: list[Check]) -> bool:
    return not blocking and all(r.status in ("holds", "not-run-ok") for r in results)


# ------------------------------------------------------------------------------------------------------- pin tool
_ROW = re.compile(r"^- row:\s*(\S+)")


def render_pins(pins: list[dict[str, Any]]) -> list[str]:
    """One JSON flow mapping per line (valid YAML); the default verdict FAIL is left out."""
    lines = ["  expect:"]
    for p in sorted(pins, key=lambda p: (p["id"], _canonical(p))):
        entry = {k: p[k] for k in ("id", "verdict", "expected", "observed") if k in p}
        if entry.get("verdict") == FAIL:
            entry.pop("verdict")
        lines.append("    - " + json.dumps(entry, ensure_ascii=False, default=str))
    return lines


def rewrite(text: str, pins: dict[str, list[dict[str, Any]]]) -> str:
    """Replace (or add) the ``expect:`` block of each named row and drop its count lines; everything else, comments
    included, is kept as written."""
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        m = _ROW.match(lines[i])
        if not m or m.group(1).strip("\"'") not in pins:
            out.append(lines[i])
            i += 1
            continue
        block = [lines[i]]
        i += 1
        while i < len(lines) and lines[i].startswith(" "):
            block.append(lines[i])
            i += 1
        kept, skip = [], False
        for ln in block:
            if re.match(r"^  (expect|expect_failing|expect_not_run):", ln):
                skip = ln.startswith("  expect:")
                continue
            if skip and (ln.startswith("    ") or ln.startswith("  - ")):
                continue
            skip = False
            kept.append(ln)
        out += kept + render_pins(pins[m.group(1).strip("\"'")])
    return "\n".join(out) + "\n"


def pin_main(argv: list[str] | None = None) -> int:
    from . import gate  # the judge (imports this module)
    ap = argparse.ArgumentParser(prog="harness.ledger pin")
    ap.add_argument("run", type=Path)
    ap.add_argument("--ledger", type=Path, default=gate.DEFAULT_LEDGER)
    ap.add_argument("--write", action="store_true", help="rewrite the ledger file in place")
    args = ap.parse_args(argv)
    _, report = gate.judge(args.run, args.ledger, pinning=True)
    pins = {r["row"]: r["actual"] for r in report["ledger"] if r["actual"]}
    stale = [r["row"] for r in report["ledger"] if not r["actual"]]
    if args.write:
        args.ledger.write_text(rewrite(args.ledger.read_text(encoding="utf-8"), pins), encoding="utf-8")
    else:
        for name, p in pins.items():
            print(f"- row: {name}\n" + "\n".join(render_pins(p)))
    unclaimed = [c["id"] for c in report["blocking"] if not c.get("ledger_row")]
    print(json.dumps({"rows_pinned": len(pins), "stale_rows": stale, "unclaimed_blocking": unclaimed[:40],
                      "unclaimed_total": len(unclaimed)}, indent=1), file=sys.stderr)
    return 0 if not stale and not unclaimed else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "pin":
        sys.exit(pin_main(sys.argv[2:]))
    print(__doc__)
    sys.exit(2)
