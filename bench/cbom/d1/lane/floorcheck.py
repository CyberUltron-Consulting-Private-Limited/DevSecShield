"""Floors only rise: floors.json against the base branch's copy (`d1.py check-floors --base REF`, run by ci.sh).

A change may add floors, raise them, rename a floor without changing it, or turn a met target into a non-regression
floor at least as high (in place or under a new id). Everything else that makes a floor easier to meet is a
loosening and is refused unless the same change records it:

* on the row it loosens, `"lowered": {"reason": ..., "pr": ...}`: a lower value, a superset list that loses an id,
  a subset list that gains one, a changed `bench` / `where` / `metric` / `mode` / `op`, a non-regression row that
  becomes a target, or a new `not_run_ok`;
* for a floor id that disappears without a replacement, a top-level `"removed": [{"id", "reason", "pr"}]` entry.

The record must be new in the change (different from the base's record for that id), so an old record never covers a
later loosening. report.md prints every record. The lane's own floor evaluation is in floors.py.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .labels import LaneError

DEFINITION = ("bench", "where", "metric", "mode", "op")


def _canon(f: dict, key: str) -> str:
    if key == "where":  # a list in `where` means "any of": order does not matter
        w = f.get("where") or {}
        return json.dumps({k: sorted(json.dumps(x) for x in v) if isinstance(v, list) else v for k, v in w.items()},
                          sort_keys=True)
    return json.dumps(f.get(key, "matched" if key == "mode" else None))


def _not_looser(op: str, base: object, head: object) -> bool:
    if op == ">=":
        return head >= base  # type: ignore[operator]
    if op == "<=":
        return head <= base  # type: ignore[operator]
    if op == "superset":
        return set(head) >= set(base)  # type: ignore[arg-type]
    if op == "subset":
        return set(head) <= set(base)  # type: ignore[arg-type]
    return head == base      # "==": any change redefines the floor


def _show(v: object) -> str:
    return f"{len(v)} ids" if isinstance(v, list) else str(v)


def loosened(base: dict, head: dict) -> str | None:
    """Why `head` is easier to meet than `base` (the same floor id), or None."""
    changed = [k for k in DEFINITION if _canon(base, k) != _canon(head, k)]
    if changed:
        return f"{', '.join(changed)} changed"
    if base["kind"] == "non-regression" and head["kind"] != "non-regression":
        return "a non-regression floor became a target"
    if head.get("not_run_ok") and not base.get("not_run_ok"):
        return "not_run_ok added"
    if not _not_looser(base["op"], base["value"], head["value"]):
        if isinstance(base["value"], list):
            lost = sorted(set(base["value"]) - set(head["value"]))
            gained = sorted(set(head["value"]) - set(base["value"]))
            return (f"value loosened: {_show(base['value'])} -> {_show(head['value'])}"
                    f" (lost {lost[:5]}, gained {gained[:5]}{' ...' if len(gained) > 5 else ''})")
        return f"value loosened: {base['value']} -> {head['value']}"
    return None


def _fresh(head_record: object, base_record: object) -> bool:
    return bool(head_record) and head_record != base_record


def compare(base: dict, head: dict) -> list[str]:
    """Problems of `head` against `base` (two floors.json documents); [] when the floors only rose."""
    head_rows = {f["id"]: f for f in head["floors"]}
    removed_base = {r["id"]: r for r in base.get("removed", [])}
    removed_head = {r["id"]: r for r in head.get("removed", [])}
    base_ids = {f["id"] for f in base["floors"]}
    problems = []
    for b in base["floors"]:
        h = head_rows.get(b["id"])
        if h is None:
            # renamed, or a met target replaced by a non-regression row at least as high under another id
            if any(r["kind"] == "non-regression" and loosened(b, {**r, "kind": b["kind"]}) is None
                   for r in head["floors"] if r["id"] not in base_ids):
                continue
            if _fresh(removed_head.get(b["id"]), removed_base.get(b["id"])):
                continue
            problems.append(f"{b['id']}: {b['kind']} floor removed with no replacement at least as high "
                            f"(record it in \"removed\": [{{id, reason, pr}}])")
            continue
        why = loosened(b, h)
        if why and not _fresh(h.get("lowered"), b.get("lowered")):
            problems.append(f"{b['id']}: {why} (record it on the row: \"lowered\": {{reason, pr}})")
    return problems


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60,
                          env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))


def load_at(repo: Path, ref: str, rel: str) -> dict | None:
    """floors.json as committed at `ref`; None when that commit has no such file. A ref that does not resolve is a
    LaneError (NOT JUDGED), never "nothing to compare"."""
    if _git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").returncode != 0:
        raise LaneError(f"floors base {ref!r} does not resolve to a commit in {repo} (fetch it, or set "
                        f"D1_FLOORS_BASE)")
    if _git(repo, "cat-file", "-e", f"{ref}:{rel}").returncode != 0:
        return None
    res = _git(repo, "show", f"{ref}:{rel}")
    if res.returncode != 0:
        raise LaneError(f"git show {ref}:{rel} failed: {res.stderr.strip()[-300:]}")
    try:
        return json.loads(res.stdout)
    except ValueError as exc:
        raise LaneError(f"{ref}:{rel} is not JSON: {exc}") from exc
