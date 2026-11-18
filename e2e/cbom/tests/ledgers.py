"""Ledger rows for the harness's own tests (ledger v3: allowlisted match keys, pinned identities)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def row(name: str, gate: list[str], match: dict[str, Any], pins: list[dict[str, Any]] | None = None,
        not_run_ok: str | None = None, owner: str = "CB-05", issue: str = "#1", why: str = "test row") -> dict[str, Any]:
    out: dict[str, Any] = {"row": name, "gate": gate, "match": match, "issue": issue, "owner": owner, "why": why}
    if pins is not None:
        out["expect"] = pins
    if not_run_ok:
        out["not_run_ok"] = not_run_ok
    return out


def nr(check_id: str, **extra: Any) -> dict[str, Any]:
    return {"id": check_id, "verdict": "NOT-RUN", **extra}


POSTURE = row("POSTURE", ["G11"], {"kind": "derived", "field": "posture"}, [nr("G11/derived/run1/posture")],
              not_run_ok="test: not run by design")
# the lab's silence on codes / impact is pinned per run (pinned() fills it from the run being judged)
NOVERDICT = row("NOVERDICT", ["G11"], {"kind": "oracle", "field": ["finding_codes", "impact"], "reason": "no-expectation"},
                not_run_ok="test: the oracle names no codes or impact")


def write(path: Path, *rows: dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(list(rows), sort_keys=False), encoding="utf-8")
    return path


def pinned(run: Path, path: Path, *rows: dict[str, Any]) -> Path:
    """Write ``rows`` with every row lacking ``expect`` pinned to what the judge sees on ``run`` now (the pin tool's
    rule, harness/ledger.py), so a test can then change the run and watch the row move."""
    from harness import gate
    write(path, *rows)
    _, report = gate.judge(run, path, pinning=True)
    actual = {r["row"]: r["actual"] for r in report["ledger"]}
    out = []
    for r in rows:
        r = dict(r)
        if "expect" not in r:
            r["expect"] = actual.get(r["row"]) or []
            if not any(p["verdict"] == "NOT-RUN" for p in r["expect"]):
                r.pop("not_run_ok", None)
        out.append(r)
    return write(path, *out)
