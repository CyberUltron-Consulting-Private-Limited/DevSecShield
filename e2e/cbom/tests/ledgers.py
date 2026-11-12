"""Ledger rows for the harness's own tests (ledger v2: allowlisted match keys, pinned counts)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def row(name: str, gate: list[str], match: dict[str, Any], failing: int = 0, not_run: int = 0,
        owner: str = "CB-05", issue: str = "#1", why: str = "test row") -> dict[str, Any]:
    out: dict[str, Any] = {"row": name, "gate": gate, "match": match, "expect_failing": failing, "issue": issue,
                           "owner": owner, "why": why}
    if not_run:
        out["expect_not_run"] = not_run
        out["not_run_ok"] = "test: not run by design"
    return out


POSTURE = row("POSTURE", ["G11"], {"kind": "derived", "field": "posture"}, not_run=1)


def write(path: Path, *rows: dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(list(rows), sort_keys=False), encoding="utf-8")
    return path
