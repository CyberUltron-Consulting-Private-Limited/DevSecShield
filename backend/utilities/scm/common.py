"""Shared helpers of the SCM package: one greppable log line per state change (ids, enums and numbers only)."""
from __future__ import annotations

from typing import Any

from rich.console import Console

console = Console()


def log(action: str, **fields: Any) -> None:
    parts = [f"scm {action}"]
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"{key}={value}")
    try:
        console.print(" ".join(parts), markup=False, highlight=False, soft_wrap=True)
    except Exception:  # logging must never fail a request
        pass


__all__ = ["log"]
