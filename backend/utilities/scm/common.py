"""Shared helpers of the SCM package: one greppable log line per state change (ids, enums and numbers only)."""
from __future__ import annotations

import re
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


_URL_USERINFO = re.compile(r"(?i)\b(https?://)[^/@\s'\"]+@")


def redact_urls(text: str) -> str:
    """``text`` with the user info of every URL dropped (``https://x-access-token:<token>@host`` -> ``https://***@host``),
    for a worker's error sentence copied onto a request: a clone URL carries the connection's token."""
    return _URL_USERINFO.sub(r"\1***@", str(text))


__all__ = ["log", "redact_urls"]
