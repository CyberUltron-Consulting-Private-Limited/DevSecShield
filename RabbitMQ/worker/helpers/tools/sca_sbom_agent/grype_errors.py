"""Why grype failed, in one line (no dependencies, so it is unit-testable without the worker's tool chain).

grype's stderr starts with harmless WARN lines ("no explicit name and version provided for directory source ...")
and only the FIRST line of a failure reaches the scan's failure reason (backend celery_connection keeps one line), so
the customer read a warning instead of the cause ("unable to download db: ... no space left on device"): found on the
local stack by the u2 UI run (round 5).
"""
from __future__ import annotations

import re

_LEVEL = re.compile(r"^\[\d+\]\s+(?:WARN|ERROR|INFO|DEBUG)\s+")
_ERRORISH = re.compile(r"\berror\b|\bfailed\b|\bfatal\b|\bunable\b|no space left", re.I)


def grype_failure_reason(stderr: str | None, limit: int = 400) -> str:
    lines = [line.strip() for line in (stderr or "").splitlines() if line.strip()]
    if not lines:
        return "grype exited with an error and printed nothing"
    errors = [line for line in lines if _ERRORISH.search(line)]
    reason = _LEVEL.sub("", errors[-1] if errors else lines[-1])
    return reason[:limit]


__all__ = ["grype_failure_reason"]
