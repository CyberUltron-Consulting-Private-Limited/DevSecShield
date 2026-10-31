"""HSTS is an attribute. Its absence records nothing and raises no finding."""

from __future__ import annotations

import re

from aibom.cbom.posture.model import BasisEntry

_AGE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)


def entries_from_value(value: str) -> tuple[BasisEntry, BasisEntry]:
    """``present`` plus a max-age, or ``unknown`` when the age is not a number."""
    match = _AGE.search(value)
    if match:
        age = match.group(1)
    elif value.strip().isdigit():
        age = value.strip()
    else:
        age = "unknown"
    return (
        BasisEntry("hsts", "present"),
        BasisEntry("hsts_max_age", age),
    )
