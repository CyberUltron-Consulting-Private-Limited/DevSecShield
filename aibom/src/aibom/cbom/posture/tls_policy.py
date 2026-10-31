"""Named TLS policy floors from the packaged registry."""

from __future__ import annotations

import json
from functools import lru_cache

from aibom.cbom.posture.defaults import read_data_bytes

_FLOOR = {"1.0": "TLSv1.0", "1.1": "TLSv1.1", "1.2": "TLSv1.2", "1.3": "TLSv1.3"}
_CONFIGURED = {"TLS_1_0": "1.0", "TLS_1_1": "1.1", "TLS_1_2": "1.2", "TLS_1_3": "1.3"}
_FAMILIES = ("aws-elbv2", "aws-cloudfront", "gcp-ssl-policy")
_WEAK_SUITE = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"


def protocol_for_policy(name: str, configured: str | None = None) -> str | None:
    """Highest floor of the policy and an optional configured minimum."""
    row = _row(name)
    ranks: list[str] = []
    if row is not None:
        ranks.append(row[0])
    extra = _CONFIGURED.get(configured or "")
    if extra is not None:
        ranks.append(extra)
    if not ranks:
        return None
    return _FLOOR.get(max(ranks, key=lambda item: float(item)))


def weak_suite_for_policy(name: str) -> str | None:
    """The 3DES suite when the registry lists it for this policy."""
    row = _row(name)
    if row is None or _WEAK_SUITE not in row[1]:
        return None
    return _WEAK_SUITE


def _row(name: str) -> tuple[str, tuple[str, ...]] | None:
    rows = _rows()
    for family in _FAMILIES:
        found = rows.get((family, name))
        if found is not None and found[0]:
            return found
    return None


@lru_cache(maxsize=1)
def _rows() -> dict[tuple[str, str], tuple[str, tuple[str, ...]]]:
    payload = json.loads(read_data_bytes("tls_policies.json"))
    found: dict[tuple[str, str], tuple[str, tuple[str, ...]]] = {}
    for row in payload.get("rows", ()):
        if not isinstance(row, dict):
            continue
        family = row.get("family")
        policy = row.get("name")
        minimum = row.get("min") or row.get("profile_floor")
        if not isinstance(family, str) or not isinstance(policy, str):
            continue
        if not isinstance(minimum, str):
            continue
        suites = row.get("suites") or ()
        names = tuple(item for item in suites if isinstance(item, str))
        found[(family, policy)] = (minimum, names)
    return found
