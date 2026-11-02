"""Named TLS policy floors from the packaged registry.

``tls_policies.json`` carries every security policy AWS publishes for Application / Network Load Balancers
(``aws-elbv2``), Classic Load Balancers (``aws-elb``) and CloudFront viewers (``aws-cloudfront``), each row citing its
AWS page, plus the GCP / Azure profiles. A load-balancer policy name that is not in the catalogue (a retired or
mistyped name) still names its minimum version the way AWS spells every published TLS policy
(``ELBSecurityPolicy-TLS-1-1-2017-01``, ``ELBSecurityPolicy-TLS13-1-2-2021-06``, ``…-FS-1-2-…``: the two digits after
``TLS-``/``TLS13-`` are the minimum); that floor is used and marked as inferred, so the reader knows it was not read
from the catalogue. Any other unknown name yields no floor.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache

from aibom.cbom.posture.defaults import read_data_bytes
from aibom.cbom.posture.model import BasisEntry

_FLOOR = {"SSLv3": "SSLv3", "1.0": "TLSv1.0", "1.1": "TLSv1.1", "1.2": "TLSv1.2", "1.3": "TLSv1.3"}
_RANK = {"SSLv3": 0, "1.0": 1, "1.1": 2, "1.2": 3, "1.3": 4}
_CONFIGURED = {"TLS_1_0": "1.0", "TLS_1_1": "1.1", "TLS_1_2": "1.2", "TLS_1_3": "1.3"}
# Load balancer names win over the Classic Load Balancer rows of the same name (a Terraform ``aws_lb_listener`` or a
# CloudFormation ``AWS::ElasticLoadBalancingV2::Listener`` is always ELBv2).
_FAMILIES = ("aws-elbv2", "aws-cloudfront", "gcp-ssl-policy", "aws-elb")
_WEAK_SUITE = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
# AWS's naming of TLS policies: ELBSecurityPolicy[-FS]-TLS[13]-<major>-<minor>-…
_NAMED_FLOOR = re.compile(r"^ELBSecurityPolicy-(?:FS-)?TLS(?:13)?-1-([0-3])(?:-|$)")
INFERRED = "inferred_from_name"


def protocol_for_policy(name: str, configured: str | None = None) -> str | None:
    """Highest floor of the policy and an optional configured minimum."""
    row = _row(name)
    ranks: list[str] = []
    if row is not None:
        ranks.append(row[0])
    else:
        inferred = _inferred_floor(name)
        if inferred is not None:
            ranks.append(inferred)
    extra = _CONFIGURED.get(configured or "")
    if extra is not None:
        ranks.append(extra)
    ranks = [rank for rank in ranks if rank in _RANK]
    if not ranks:
        return None
    return _FLOOR.get(max(ranks, key=lambda item: _RANK[item]))


def policy_floor_note(name: str) -> BasisEntry | None:
    """A basis note when the floor of ``name`` comes from its name, not from the catalogue."""
    if _row(name) is None and _inferred_floor(name) is not None:
        return BasisEntry("policy_floor", INFERRED)
    return None


def in_catalog(name: str) -> bool:
    return _row(name) is not None


def weak_suite_for_policy(name: str) -> str | None:
    """The 3DES suite when the registry lists it for this policy."""
    row = _row(name)
    if row is None or _WEAK_SUITE not in row[1]:
        return None
    return _WEAK_SUITE


def _inferred_floor(name: str) -> str | None:
    match = _NAMED_FLOOR.match(name.strip())
    return f"1.{match.group(1)}" if match else None


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
