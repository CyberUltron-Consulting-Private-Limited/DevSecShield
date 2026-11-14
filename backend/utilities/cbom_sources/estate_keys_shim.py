"""A thin stand-in for CB-21's ``asset_keys`` (PR #137) with the same signatures, used by ``estate`` ONLY while that
module is not on the branch. Delete this file once #137 has landed (``estate`` imports ``asset_keys`` first).

It keys a certificate by its SHA-256 fingerprint, else serial + notAfter day, an endpoint by ``host:port`` and a cloud
resource by its ARN / resource id; it does NOT correlate Windows thumbprint-only rows, ACM "Amazon" issuers or weak DN
keys (that is CB-21's job), so keys written under it are re-keyed by the first write after #137 (``estate`` moves an
observation whose key changed, it never reads it as a removal).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

KEY_VERSION = "shim0"
CERT_TYPES = frozenset({"certificate", "k8s_certificate"})
ENDPOINT_TYPES = frozenset({"tls_endpoint", "ssh_endpoint", "database_tls", "k8s_ingress_tls", "load_balancer_tls",
                            "cdn_tls", "api_tls"})


class NotCorrelated:
    _instance: "NotCorrelated | None" = None
    reason = "not_correlated"

    def __new__(cls) -> "NotCorrelated":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "NOT_CORRELATED"


NOT_CORRELATED = NotCorrelated()


def _hash(prefix: str, basis: str, value: str) -> str:
    return f"{prefix}:{hashlib.sha256(f'{KEY_VERSION}|{basis}|{value}'.encode('utf-8', 'replace')).hexdigest()[:40]}"


def _attrs(obj: Any) -> tuple[str, Mapping[str, Any], str, str, str]:
    if isinstance(obj, Mapping):
        facts = obj.get("facts")
        return (str(obj.get("asset_type") or obj.get("type") or ""), facts if isinstance(facts, Mapping) else {},
                str(obj.get("location") or ""), str(obj.get("target") or ""), str(obj.get("cdx_type") or ""))
    facts = getattr(obj, "facts", None)
    return (str(getattr(obj, "asset_type", "") or ""), facts if isinstance(facts, Mapping) else {},
            str(getattr(obj, "location", "") or ""), str(getattr(obj, "target", "") or ""),
            str(getattr(obj, "cdx_type", "") or ""))


def asset_key(obj: Any) -> str | None | NotCorrelated:
    kind, facts, location, target, cdx_type = _attrs(obj)
    if kind in CERT_TYPES or cdx_type == "certificate":
        sha = "".join(c for c in str(facts.get("fingerprint_sha256") or "").lower() if c in "0123456789abcdef")
        if len(sha) == 64:
            return _hash("cert", "sha256", sha)
        serial = str(facts.get("serial") or facts.get("serial_number") or "").lower().replace(":", "").lstrip("0")
        after = str(facts.get("not_after") or "")[:10]
        if serial and after:
            return _hash("cert", "serial", f"{serial}|{after}")
        return NOT_CORRELATED
    if kind in ENDPOINT_TYPES and location:
        return _hash("ep", "endpoint", location.lower())
    ident = str(facts.get("identity") or "")
    if ident.startswith("arn:"):
        return _hash("cloud", "cloud", ident)
    return None


def observation_key(row: Any, source_ref: str) -> str:
    from backend.utilities.cbom_sources import identity as ID

    return ID.stable_key("node", source_ref, ID.node_identity(row))


@dataclass
class Correlation:
    keys: list[Any]
    aliases: list[frozenset[str]]


def correlate_detail(observations: Sequence[Any]) -> Correlation:
    keys = [asset_key(o) for o in observations]
    return Correlation(keys=keys, aliases=[frozenset({k}) if isinstance(k, str) else frozenset() for k in keys])
