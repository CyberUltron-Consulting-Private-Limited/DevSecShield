"""Normalise what a scan node reports about TLS before it is stored (CB-12), for every node version:

* sentinel values ``openssl s_client`` prints where it has no value (``<NULL>``, ``(NONE)``, ``NONE``) are not a group
  or a suite: they are dropped, never stored;
* a negotiated suite reported by its OpenSSL name (nodes before CB-12 stored s_client's name) is stored by its IANA name
  with its 2-byte code, so the same suite never appears under two names (#103).

Suite names and codes come from ``tls_suites``, the product's one suite table and its one reader (CB-06 owns it).
"""
from __future__ import annotations

from typing import Any

from backend.utilities.cbom_sources import tls_suites

TLS_TYPES = frozenset({"tls_endpoint", "database_tls", "k8s_ingress_tls", "load_balancer_tls", "cdn_tls", "api_tls"})


def iana_suite(name: Any) -> tuple[int, str] | None:
    """(code, IANA name) of a suite named any way (IANA, OpenSSL of any version, ``SSL_``), or None."""
    hit = tls_suites.lookup(name)
    return (hit.code, hit.iana) if hit is not None and not hit.signalling else None


def is_sentinel(value: Any) -> bool:
    return tls_suites.is_sentinel(value)


def normalise_tls(asset_type: str, facts: dict[str, Any], algorithm: str | None) -> tuple[dict[str, Any], str | None]:
    """(facts, algorithm) to store for one asset; assets that are not TLS rows pass unchanged."""
    if asset_type not in TLS_TYPES:
        return facts, algorithm
    out = dict(facts)
    for key in ("negotiated_group", "group", "negotiated_cipher", "cipher"):
        if is_sentinel(out.get(key)):
            out.pop(key)
    for key in ("negotiated_cipher", "cipher"):
        hit = tls_suites.lookup(out.get(key))
        if hit is not None and not hit.signalling:
            out[key] = hit.iana
            out.setdefault(f"{key}_code", hit.hex)
    if is_sentinel(algorithm):
        algorithm = None
    hit = tls_suites.lookup(algorithm)
    if hit is not None and not hit.signalling:
        algorithm = hit.iana
    return out, algorithm
