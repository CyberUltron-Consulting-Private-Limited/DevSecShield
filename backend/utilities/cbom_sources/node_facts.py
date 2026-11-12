"""Normalise what a scan node reports about TLS before it is stored (CB-12), for every node version:

* sentinel values ``openssl s_client`` prints where it has no value (``<NULL>``, ``(NONE)``, ``NONE``) are not a group
  or a suite: they are dropped, never stored;
* a negotiated suite reported by its OpenSSL name (nodes before CB-12 stored s_client's name) is stored by its IANA name
  with its 2-byte code, so the same suite never appears under two names (#103).

The suite table is ``data/tls_cipher_suites.json``, generated with the scan node's ``tls_registry`` by
``scan_node/scripts/gen_tls_registry.py`` (one table, two copies; a test keeps them equal).
"""
from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any

SENTINELS = frozenset({"<NULL>", "(NONE)", "NONE", "(NULL)", "NULL"})
TLS_TYPES = frozenset({"tls_endpoint", "database_tls", "k8s_ingress_tls", "load_balancer_tls", "cdn_tls", "api_tls"})
_TABLE = Path(__file__).with_name("data") / "tls_cipher_suites.json"


@functools.lru_cache(maxsize=1)
def suite_codes() -> dict[str, tuple[int, str]]:
    """IANA or OpenSSL suite name -> (code, IANA name)."""
    data = json.loads(_TABLE.read_text())
    out: dict[str, tuple[int, str]] = {}
    for hex_code, names in data["suites"].items():
        code = int(hex_code, 16)
        if names.get("openssl"):
            out[names["openssl"]] = (code, names["iana"])
    for hex_code, names in data["suites"].items():
        out[names["iana"]] = (int(hex_code, 16), names["iana"])
    return out


def iana_suite(name: Any) -> tuple[int, str] | None:
    """(code, IANA name) of a suite named either way, or None."""
    if not isinstance(name, str) or not name.strip():
        return None
    return suite_codes().get(name.strip())


def is_sentinel(value: Any) -> bool:
    return isinstance(value, str) and value.strip().upper() in SENTINELS


def normalise_tls(asset_type: str, facts: dict[str, Any], algorithm: str | None) -> tuple[dict[str, Any], str | None]:
    """(facts, algorithm) to store for one asset; assets that are not TLS rows pass unchanged."""
    if asset_type not in TLS_TYPES:
        return facts, algorithm
    out = dict(facts)
    for key in ("negotiated_group", "group", "negotiated_cipher", "cipher"):
        if is_sentinel(out.get(key)):
            out.pop(key)
    for key in ("negotiated_cipher", "cipher"):
        known = iana_suite(out.get(key))
        if known is not None:
            out[key] = known[1]
            out.setdefault(f"{key}_code", f"0x{known[0]:04X}")
    if is_sentinel(algorithm):
        algorithm = None
    known = iana_suite(algorithm)
    if known is not None:
        algorithm = known[1]
    return out, algorithm
