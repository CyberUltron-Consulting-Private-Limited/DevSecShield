"""TLS cipher suites: the product's ONE table, and the only code that reads it.

Collectors store suites under different names for the same code point: openssl ``s_client`` prints OpenSSL names
(``ECDHE-RSA-AES128-SHA``), the raw probes (``zs_scan_node.tlsprobe``) and IANA-aware collectors print the IANA registry
name (``TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA``), Java and SSLv3-era tools the ``SSL_`` spelling, and a database reports its
server's OpenSSL name (older servers: OpenSSL 1.0.2 / 1.1.1 names such as ``DES-CBC3-SHA``, ``RC4-SHA``,
``EDH-RSA-DES-CBC3-SHA``). Every reader (the run export, CB-06; the node-fact normaliser, CB-12; anything later) goes
through this module: lookups by code, by IANA name, by OpenSSL name, or by any spelling.

The table is ``data/tls_cipher_suites.json`` (its layout is this module's business: no other code reads it), generated
by ``scripts/tls_suites/build_table.py`` from the IANA registry and OpenSSL's own name lists (3.5.7, the scan node
image's; 3.0.13; the 1.1.1 and 1.0.2 manuals), all vendored in ``scripts/tls_suites/sources``. Each suite: its 2-byte
code, its IANA name, every OpenSSL name it has had. Suites only: key-exchange groups are algid's (CB-04).
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, NamedTuple

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "tls_cipher_suites.json")
# what tools print when there is no suite or group: never a name (openssl s_client "Cipher is (NONE)",
# "Negotiated TLS1.3 group: <NULL>", Perl/Net::SSLeay "undef")
SENTINELS = frozenset({"<null>", "(null)", "null", "none", "(none)", "undef", "n/a", "-"})


class Suite(NamedTuple):
    code: int  # 0xC013
    iana: str  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    openssl: tuple[str, ...]  # every OpenSSL name of the suite, sorted (also one equal to the IANA name: TLS 1.3)

    @property
    def hex(self) -> str:
        """``0xC013``"""
        return f"0x{self.code:04X}"

    @property
    def pair(self) -> str:
        """``0xC0,0x13`` (the registry's and ``openssl ciphers -V``'s form)"""
        return f"0x{self.code >> 8:02X},0x{self.code & 0xFF:02X}"

    @property
    def identifiers(self) -> list[str]:
        """CycloneDX ``cipherSuites[].identifiers``: ``["0xC0", "0x13"]``"""
        return self.pair.split(",")

    @property
    def signalling(self) -> bool:
        """TLS_FALLBACK_SCSV and TLS_EMPTY_RENEGOTIATION_INFO_SCSV are registry values, not suites a server accepts."""
        return self.iana.endswith("_SCSV")


@lru_cache(maxsize=1)
def suites() -> tuple[Suite, ...]:
    """Every suite of the table, by code."""
    with open(DATA, encoding="utf-8") as fh:
        rows = json.load(fh)["suites"]
    return tuple(sorted((Suite(int(r["code"].replace("0x", "").replace(",", ""), 16), r["iana"], tuple(r["openssl"]))
                         for r in rows), key=lambda s: s.code))


@lru_cache(maxsize=1)
def _indexes() -> tuple[dict[int, Suite], dict[str, Suite], dict[str, Suite], dict[str, Suite]]:
    by_code: dict[int, Suite] = {}
    by_iana: dict[str, Suite] = {}
    by_openssl: dict[str, Suite] = {}
    any_name: dict[str, Suite] = {}
    for suite in suites():
        by_code[suite.code] = suite
        by_iana[suite.iana.upper()] = suite
        for name in suite.openssl:
            by_openssl[name.upper()] = suite
    for suite in suites():  # IANA first, then OpenSSL, then the SSLv3 spelling of the same code point
        names = [suite.iana, *suite.openssl] + (["SSL_" + suite.iana[4:]] if suite.iana.startswith("TLS_") else [])
        for name in names:
            any_name.setdefault(name.upper(), suite)
    return by_code, by_iana, by_openssl, any_name


def _code(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().lower().replace("0x", "").replace(",", "").replace(" ", "")
    try:
        return int(text, 16) if 1 <= len(text) <= 4 else None
    except ValueError:
        return None


def by_code(code: Any) -> Suite | None:
    """The suite with this code: ``0xC013`` (int), ``"0xC013"``, ``"0xC0,0x13"`` or ``"c013"``; None if unassigned."""
    number = _code(code)
    return _indexes()[0].get(number) if number is not None else None


def by_iana(name: Any) -> Suite | None:
    """The suite with this IANA name (any case)."""
    return _indexes()[1].get(name.strip().upper()) if isinstance(name, str) else None


def by_openssl(name: Any) -> Suite | None:
    """The suite with this OpenSSL name, current or historical (any case)."""
    return _indexes()[2].get(name.strip().upper()) if isinstance(name, str) else None


def lookup(name: Any) -> Suite | None:
    """The suite named any way: IANA, OpenSSL (any version) or ``SSL_`` spelling, any case; None for anything else
    (sentinels such as ``<NULL>`` included)."""
    if not isinstance(name, str) or not name.strip() or is_sentinel(name):
        return None
    return _indexes()[3].get(name.strip().upper())


def is_sentinel(name: Any) -> bool:
    return isinstance(name, str) and name.strip().lower() in SENTINELS


def canonical(name: str) -> tuple[str, str | None]:
    """(IANA name, code ``0xC0,0x13``) of the suite ``name`` (any spelling); a name the table does not hold comes back
    as given, with no code."""
    hit = lookup(name)
    return (hit.iana, hit.pair) if hit is not None else (name, None)


def identifiers(code: str | None) -> list[str]:
    """CycloneDX ``cipherSuites[].identifiers`` of a ``0xC0,0x13`` code: ``["0xC0", "0x13"]``."""
    return code.split(",") if code else []


__all__ = ["DATA", "SENTINELS", "Suite", "by_code", "by_iana", "by_openssl", "canonical", "identifiers", "is_sentinel",
           "lookup", "suites"]
