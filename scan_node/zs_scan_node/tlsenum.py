"""Enumerate what a TLS server accepts: cipher suites per protocol version, TLS 1.3 suites and groups (CB-12, #100).

Each probe is one raw ClientHello (``tlsprobe``); the server's choice is removed from the next offer until it refuses
(alert ``handshake_failure`` / ``insufficient_security``), so a pass costs (accepted + 1) handshakes. A pass that ends
any other way (the handshake budget, the time cap, a close, another alert, a choice outside the offer) is recorded as
incomplete with its reason, never as complete. Probes go through ``send(hello, want_kex)``, which the caller provides:
it applies the network gate, the rate limiter and the endpoint's budget, and raises ``Stop`` when the budget or time
is used up.

Budget (per endpoint, documented in scan_node/README.md):
  legacy suites   per accepted TLS <= 1.2 version: accepted + 2 (chunk A = the version probes' 77-suite table, the
                  ClientHello size the server already answered; chunk B = every other IANA suite)
  TLS 1.3 suites  accepted + 1 (every IANA TLS 1.3 suite offered at once)
  TLS 1.3 groups  PQ groups accepted + 1, then classical groups accepted + 1 (empty key_share: HelloRetryRequest names
                  the group, nothing is computed)
  TLS <= 1.2 curves (servers without TLS 1.3): curves accepted + 1 (ServerKeyExchange names the curve)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from zs_scan_node import algid_tables as A
from zs_scan_node import tls_registry as R
from zs_scan_node import tlsprobe as T

TERMINAL_ALERTS = frozenset({"handshake_failure", "insufficient_security"})
# TLS 1.3 groups, from algid (the one source of algorithm identity, CB-04): its post-quantum probe list, and every
# other group its TLS 1.3 detection offer names (classical: x25519, NIST curves, FFDHE, brainpool tls13, GOST, SM2)
PQ_OFFER = list(A.PQ_PROBE_GROUPS)
CLASSICAL13_OFFER = [g for g in A.TLS13_OFFER_GROUPS if g not in set(A.PQ_PROBE_GROUPS)]
# TLS <= 1.2 named curves (RFC 8422 and RFC 7027 brainpool), strongest-known first
CURVES12_OFFER = [29, 23, 24, 25, 30, 26, 27, 28, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
                  4, 3, 2, 1]
# every classical group the legacy hellos may name, so ECDHE suites are not refused for want of a curve
LEGACY_GROUPS = [29, 23, 24, 25, 30, 26, 27, 28, 256, 257, 258, 259, 260]
TLS13_COMMON = [0x1302, 0x1301, 0x1303, 0x1304, 0x1305]
TLS13_OFFER = TLS13_COMMON + [c for c in R.TLS13_SUITES if c not in TLS13_COMMON]
CHUNK_A = [c for c in T.LEGACY_SUITES]
CHUNK_B = [c for c in R.LEGACY_SUITES if c not in set(CHUNK_A)]
VERSION_ORDER = (T.TLS12, T.TLS11, T.TLS10, T.SSL3)


class Stop(Exception):
    """The endpoint's handshake budget or time is used up: the pass is incomplete for this reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


Send = Callable[[bytes, bool], T.HelloResult]


@dataclass
class Pass:
    found: list[int] = field(default_factory=list)
    complete: bool = False
    reason: str | None = None
    answered: bool = False  # at least one probe got a TLS answer (a choice, an alert or a close)


def _ended(r: T.HelloResult) -> tuple[bool, str]:
    """How a probe that did not give a new choice ends the pass: (complete, reason)."""
    if r.alert in TERMINAL_ALERTS:
        return True, ""
    if r.alert:
        return False, f"alert {r.alert}"
    return False, "connection closed" if r.closed else "no answer"


def _run(send: Send, offer: list[int], hello: Callable[[list[int]], bytes], accept: Callable[[T.HelloResult, list[int]], int | None],
         want_kex: bool = False, on_hit: Callable[[T.HelloResult], None] | None = None,
         max_probes: int | None = None) -> Pass:
    out = Pass()
    remaining = list(offer)
    probes = 0
    while remaining:
        if max_probes is not None and probes >= max_probes:
            out.reason = "continued later"
            return out
        probes += 1
        try:
            r = send(hello(remaining), want_kex)
        except Stop as stop:
            out.reason = stop.reason
            return out
        except (T.ProbeError, T.StarttlsUnavailable) as exc:
            out.reason = getattr(exc, "code", "starttls")
            return out
        out.answered = True
        choice = accept(r, remaining)
        if choice is not None:
            out.found.append(choice)
            remaining.remove(choice)
            if on_hit:
                on_hit(r)
            continue
        if r.ok:  # answered, but not with something it was offered (or another version): do not guess further
            out.reason = "server answered outside the offer"
            return out
        out.complete, out.reason = _ended(r)
        out.reason = out.reason or None
        return out
    out.complete = True  # everything offered was accepted
    return out


def legacy_suites(send: Send, version: int, known: set[int], sni: str | None, kex: dict[str, Any]) -> Pass:
    """Every suite ``version`` (TLS 1.2 or older) accepts, beyond ``known``: chunk A, then chunk B."""
    def hello(rem: list[int]) -> bytes:
        return T.build_client_hello(version, rem, sni=sni, groups=LEGACY_GROUPS)

    def accept(r: T.HelloResult, rem: list[int]) -> int | None:
        return r.cipher if r.ok and r.version == version and r.cipher in rem else None

    def hit(r: T.HelloResult) -> None:
        if r.dh_bits:
            kex["dh_bits"] = min(kex.get("dh_bits") or r.dh_bits, r.dh_bits)
        if r.ecdhe_group:
            kex.setdefault("curves", set()).add(r.ecdhe_group)

    total = Pass(complete=True)
    for chunk in (CHUNK_A, CHUNK_B):
        p = _run(send, [c for c in chunk if c not in known], hello, accept, want_kex=True, on_hit=hit)
        total.found += p.found
        if not p.complete:
            total.complete, total.reason = False, p.reason
            return total
    return total


def tls13_suites(send: Send, known: set[int], sni: str | None) -> Pass:
    def hello(rem: list[int]) -> bytes:
        return T.build_client_hello(T.TLS12, rem, sni=sni, tls13=True,
                                    groups=CLASSICAL13_OFFER + PQ_OFFER, key_share_groups=[29])

    def accept(r: T.HelloResult, rem: list[int]) -> int | None:
        return r.cipher if r.ok and (r.version == T.TLS13 or r.hrr) and r.cipher in rem else None

    return _run(send, [c for c in TLS13_OFFER if c not in known], hello, accept)


def tls13_groups(send: Send, offer: list[int], sni: str | None, max_probes: int | None = None) -> Pass:
    """Groups by HelloRetryRequest: an empty key_share makes the server name the group it would use."""
    def hello(rem: list[int]) -> bytes:
        return T.build_client_hello(T.TLS12, T.TLS13_SUITES, sni=sni, tls13=True, groups=rem, key_share_groups=[])

    def accept(r: T.HelloResult, rem: list[int]) -> int | None:
        return r.group if r.ok and r.group in rem else None

    return _run(send, offer, hello, accept, max_probes=max_probes)


def legacy_curves(send: Send, version: int, ecdhe_suites: list[int], known: set[int], sni: str | None) -> Pass:
    """TLS <= 1.2 named curves: the ServerKeyExchange of an ECDHE suite names the curve the server picked."""
    def hello(rem: list[int]) -> bytes:
        return T.build_client_hello(version, ecdhe_suites, sni=sni, groups=rem)

    def accept(r: T.HelloResult, rem: list[int]) -> int | None:
        return r.ecdhe_group if r.ok and r.ecdhe_group in rem else None

    return _run(send, [g for g in CURVES12_OFFER if g not in known], hello, accept, want_kex=True)


# ----------------------------------------------------------------------------- classes and facts
def suite_classes(name: str) -> set[str]:
    """The weak classes of a suite name (the rules the node always used, over the whole IANA registry)."""
    out: set[str] = set()
    if any(t in name for t in ("RC4", "3DES", "_DES_", "NULL", "EXPORT", "anon", "IDEA", "SEED", "RC2")):
        out.add("obsolete")
    if name.startswith("TLS_RSA_WITH_") and not any(t in name for t in ("NULL", "RC4", "DES", "IDEA", "SEED")):
        out.add("static_rsa")
    if ("ECDHE" in name or "DHE" in name) and "CBC" in name and not any(t in name for t in ("3DES", "_DES_", "EXPORT", "anon")):
        out.add("cbc")
    if name.startswith("TLS_DHE_") and "EXPORT" not in name:
        out.add("dhe")
    return out


def is_ecdhe(code: int) -> bool:
    return R.SUITES.get(code, "").startswith(("TLS_ECDHE_", "TLS_ECDH_anon_"))


def suite_entry(code: int) -> dict[str, str]:
    return {"code": R.code_hex(code), "name": R.suite_name(code)}


_OPENSSL_GROUPS = {"prime256v1": "secp256r1", "secp256r1": "secp256r1"}
_GROUP_BY_LOWER = {n.lower(): n for n in A.TLS_GROUPS.values()}


def group_name(code: int) -> str:
    """The IANA name of a TLS supported group (algid's table); an unassigned codepoint is shown as its hex value."""
    return A.TLS_GROUPS.get(code, f"0x{code:04X}")


def iana_group(name: str | None) -> str | None:
    """An OpenSSL group name (s_client) as its IANA name; None for sentinels; unknown text is kept as it is."""
    if not name:
        return None
    text = str(name).strip()
    if text.upper() in T.SENTINELS:
        return None
    return _OPENSSL_GROUPS.get(text) or _GROUP_BY_LOWER.get(text.lower()) or text
