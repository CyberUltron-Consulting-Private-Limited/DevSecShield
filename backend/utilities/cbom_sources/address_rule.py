"""The CBOM SSRF guard's address rule: which addresses ZeroShield may connect to for a URL a customer supplied.

One file, run by every caller (#53): ``safe_fetch.py`` (CBOM metadata fetches; it adds its operator allowlists and lab
mode through ``permit``), the scan API's check of an MCP server URL and a custom model URI (``utilities/scan/
target_address.py``) and the scan worker when an MCP or LLM scan connects (``RabbitMQ/worker/helpers/net/guard.py``
loads this file; the worker image carries it at the same path, ``/build/backend/utilities/cbom_sources/``). Standard
library only and no import from the backend package, so the worker can load it on its own.

* every address a host resolves to must be public: not private, loopback, link-local (169.254.169.254, the cloud
  metadata service), CGNAT, unique-local, site-local, multicast, reserved, or an IPv4-mapped or translated form of
  one. One refused address refuses the host: DNS may hand it out later;
* the checked addresses are tried in turn, those this host can route first (a dual-stack name works in an IPv4-only
  container), and the connection goes to one of them, so a DNS answer cannot change between the check and the
  connection.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from typing import Callable
from urllib.parse import urlsplit

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# IPv6 prefixes that carry an IPv4 address to a translator or relay (NAT64, local NAT64, 6to4)
_V4_IN_V6 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"), ipaddress.ip_network("2002::/16"),
             ipaddress.ip_network("::ffff:0:0:0/96"), ipaddress.ip_network("::/96"))  # + IPv4-translated, -compatible


class Unresolvable(OSError):
    """``host`` does not resolve: a network failure, reported as one, not a refusal."""


class AddressRefused(Exception):
    """``host`` resolves to ``address``, which the rule refuses. Callers word the refusal for their audience."""

    def __init__(self, host: str, address: str):
        super().__init__(f"{host} resolves to a private or reserved address")
        self.host = host
        self.address = address


class TargetURLError(ValueError):
    """Not a URL an MCP or LLM scan can connect to. ``str(err)`` completes a sentence about the field
    ("... is required")."""


def public_address(text: str) -> bool:
    ip = ipaddress.ip_address(text)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and any(ip in net for net in _V4_IN_V6):
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local:
        # fec0::/10, deprecated site-local (RFC 3879): an internal network like RFC 1918, though Python calls it global
        return False
    return bool(ip.is_global) and not ip.is_multicast


def _routable(address: str, port: int) -> bool:
    """Whether this host has a route to ``address``. A UDP ``connect`` sends nothing; it only picks a route, and fails
    at once for a family the host cannot reach (IPv6 in an IPv4-only container)."""
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.connect((address, port or 9))
        return True
    except OSError:
        return False


def connection_order(addresses: list[str], port: int) -> list[str]:
    """Checked addresses in the order to try them: the resolver's order (RFC 6724 where the resolver applies it),
    addresses this host can route first. Every one of them was checked; each attempt stays pinned to its address."""
    unique = list(dict.fromkeys(addresses))
    if len(unique) < 2:
        return unique
    return sorted(unique, key=lambda address: not _routable(address, port))  # stable: resolver order otherwise


def connect_first(addresses: list[str], port: int, timeout: float, deadline: float | None = None) -> socket.socket:
    """A TCP connection to the first of the (checked) ``addresses`` that accepts one, tried in turn: a dual-stack name
    whose IPv6 address this host cannot reach falls back to its IPv4 address. Raises the last connect error."""
    last: OSError | None = None
    for address in addresses:
        wait = timeout if deadline is None else min(timeout, deadline - time.monotonic())
        if wait <= 0:
            break
        try:
            return socket.create_connection((address, port), wait)
        except OSError as exc:
            last = exc
    raise last if last is not None else TimeoutError("no time left to connect")


def resolve(host: str, port: int) -> list[str]:
    """Every address the system resolver gives for ``host``, in its order. Raises Unresolvable."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise Unresolvable(f"{host} does not resolve") from exc
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if not addresses:
        raise Unresolvable(f"{host} does not resolve")
    return addresses


def checked_addresses(host: str, port: int, permit: Callable[[str], bool] | None = None) -> list[str]:
    """Every address ``host`` resolves to, each checked, in ``connection_order``. An address passes when it is public,
    or when the caller's ``permit(address)`` opens it (safe_fetch: lab mode, an operator allowlist). Raises
    Unresolvable, or AddressRefused for the first address that does not pass."""
    addresses = resolve(host, port)
    for address in addresses:
        if public_address(address) or (permit is not None and permit(address)):
            continue
        raise AddressRefused(host, address)
    return connection_order(addresses, port)


def scan_target(url: str | None) -> tuple[str, int]:
    """The host and port an MCP server URL or a custom model URI connects to: an http:// or https:// URL with a host
    (any port; the scheme's default when it names none). Raises TargetURLError."""
    text = str(url or "").strip()
    if not text:
        raise TargetURLError("is required")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise TargetURLError("has an invalid port" if "port" in str(exc).lower() else "is not a valid URL") from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise TargetURLError("must be an http:// or https:// URL with a host name")
    return parts.hostname, port or (443 if scheme == "https" else 80)
