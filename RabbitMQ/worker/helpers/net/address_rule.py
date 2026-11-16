"""The address rule for what an MCP or LLM scan connects to (issue #53): the CBOM SSRF guard's rule, at connect time.

The ZeroShield server checks an MCP server URL and a custom model URI with ``backend/utilities/cbom_sources/
safe_fetch.py`` before it queues a scan (backend/utilities/scan/target_address.py). DNS can answer differently when the
worker connects (DNS rebinding) and a server can redirect, so the worker applies the rule again to every connection of
a scan (helpers/net/egress.py). The worker image cannot import the backend: ``_CGNAT``, ``_V4_IN_V6``,
``public_address``, ``_routable`` and ``connection_order`` below are safe_fetch's code, copied verbatim, and
backend/tests/test_mcp_llm_target_ssrf.py and tests/test_scan_target_egress.py fail when a copy differs. Standard
library only.

* only http:// and https:// URLs with a host;
* every address a host resolves to must be public: not private, loopback, link-local (169.254.169.254, the cloud
  metadata service), CGNAT, unique-local, site-local, multicast, reserved, or an IPv4-mapped or translated form of
  one. One refused address refuses the host: DNS may hand it out later. No allowlist: the product has no documented
  setting that opens private addresses to MCP or LLM scans;
* ``TargetGuard`` pins every connection to checked addresses: a host is resolved once and its answer is used, as
  checked, for ``PIN_SECONDS``, so an answer that changes after the check is never followed. After that the host is
  resolved and checked again, so a long LLM scan follows a provider's address rotation (a load balancer's addresses
  change) the way it did when every request resolved the name, and every answer it uses was checked.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from typing import Callable
from urllib.parse import urlsplit

PIN_SECONDS = 60.0  # a load balancer's DNS answers live about this long (e.g. 60 s for an AWS ALB)

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# IPv6 prefixes that carry an IPv4 address to a translator or relay (NAT64, local NAT64, 6to4)
_V4_IN_V6 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"), ipaddress.ip_network("2002::/16"),
             ipaddress.ip_network("::ffff:0:0:0/96"), ipaddress.ip_network("::/96"))  # + IPv4-translated, -compatible


class TargetRefused(ConnectionRefusedError):
    """A connection a scan may not make: a private or reserved address, or a URL that is not http(s). Never made."""


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


def system_resolve(host: str, port: int) -> list[str]:
    """Every address the system resolver gives for ``host``, in its order. A name that does not resolve raises
    OSError (socket.gaierror): a network failure, reported as one, not a refusal."""
    return list(dict.fromkeys(str(info[4][0]) for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))


def _allowed(address: str) -> bool:
    try:
        return public_address(address)
    except ValueError:  # not an address at all
        return False


class TargetGuard:
    """The checked addresses of every host one scan connects to. Thread-safe; one guard per scan (or estimate)."""

    def __init__(self, resolve: Callable[[str, int], list[str]] = system_resolve,
                 clock: Callable[[], float] = time.monotonic):
        self._resolve = resolve
        self._clock = clock
        self._pinned: dict[str, tuple[float, tuple[str, ...]]] = {}  # host -> (checked until, addresses)
        self._lock = threading.Lock()
        self.refused: list[str] = []  # what was refused: a refusal in a client's background task may reach the
        # caller only as that task group's cancellation (mcp's streamable HTTP client)

    def addresses(self, host: str, port: int) -> tuple[str, ...]:
        """The checked addresses of ``host`` in the order to try them: the pinned answer while it is fresh, else a new
        answer, resolved and checked (every address). Raises TargetRefused, or OSError when the name does not
        resolve."""
        key = str(host or "").strip().strip("[]").lower()
        now = self._clock()
        with self._lock:
            pinned = self._pinned.get(key)
        if pinned is not None and now < pinned[0]:
            return pinned[1]
        found = list(dict.fromkeys(self._resolve(key, port)))
        if not found:
            raise OSError(f"{key[:100]} does not resolve")
        if not all(_allowed(address) for address in found):
            message = f"{key[:100]} resolves to a private or reserved address; only public addresses can be scanned"
            with self._lock:
                self.refused.append(message)
            raise TargetRefused(message)
        checked = tuple(connection_order(found, port))
        with self._lock:
            self._pinned[key] = (now + PIN_SECONDS, checked)
        return checked

    def check_url(self, url: str) -> tuple[str, ...]:
        """The checked addresses of ``url``'s host (http:// and https:// only). Raises TargetRefused or OSError."""
        try:
            parts = urlsplit(str(url or "").strip())
            port = parts.port
        except ValueError:
            raise TargetRefused("the URL is not valid (host or port)") from None
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            raise TargetRefused("only http:// and https:// URLs with a host name can be scanned")
        return self.addresses(parts.hostname, port or (443 if scheme == "https" else 80))

    def connect(self, host: str, port: int, timeout: float | None = None) -> socket.socket:
        """A TCP connection to ``host``:``port`` at the first of its checked addresses that accepts one. Raises
        TargetRefused, or the last connect error."""
        last: OSError | None = None
        for address in self.addresses(host, port):
            try:
                return socket.create_connection((address, port), timeout)
            except OSError as exc:
                last = exc
        raise last if last is not None else OSError(f"could not connect to {str(host)[:100]}:{port}")
