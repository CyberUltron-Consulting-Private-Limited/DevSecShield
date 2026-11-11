"""The DAST address rule: which addresses a DAST scan may connect to.

This file exists twice, byte for byte: backend/utilities/dast/address_rule.py (the ZeroShield server checks a URL
before it queues a scan) and RabbitMQ/dast_worker/helpers/net/address_rule.py (the DAST worker checks again when it
connects; its image cannot import the backend). backend/tests/test_dast_address_rule_shared.py fails when the two
differ. Standard library only.

* only http:// and https:// URLs;
* cloud metadata / link-local (169.254.0.0/16, fe80::/10, AWS fd00:ec2::/32), unspecified and multicast addresses are
  refused always, whatever the operator lists;
* private, loopback, reserved, CGNAT and other non-global addresses are refused unless the operator lists the host
  name or a network containing the address in DAST_ALLOWED_PRIVATE (comma-separated CIDRs and/or exact host names);
* a host name is checked through EVERY address it resolves to.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

ENV_ALLOWED_PRIVATE = "DAST_ALLOWED_PRIVATE"

# Cloud metadata / link-local: never allowed, even if the operator lists them.
_ALWAYS_BLOCK_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::/32"),
)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class DastSsrfError(ValueError):
    """A DAST target, login or additional URL, or an address a scan would connect to, is not allowed."""


@dataclass(frozen=True)
class OperatorAllowlist:
    """The operator's DAST_ALLOWED_PRIVATE: private networks and host names a DAST scan may reach."""
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    hosts: frozenset[str] = field(default_factory=frozenset)
    ignored: tuple[str, ...] = ()


def parse_allowlist(text: str | None) -> OperatorAllowlist:
    """CIDRs (or single addresses) and exact host names, comma-separated; anything else is ignored (and returned)."""
    networks, hosts, ignored = [], set(), []
    for raw in (text or "").split(","):
        entry = raw.strip().lower()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
            continue
        except ValueError:
            pass
        if _HOST_RE.match(entry.rstrip(".")):
            hosts.add(entry.rstrip("."))
        else:
            ignored.append(entry[:100])
    return OperatorAllowlist(tuple(networks), frozenset(hosts), tuple(ignored))


def operator_allowlist() -> OperatorAllowlist:
    """DAST_ALLOWED_PRIVATE as set now (read on every call: tests and operators change it)."""
    return parse_allowlist(os.environ.get(ENV_ALLOWED_PRIVATE))


def host_from_url(url: str) -> str:
    parsed = urlparse(str(url).strip())
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise DastSsrfError("URL is missing a host")
    return host


def check_scheme(url: str) -> None:
    if urlparse(str(url).strip()).scheme.lower() not in ("http", "https"):
        raise DastSsrfError(f"Only http:// and https:// URLs can be scanned ({str(url)[:80]})")


def literal_address(host: str) -> IPAddress | None:
    """The address when ``host`` is an IP literal (brackets and an IPv6 zone are dropped), else None."""
    try:
        return ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return None


def normalise(ip: IPAddress) -> IPAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def always_blocked(ip: IPAddress) -> bool:
    ip = normalise(ip)
    if ip.is_unspecified or ip.is_multicast:
        return True
    return any(ip.version == net.version and ip in net for net in _ALWAYS_BLOCK_NETWORKS)


def is_private(ip: IPAddress) -> bool:
    ip = normalise(ip)
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or (ip.version == 4 and ip in _CGNAT) or not ip.is_global)


def operator_permits(rules: OperatorAllowlist, host: str, ip: IPAddress) -> bool:
    if host in rules.hosts:
        return True
    ip = normalise(ip)
    return any(ip.version == net.version and ip in net for net in rules.networks)


def check_address(host: str, address: str, literal: bool, rules: OperatorAllowlist) -> None:
    """Raise DastSsrfError unless ``host`` may be scanned at ``address``."""
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError as exc:
        raise DastSsrfError(f"Host {host} resolved to an invalid address") from exc
    verb = "is" if literal else f"resolves to {address}, which is"
    if always_blocked(ip):
        raise DastSsrfError(f"Host {host} {verb} a blocked metadata/link-local address and can never be scanned")
    if is_private(ip) and not operator_permits(rules, host, ip):
        raise DastSsrfError(
            f"Host {host} {verb} a private address; an operator can allow it in {ENV_ALLOWED_PRIVATE} on the "
            "ZeroShield server")


def system_resolve(host: str) -> list[str]:
    """Every address the system resolver gives for ``host``, in its order."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise DastSsrfError(f"Could not resolve host {host}") from exc
    return [str(info[4][0]).split("%", 1)[0] for info in infos if info[4]]


def checked_addresses(host: str, rules: OperatorAllowlist, resolve: Callable[[str], list[str]]) -> list[str]:
    """The addresses ``host`` may be scanned at: the literal itself, or every address the name resolves to (each one
    checked; one refused address refuses the host). Raises DastSsrfError."""
    literal = literal_address(host)
    if literal is not None:
        check_address(host, str(literal), True, rules)
        return [str(literal)]
    addresses = list(dict.fromkeys(resolve(host)))
    if not addresses:
        raise DastSsrfError(f"Could not resolve host {host}")
    for address in addresses:
        check_address(host, address, False, rules)
    return addresses
