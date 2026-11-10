"""SSRF / host-allowlist checks for every DAST target: automatic profiles, CI runs and manual scans (estimate and start).

One rule for all of them (found on the local stack, round 5: manual estimate/start had no check at all, and the
DAST worker crawled http://backend:8080 and accepted http://169.254.169.254 on a customer's say-so):

* only http:// and https:// URLs;
* every URL's host must be in scope: a profile's ``allowed_hosts``, else the target URL's own host;
* the host name is resolved and EVERY address it resolves to is checked (a literal address is checked as it is):
  - cloud metadata / link-local, unspecified and multicast addresses are refused always, whatever is listed;
  - private, loopback, reserved and CGNAT addresses (Docker service names, localhost, 10.x, ...) are refused
    unless the operator lists the host name or a network containing the address in ``DAST_ALLOWED_PRIVATE`` on the
    ZeroShield server (comma-separated CIDRs and/or exact host names, the format of ``INTEGRATION_ALLOWED_PRIVATE``).
    A customer's ``allowed_hosts`` narrows the scope; it can never open a private address.

The DAST worker resolves the name again when it crawls; a name whose DNS answer changes between this check and the
crawl is not covered here (the worker drives a browser and cannot pin addresses).
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

from backend.utilities.cbom_sources.safe_fetch import PrivateAllowlist, parse_private_allowlist

ENV_ALLOWED_PRIVATE = "DAST_ALLOWED_PRIVATE"

# Cloud metadata / link-local — never allowed, even if listed on the profile or by the operator.
_ALWAYS_BLOCK_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::/32"),
)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class DastSsrfError(ValueError):
    """Target, login or additional URL is not allowed for DAST."""


def host_from_url(url: str) -> str:
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise DastSsrfError("URL is missing a host")
    return host


def operator_allowlist() -> PrivateAllowlist:
    """The operator's DAST_ALLOWED_PRIVATE (read on every call: tests and operators change it)."""
    return parse_private_allowlist(os.environ.get(ENV_ALLOWED_PRIVATE), ENV_ALLOWED_PRIVATE)


def _resolve_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise DastSsrfError(f"Could not resolve host {host}") from exc
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            ips.append(str(sockaddr[0]).split("%", 1)[0])
    return ips


def _normalise(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _ip_always_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = _normalise(ip)
    if ip.is_unspecified or ip.is_multicast:
        return True
    return any(ip.version == net.version and ip in net for net in _ALWAYS_BLOCK_NETWORKS)


def _ip_is_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = _normalise(ip)
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or (ip.version == 4 and ip in _CGNAT) or not ip.is_global)


def _operator_permits(rules: PrivateAllowlist, host: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if host in rules.hosts:
        return True
    ip = _normalise(ip)
    return any(ip.version == net.version and ip in net for net in rules.networks)


def _check_address(host: str, address: str, literal: bool, rules: PrivateAllowlist) -> None:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise DastSsrfError(f"Host {host} resolved to an invalid address") from exc
    verb = "is" if literal else f"resolves to {address}, which is"
    if _ip_always_blocked(ip):
        raise DastSsrfError(f"Host {host} {verb} a blocked metadata/link-local address and can never be scanned")
    if _ip_is_private(ip) and not _operator_permits(rules, host, ip):
        raise DastSsrfError(
            f"Host {host} {verb} a private address; an operator can allow it in {ENV_ALLOWED_PRIVATE} on the "
            "ZeroShield server")


def _check_scheme(url: str) -> None:
    if urlparse(str(url).strip()).scheme.lower() not in ("http", "https"):
        raise DastSsrfError(f"Only http:// and https:// URLs can be scanned ({str(url)[:80]})")


def assert_urls_allowed(urls: list[str], allowed_hosts: list[str]) -> None:
    allowed = {h.lower().strip().rstrip(".") for h in (allowed_hosts or []) if h and h.strip()}
    if not allowed:
        raise DastSsrfError("allowed_hosts is empty")
    rules = operator_allowlist()

    for raw in urls:
        if not raw or not str(raw).strip():
            continue
        _check_scheme(raw)
        host = host_from_url(raw)

        try:
            literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            literal = None

        if literal is not None:
            _check_address(host, str(literal), True, rules)
        if host not in allowed:
            raise DastSsrfError(f"Host {host} is not in allowlist")
        if literal is not None:
            continue
        addresses = _resolve_ips(host)
        if not addresses:
            raise DastSsrfError(f"Could not resolve host {host}")
        for address in addresses:
            _check_address(host, address, False, rules)


def dast_target_urls(target_url: str, login_url: str | None, additional_urls: list[str] | None) -> list[str]:
    """Every URL of a DAST run the worker will open."""
    return [u for u in [target_url, login_url or "", *(additional_urls or [])] if u and str(u).strip()]


def assert_manual_dast_allowed(target_url: str, login_url: str | None, additional_urls: list[str] | None) -> None:
    """A manual DAST scan (estimate or start) follows the profile rule with the default scope: the target's host."""
    _check_scheme(target_url)
    assert_urls_allowed(dast_target_urls(target_url, login_url, additional_urls), [host_from_url(target_url)])
