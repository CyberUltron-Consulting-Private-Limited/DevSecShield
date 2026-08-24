"""SSRF / host-allowlist checks for automatic DAST targets."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Cloud metadata / link-local — never allowed, even if listed on the profile.
_ALWAYS_BLOCK_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)


class DastSsrfError(ValueError):
    """Target or login URL is not allowed for automatic DAST."""


def host_from_url(url: str) -> str:
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if not host:
        raise DastSsrfError("URL is missing a host")
    return host


def _resolve_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise DastSsrfError(f"Could not resolve host {host}") from exc
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            ips.append(sockaddr[0])
    return ips


def _ip_always_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for net in _ALWAYS_BLOCK_NETWORKS:
        try:
            if ip in net:
                return True
        except TypeError:
            continue
    return False


def _ip_is_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def assert_urls_allowed(urls: list[str], allowed_hosts: list[str]) -> None:
    allowed = {h.lower().strip() for h in (allowed_hosts or []) if h and h.strip()}
    if not allowed:
        raise DastSsrfError("allowed_hosts is empty")

    for raw in urls:
        if not raw or not str(raw).strip():
            continue
        host = host_from_url(raw)

        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None

        if literal is not None and _ip_always_blocked(literal):
            raise DastSsrfError(f"Host {host} is a blocked metadata/link-local address")

        if host not in allowed:
            if literal is not None and _ip_is_private(literal):
                raise DastSsrfError(f"Host {host} is a private address")
            raise DastSsrfError(f"Host {host} is not in allowlist")

        if literal is not None:
            continue

        for ip_str in _resolve_ips(host):
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if _ip_always_blocked(ip):
                raise DastSsrfError(f"Host {host} resolved to a blocked metadata/link-local address")
            if _ip_is_private(ip) and host not in allowed:
                raise DastSsrfError(f"Host {host} resolved to a private address")
