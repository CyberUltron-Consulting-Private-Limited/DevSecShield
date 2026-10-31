"""HTTPS GET of a customer-supplied URL from ZeroShield's servers, without SSRF.

* https only, port 443 or 1024-65535, no user info in the URL;
* every address the name resolves to must be public (not private, loopback, link-local, CGNAT,
  unique-local, multicast, reserved, or an IPv4-mapped form of one), and the connection goes to the
  address that was checked, so a DNS answer cannot change between the check and the fetch;
* no proxy from the environment; at most 3 redirects, each checked the same way;
* 1 MB body cap, 10 s timeout, identity encoding only.

``CBOM_LAB_ALLOW_PRIVATE_FETCH=1`` allows private addresses for a local test lab only (it is logged
loudly), and ``CBOM_LAB_CA_FILE`` adds a lab CA to the trust store.
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from backend.utilities.cbom_sources.common import log

MAX_BYTES = 1024 * 1024
TIMEOUT = 10.0
MAX_REDIRECTS = 3
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class FetchError(Exception):
    """``str(err)`` is safe to show to the customer."""


@dataclass
class Fetched:
    url: str
    status: int
    content_type: str
    body: bytes


def _lab_private_allowed() -> bool:
    allowed = os.environ.get("CBOM_LAB_ALLOW_PRIVATE_FETCH") == "1"
    if allowed:
        log("WARNING lab_mode private_fetch=allowed (never set CBOM_LAB_ALLOW_PRIVATE_FETCH in production)")
    return allowed


def public_address(text: str) -> bool:
    ip = ipaddress.ip_address(text)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return False
    return bool(ip.is_global) and not ip.is_multicast


def lab_address(text: str) -> bool:
    """Lab mode widens the rule to RFC 1918 and unique-local addresses only: loopback, link-local (the
    cloud metadata service), CGNAT and unspecified addresses stay blocked even in a lab."""
    ip = ipaddress.ip_address(text)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        return ip in ipaddress.ip_network("10.0.0.0/8") or ip in ipaddress.ip_network("172.16.0.0/12") \
            or ip in ipaddress.ip_network("192.168.0.0/16")
    return ip in ipaddress.ip_network("fc00::/7") and not str(ip).startswith("fd00:ec2:")


def _resolve(host: str, port: int, allow_private: bool) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError(f"{host} does not resolve") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise FetchError(f"{host} does not resolve")
    allowed = (lambda a: public_address(a) or lab_address(a)) if allow_private else public_address
    if any(not allowed(a) for a in addresses):
        raise FetchError(f"{host} resolves to a private or reserved address; only public metadata URLs can be read")
    return addresses[0]


def _context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    lab_ca = os.environ.get("CBOM_LAB_CA_FILE")
    if lab_ca and os.path.isfile(lab_ca):
        ctx.load_verify_locations(cafile=lab_ca)
    return ctx


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, context: ssl.SSLContext):
        super().__init__(host, port, timeout=TIMEOUT, context=context)
        self._address = address

    def connect(self) -> None:  # connect to the checked address, verify the certificate for the name
        sock = socket.create_connection((self._address, self.port), TIMEOUT)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # type: ignore[attr-defined]


def fetch(url: str, *, accept: str = "application/json") -> Fetched:
    allow_private = _lab_private_allowed()
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        if parts.scheme != "https" or not parts.hostname:
            raise FetchError("only https:// URLs can be read")
        if parts.username or parts.password:
            raise FetchError("URL must not contain a user name or password")
        port = parts.port or 443
        if port != 443 and port < 1024:
            raise FetchError("URL port must be 443 or above 1023")
        address = _resolve(parts.hostname, port, allow_private)
        conn = _PinnedHTTPS(parts.hostname, address, port, _context())
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        try:
            conn.request("GET", path, headers={"Accept": accept, "Accept-Encoding": "identity",
                                               "User-Agent": "ZeroShield-CBOM/1.0", "Host": parts.netloc})
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location")
                if not location:
                    raise FetchError(f"redirect without a Location from {parts.hostname}")
                current = urljoin(current, location)
                continue
            body = resp.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise FetchError("the document is larger than 1 MB")
            return Fetched(current, resp.status, resp.getheader("Content-Type") or "", body)
        except ssl.SSLCertVerificationError as exc:
            raise FetchError(f"TLS certificate of {parts.hostname} is not trusted ({exc.verify_message})") from exc
        except (OSError, http.client.HTTPException) as exc:
            if isinstance(exc, FetchError):
                raise
            raise FetchError(f"could not read {parts.hostname}: {type(exc).__name__}") from exc
        finally:
            conn.close()
    raise FetchError("too many redirects")
