"""HTTPS GET of a customer-supplied URL from ZeroShield's servers, without SSRF.

* https only, port 443 or 1024-65535, no user info in the URL;
* every address the name resolves to must be public (not private, loopback, link-local, CGNAT,
  unique-local, multicast, reserved, or an IPv4-mapped form of one), and the connection goes to the
  address that was checked, so a DNS answer cannot change between the check and the fetch;
* no proxy from the environment; at most 3 redirects, each checked the same way;
* 1 MB body cap, 10 s per read and 30 s for the whole fetch, identity encoding only.

Air-gapped installs whose identity provider is on a private network: the operator lists the IdP in
``CBOM_IDP_ALLOWED_PRIVATE`` (comma-separated CIDRs and/or exact host names). Only callers that pass
``private_allowlist`` (the IdP collector) use it; a private address is then accepted when it is in a listed CIDR or
the URL's host name is listed. Loopback, link-local (the cloud metadata service), CGNAT, unspecified, multicast,
reserved, AWS's fd00:ec2::/32 and IPv4-in-IPv6 translation addresses stay blocked whatever is listed.
``CBOM_EXTRA_CA_FILE`` adds a PEM bundle (a private CA) to the trust store; ``CBOM_LAB_CA_FILE`` is its old name and
still works.

``CBOM_LAB_ALLOW_PRIVATE_FETCH=1`` allows RFC 1918 / unique-local addresses for a local test lab only (it is logged
loudly).
"""
from __future__ import annotations

import functools
import http.client
import ipaddress
import os
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from backend.utilities.cbom_sources.common import log

MAX_BYTES = 1024 * 1024
TIMEOUT = 10.0  # per connect / read
TOTAL_TIMEOUT = 30.0  # the whole fetch, redirects included: a server dripping bytes cannot hold the worker
MAX_REDIRECTS = 3
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# IPv6 prefixes that carry an IPv4 address to a translator or relay (NAT64, local NAT64, 6to4)
_V4_IN_V6 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"), ipaddress.ip_network("2002::/16"),
             ipaddress.ip_network("::ffff:0:0:0/96"), ipaddress.ip_network("::/96"))  # + IPv4-translated, -compatible


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
    if isinstance(ip, ipaddress.IPv6Address) and any(ip in net for net in _V4_IN_V6):
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


_CGNAT_AND_AWS = (_CGNAT, ipaddress.ip_network("fd00:ec2::/32"))
_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def always_blocked(text: str) -> bool:
    """Addresses no allowlist can open: loopback, link-local (169.254.169.254), CGNAT, unspecified, multicast,
    reserved, AWS's fd00:ec2::/32 (IPv6 metadata) and IPv4 carried in IPv6 for a translator or relay."""
    ip = ipaddress.ip_address(text)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return True
    if any(ip.version == net.version and ip in net for net in _CGNAT_AND_AWS):
        return True
    return isinstance(ip, ipaddress.IPv6Address) and any(ip in net for net in _V4_IN_V6)


@dataclass(frozen=True)
class PrivateAllowlist:
    """Private addresses an operator opened for one purpose (CBOM_IDP_ALLOWED_PRIVATE for IdP metadata)."""
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    hosts: frozenset[str] = field(default_factory=frozenset)
    source: str = ""

    def permits(self, host: str, address: str) -> str | None:
        """The rule that lets ``host`` at private ``address`` be read, or None."""
        if always_blocked(address):
            return None
        if host.lower().rstrip(".") in self.hosts:
            return "host"
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        for net in self.networks:
            if ip.version == net.version and ip in net:
                return f"cidr {net}"
        return None


@functools.lru_cache(maxsize=8)
def parse_private_allowlist(text: str | None, source: str) -> PrivateAllowlist:
    """CIDRs (or single addresses) and exact host names, comma-separated. Anything else is ignored, loudly."""
    networks, hosts = [], set()
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
            log("WARNING private_allowlist entry_ignored", source=source, entry=repr(entry[:100]))
    return PrivateAllowlist(tuple(networks), frozenset(hosts), source)


def idp_private_allowlist() -> PrivateAllowlist:
    """The operator's CBOM_IDP_ALLOWED_PRIVATE, for the identity-provider metadata fetches only."""
    return parse_private_allowlist(os.environ.get("CBOM_IDP_ALLOWED_PRIVATE"), "CBOM_IDP_ALLOWED_PRIVATE")


def _resolve(host: str, port: int, allow_private: bool, allowlist: PrivateAllowlist | None = None) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError(f"{host} does not resolve") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise FetchError(f"{host} does not resolve")
    for address in addresses:
        if public_address(address) or (allow_private and lab_address(address)):
            continue
        rule = allowlist.permits(host, address) if allowlist else None
        if rule is None:
            hint = f" (private IdP addresses can be allowed in {allowlist.source})" if allowlist and allowlist.source \
                and not always_blocked(address) else ""
            raise FetchError(f"{host} resolves to a private or reserved address; only public metadata URLs can be "
                             f"read{hint}")
        log("private fetch allowed", source=allowlist.source, host=host, address=address, rule=rule)
    return addresses[0]


_ca_warned: set[tuple[str, str]] = set()


def _context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    for name in ("CBOM_EXTRA_CA_FILE", "CBOM_LAB_CA_FILE"):  # the second is the old (lab) name of the first
        path = os.environ.get(name)
        if not path:
            continue
        if os.path.isfile(path):
            ctx.load_verify_locations(cafile=path)
        elif (name, path) not in _ca_warned:
            _ca_warned.add((name, path))
            log(f"WARNING {name} is set but is not a readable file; it is not trusted", path=path)
    return ctx


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, context: ssl.SSLContext):
        super().__init__(host, port, timeout=TIMEOUT, context=context)
        self._address = address

    def connect(self) -> None:  # connect to the checked address, verify the certificate for the name
        sock = socket.create_connection((self._address, self.port), TIMEOUT)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # type: ignore[attr-defined]


def _read_capped(resp: http.client.HTTPResponse, conn: http.client.HTTPConnection, deadline: float) -> bytes:
    body = bytearray()
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise FetchError(f"the server took longer than {int(TOTAL_TIMEOUT)} s to send the document")
        if conn.sock is not None:
            conn.sock.settimeout(min(TIMEOUT, left))
        chunk = resp.read1(min(65536, MAX_BYTES + 1 - len(body)))  # one socket read at most, then re-check
        if not chunk:
            return bytes(body)
        body += chunk
        if len(body) > MAX_BYTES:
            raise FetchError("the document is larger than 1 MB")


def _abort(conn: http.client.HTTPConnection) -> None:
    """Deadline reached: shut the socket so a blocked handshake or header read returns at once."""
    sock = conn.sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def fetch(url: str, *, accept: str = "application/json", private_allowlist: PrivateAllowlist | None = None) -> Fetched:
    """``private_allowlist`` opens the private addresses an operator listed for this caller's purpose (redirect hops
    are checked against it the same way); other callers stay public-only."""
    allow_private = _lab_private_allowed()
    current = url
    deadline = time.monotonic() + TOTAL_TIMEOUT
    for _hop in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        if parts.scheme != "https" or not parts.hostname:
            raise FetchError("only https:// URLs can be read")
        if parts.username or parts.password:
            raise FetchError("URL must not contain a user name or password")
        port = parts.port or 443
        if port != 443 and port < 1024:
            raise FetchError("URL port must be 443 or above 1023")
        address = _resolve(parts.hostname, port, allow_private, private_allowlist)
        conn = _PinnedHTTPS(parts.hostname, address, port, _context())
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        left = deadline - time.monotonic()
        if left <= 0:
            raise FetchError(f"the server took longer than {int(TOTAL_TIMEOUT)} s to send the document")
        # the per-read timeout alone lets a server drip handshake or header bytes for ever; this bounds the hop
        timer = threading.Timer(left, _abort, (conn,))
        timer.daemon = True
        timer.start()
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
            body = _read_capped(resp, conn, deadline)
            return Fetched(current, resp.status, resp.getheader("Content-Type") or "", body)
        except ssl.SSLCertVerificationError as exc:
            raise FetchError(f"TLS certificate of {parts.hostname} is not trusted ({exc.verify_message})") from exc
        except (OSError, http.client.HTTPException) as exc:
            if time.monotonic() >= deadline:
                raise FetchError(f"the server took longer than {int(TOTAL_TIMEOUT)} s to send the document") from exc
            raise FetchError(f"could not read {parts.hostname}: {type(exc).__name__}") from exc
        finally:
            timer.cancel()
            conn.close()
    raise FetchError("too many redirects")
