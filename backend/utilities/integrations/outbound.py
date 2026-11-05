"""Every outbound connection an integration makes (HTTPS, syslog over TCP / TLS / UDP) goes through this module.

The destination is customer-supplied, so each connection is an SSRF risk. The rules:

* the host name is resolved ONCE per connection and every address it resolves to is checked; the connection then goes
  to the addresses that were checked (pinned), tried in turn with those this host can route first, so a DNS answer
  cannot change between the check and the connect and a dual-stack name works in an IPv4-only container;
* loopback, link-local (169.254.169.254, the cloud metadata service), CGNAT (100.64.0.0/10), unspecified, multicast,
  reserved, AWS's IPv6 metadata range (fd00:ec2::/32), IETF protocol assignments (192.0.0.0/24), "this network"
  (0.0.0.0/8) and IPv4 carried in IPv6 for a translator are refused ALWAYS, whatever the operator lists;
* private addresses (RFC 1918, unique-local and site-local IPv6, other non-global ranges) are refused unless the
  operator lists them in ``INTEGRATION_ALLOWED_PRIVATE`` (comma-separated CIDRs and/or exact host names, the same
  format as ``CBOM_IDP_ALLOWED_PRIVATE``): an on-premises Splunk, syslog collector or ServiceNow MID endpoint;
* HTTP is https only, TLS 1.2+, certificates are always verified (a destination may add its own CA bundle, ``ca_pem``,
  next to the system store and ``CBOM_EXTRA_CA_FILE``); redirects are never followed; no proxy from the environment
  (a proxy would resolve the name itself and bypass the pin);
* connect 5 s, each read 10 s, and the whole request 20 s (a timer shuts the socket, so a server that drips bytes
  cannot hold the dispatcher); at most 64 KB of a response is read, only to parse a status or an id;
* error messages are short and safe to show (status code and a phrase); a response body is never returned to a
  browser.
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from backend.utilities.cbom_sources.common import log
from backend.utilities.cbom_sources.safe_fetch import (
    PrivateAllowlist,
    always_blocked,
    connect_first,
    connection_order,
    parse_private_allowlist,
    public_address,
)

ENV_ALLOWED_PRIVATE = "INTEGRATION_ALLOWED_PRIVATE"
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
TOTAL_TIMEOUT = 20.0
MAX_RESPONSE = 64 * 1024
_EXTRA_BLOCKED = (ipaddress.ip_network("0.0.0.0/8"), ipaddress.ip_network("192.0.0.0/24"))


class Refused(Exception):
    """The destination is not allowed (policy). ``str(err)`` is safe to show. Retrying cannot help until the
    configuration or the operator's allowlist changes."""


class TransportError(Exception):
    """DNS, connect, TLS, timeout or a broken connection. ``str(err)`` is safe to show."""


@dataclass
class Response:
    status: int
    reason: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""  # at most MAX_RESPONSE bytes; parsed for an id or a status, never shown to a browser

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


def allowlist() -> PrivateAllowlist:
    """The operator's INTEGRATION_ALLOWED_PRIVATE (read on every call: tests and operators change it)."""
    return parse_private_allowlist(os.environ.get(ENV_ALLOWED_PRIVATE), ENV_ALLOWED_PRIVATE)


def _never(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if always_blocked(str(ip)):
        return True
    return any(ip.version == net.version and ip in net for net in _EXTRA_BLOCKED)


def check_address(host: str, address: str, rules: PrivateAllowlist | None = None) -> str | None:
    """Why ``address`` (what ``host`` resolved to) is refused, or None when it may be used."""
    if _never(address):
        return f"{host} resolves to a loopback, link-local, metadata or reserved address, which is never allowed"
    if public_address(address):
        return None
    rule = (rules or allowlist()).permits(host, address)
    if rule is None:
        return (f"{host} resolves to a private address; an operator can allow it in {ENV_ALLOWED_PRIVATE} "
                "on the ZeroShield server")
    return None


def resolve(host: str, port: int, *, kind: int = socket.SOCK_STREAM) -> list[str]:
    """Resolve once and check every address; return them all in the order to try (``connection_order``: the
    resolver's order, addresses this host can route first). A connection tries them in turn, each pinned, so a
    dual-stack name whose IPv6 address an IPv4-only container cannot reach still works. Raises Refused or
    TransportError."""
    name = (host or "").strip().rstrip(".")
    if not name:
        raise Refused("no host")
    if not 1 <= int(port) <= 65535:
        raise Refused("port must be 1-65535")
    try:
        addresses = [str(ipaddress.ip_address(name.strip("[]")))]  # an IP literal needs no lookup
    except ValueError:
        try:
            infos = socket.getaddrinfo(name, port, type=kind)
        except (socket.gaierror, UnicodeError) as exc:
            raise TransportError(f"{name} does not resolve") from exc
        addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses:
        raise TransportError(f"{name} does not resolve")
    rules = allowlist()
    for address in addresses:
        why = check_address(name, address, rules)
        if why:
            log("integration destination REFUSED", host=name[:100], address=address)
            raise Refused(why)
    for address in addresses:
        if not public_address(address):
            log("integration private destination allowed", host=name[:100], address=address, rule=ENV_ALLOWED_PRIVATE)
    return connection_order(addresses, int(port))


def tls_context(ca_pem: str | None = None) -> ssl.SSLContext:
    """System trust store (+ CBOM_EXTRA_CA_FILE) plus the destination's own CA, TLS 1.2+, hostname checked."""
    from backend.utilities.cbom_sources.safe_fetch import _context

    ctx = _context()
    if ca_pem and ca_pem.strip():
        ctx.load_verify_locations(cadata=ca_pem)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _tls_reason(exc: ssl.SSLError) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"TLS certificate is not trusted ({exc.verify_message or 'verification failed'})"
    return f"TLS handshake failed ({exc.reason or type(exc).__name__})"


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, addresses: list[str], port: int, context: ssl.SSLContext, deadline: float):
        super().__init__(host, port, timeout=READ_TIMEOUT, context=context)
        self._addresses = addresses
        self._deadline = deadline
        self.fds: list[int] = []

    def connect(self) -> None:  # connect to a checked address (each in turn), verify the certificate for the name
        sock = connect_first(self._addresses, self.port, CONNECT_TIMEOUT, self._deadline)
        sock.settimeout(READ_TIMEOUT)
        self.fds.append(sock.fileno())  # the deadline timer can shut it even during the TLS handshake
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # type: ignore[attr-defined]


def _shutdown_fd(fd: int) -> None:
    """Shut a connection down from another thread. Wrapping a socket in TLS detaches the original socket object, so
    the shutdown goes through a duplicate of its file descriptor (shutdown acts on the connection, not the fd)."""
    try:
        dup = socket.socket(fileno=os.dup(fd))
    except OSError:
        return
    try:
        dup.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        dup.close()


def _abort(fds: list[int]) -> None:
    for fd in list(fds):
        _shutdown_fd(fd)


def check_https_url(url: str) -> tuple[str, int, str]:
    """(host, port, path+query) of an https URL without user info. Raises Refused."""
    parts = urlsplit(url or "")
    if parts.scheme != "https" or not parts.hostname:
        raise Refused("only https:// URLs are used")
    if parts.username or parts.password:
        raise Refused("the URL must not contain a user name or password")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise Refused("the URL has an invalid port") from exc
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return parts.hostname, port, path


def request(method: str, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None,
            ca_pem: str | None = None, total: float = TOTAL_TIMEOUT, max_body: int = MAX_RESPONSE) -> Response:
    """One HTTPS request to a checked, pinned address. Redirects are returned as they are (never followed).
    At most ``max_body`` bytes of the response are read (64 KB unless a caller reads data, e.g. a CMDB page)."""
    host, port, path = check_https_url(url)
    addresses = resolve(host, port)
    deadline = time.monotonic() + total
    conn = _PinnedHTTPS(host, addresses, port, tls_context(ca_pem), deadline)
    timer = threading.Timer(total, _abort, (conn.fds,))
    timer.daemon = True
    timer.start()
    sent = {"User-Agent": "ZeroShield-Integrations/1.0", "Accept-Encoding": "identity", "Connection": "close",
            **(headers or {})}
    try:
        conn.request(method, path, body=body, headers=sent)
        resp = conn.getresponse()
        data = bytearray()
        while len(data) < max_body:
            if time.monotonic() >= deadline:
                raise TransportError(f"{host} did not finish the response within {int(total)} s")
            chunk = resp.read1(min(65536, max_body - len(data)))
            if not chunk:
                break
            data += chunk
        return Response(resp.status, resp.reason or "", {k.lower(): v for k, v in resp.getheaders()}, bytes(data))
    except ssl.SSLError as exc:
        if time.monotonic() >= deadline:
            raise TransportError(f"{host} did not answer within {int(total)} s") from exc
        raise TransportError(f"{host}: {_tls_reason(exc)}") from exc
    except (OSError, http.client.HTTPException) as exc:
        if time.monotonic() >= deadline:
            raise TransportError(f"{host} did not answer within {int(total)} s") from exc
        raise TransportError(f"{host}:{port} {_socket_reason(exc)}") from exc
    finally:
        timer.cancel()
        conn.close()


def _socket_reason(exc: BaseException) -> str:
    if isinstance(exc, ConnectionRefusedError):
        return "refused the connection"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timed out"
    if isinstance(exc, ConnectionResetError):
        return "reset the connection"
    return f"connection failed ({type(exc).__name__})"


def _close_reason(exc: OSError) -> str:
    if isinstance(exc, ssl.SSLError):
        return f"ended TLS with an error ({exc.reason or type(exc).__name__})"
    if isinstance(exc, ConnectionError):
        return "reset the connection"
    return f"closed the connection abnormally ({type(exc).__name__})"


def send_stream(host: str, port: int, frames: list[bytes], *, tls: bool, ca_pem: str | None = None,
                total: float = TOTAL_TIMEOUT) -> int:
    """Write ``frames`` on one TCP (or TLS) connection to a checked, pinned address, then close it gracefully.
    Returns the number of frames written. Raises Refused or TransportError (nothing is known to be delivered then),
    including when the receiver resets the connection while it is being closed: a reset discards unread data."""
    addresses = resolve(host, port)
    deadline = time.monotonic() + total
    sock: socket.socket | None = None
    fds: list[int] = []
    timer = threading.Timer(total, _abort, (fds,))  # deadline: a stalled handshake or write returns at once
    timer.daemon = True
    timer.start()
    try:
        raw = connect_first(addresses, port, CONNECT_TIMEOUT, deadline)
        raw.settimeout(READ_TIMEOUT)
        fds.append(raw.fileno())
        sock = tls_context(ca_pem).wrap_socket(raw, server_hostname=host) if tls else raw
        for frame in frames:
            if time.monotonic() >= deadline:
                raise TransportError(f"{host}:{port} took longer than {int(total)} s")
            sock.sendall(frame)
        # graceful close: the peer sees close_notify (TLS) and FIN after the last frame; wait briefly for its side
        try:
            if tls:
                sock = sock.unwrap()  # type: ignore[union-attr]
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(2.0)
            while sock.recv(4096):
                pass
        except (TimeoutError, ssl.SSLEOFError):
            # still open after the wait, or (TLS) closed after reading our close_notify without answering it (RFC 5425
            # 4.4 asks for an answer): everything was written and the receiver read up to the end
            pass
        except OSError as exc:
            # a reset (or a TLS alert) while closing: the receiver discarded what it had not read, so nothing in
            # this batch is known to be delivered; the queue retries it
            raise TransportError(f"{host}:{port} {_close_reason(exc)} before the batch was confirmed") from exc
        return len(frames)
    except ssl.SSLError as exc:
        if time.monotonic() >= deadline:
            raise TransportError(f"{host}:{port} took longer than {int(total)} s") from exc
        raise TransportError(f"{host}: {_tls_reason(exc)}") from exc
    except TransportError:
        raise
    except OSError as exc:
        if time.monotonic() >= deadline:
            raise TransportError(f"{host}:{port} took longer than {int(total)} s") from exc
        raise TransportError(f"{host}:{port} {_socket_reason(exc)}") from exc
    finally:
        timer.cancel()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def send_datagrams(host: str, port: int, datagrams: list[bytes]) -> int:
    """One UDP datagram per message to a checked, pinned address (RFC 5426: no delivery confirmation exists). The
    checked addresses are tried in turn until one takes the first datagram (an unroutable family fails at once)."""
    last: OSError | None = None
    for address in resolve(host, port, kind=socket.SOCK_DGRAM):
        family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
        sent = 0
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(READ_TIMEOUT)
                for datagram in datagrams:
                    sock.sendto(datagram, (address, port))
                    sent += 1
            return len(datagrams)
        except OSError as exc:
            if sent:  # part of the batch went out: never send it again to a second address
                raise TransportError(f"{host}:{port} {_socket_reason(exc)}") from exc
            last = exc
    raise TransportError(f"{host}:{port} {_socket_reason(last or OSError())}") from last
