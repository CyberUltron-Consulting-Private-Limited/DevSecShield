"""Connect-time egress control for one DAST scan (DNS rebinding).

The backend checks a scan's URLs before it queues the scan (backend/utilities/dast/ssrf.py). The worker resolved the
names again when it crawled, so a name could answer a public address to that check and a private one (backend:8080,
169.254.169.254) to the worker. Now every connection the worker makes for a scan goes through one ``ScanEgress``:

* at scan start each in-scope host (the hosts of the target, login and additional URLs) is resolved ONCE and every
  address is checked with the same rule as the backend (address_rule.py, byte-identical; DAST_ALLOWED_PRIVATE on the
  worker). A host that fails stops the scan before any connection is made;
* a connection is only ever made to one of those checked addresses (pinned): a host name outside the scope, or an
  address that is not a checked address of an in-scope host, is refused and recorded (``refusals``) as a coverage gap;
* Python HTTP (the crawler, the security-headers check) uses ``ScanEgress.urlopen``: http/https only, no environment
  proxy, every connection (redirects included) pinned; TLS still verifies the original host name;
* nuclei and its Chromium reach the network only through ``EgressProxy``, a local SOCKS5 proxy owned by the scan that
  applies the same pinning to every CONNECT (host names and IP literals alike).
"""
from __future__ import annotations

import http.client
import ipaddress
import select
import socket
import socketserver
import threading
import urllib.request
from typing import Callable

from rich.console import Console

from helpers.net.address_rule import (
    DastSsrfError,
    OperatorAllowlist,
    check_scheme,
    checked_addresses,
    host_from_url,
    literal_address,
    normalise,
    operator_allowlist,
    system_resolve,
)

console = Console(markup=False)

_MAX_RECORDED_REFUSALS = 50


class EgressRefused(ConnectionRefusedError):
    """A scan connection to a host or address outside the scan's checked scope."""


def _host_key(host: str) -> str:
    return str(host or "").strip().strip("[]").lower().rstrip(".")


class ScanEgress:
    """The checked, pinned network scope of one DAST scan."""

    def __init__(
        self,
        urls: list[str],
        *,
        rules: OperatorAllowlist | None = None,
        resolve: Callable[[str], list[str]] = system_resolve,
    ):
        self.rules = rules if rules is not None else operator_allowlist()
        self.pinned: dict[str, tuple[str, ...]] = {}
        for url in urls:
            if not url or not str(url).strip():
                continue
            check_scheme(url)
            host = _host_key(host_from_url(url))
            if host not in self.pinned:
                self.pinned[host] = tuple(checked_addresses(host, self.rules, resolve))
        if not self.pinned:
            raise DastSsrfError("The scan has no URL to connect to")
        self._addresses = frozenset(str(normalise(ipaddress.ip_address(a))) for v in self.pinned.values() for a in v)
        self._lock = threading.Lock()
        self.refusals: list[dict] = []
        self.refusal_count = 0

    # ------------------------------------------------------------------ policy
    def addresses_for(self, host: str) -> tuple[str, ...]:
        """The checked addresses a connection to ``host`` may use. Raises EgressRefused."""
        key = _host_key(host)
        if key in self.pinned:
            return self.pinned[key]
        literal = literal_address(key)
        if literal is not None and str(normalise(literal)) in self._addresses:
            return (str(literal),)
        reason = ("is not a checked address of this scan's hosts" if literal is not None
                  else "is not in this scan's scope")
        self._record(key, reason)
        raise EgressRefused(f"DAST egress refused: {key} {reason}")

    def _record(self, destination: str, reason: str) -> None:
        with self._lock:
            self.refusal_count += 1
            entry = {"destination": destination[:200], "reason": reason}
            if len(self.refusals) < _MAX_RECORDED_REFUSALS and entry not in self.refusals:
                self.refusals.append(entry)
        console.print(f"DAST egress refused: {destination[:200]} ({reason})", style="bold red")

    def connect(self, host: str, port: int, timeout: float | None = None) -> socket.socket:
        """A TCP connection to ``host``:``port`` at one of its checked addresses (never re-resolved)."""
        last: OSError | None = None
        for address in self.addresses_for(host):
            try:
                return socket.create_connection((address, int(port)), timeout=timeout)
            except OSError as exc:
                last = exc
        raise last or OSError(f"Could not connect to {host}:{port}")

    def metadata(self) -> dict:
        """What the scan could not reach because of the scope (empty when nothing was refused)."""
        with self._lock:
            if not self.refusal_count:
                return {}
            return {"refused_connections": self.refusal_count, "refused": list(self.refusals)}

    # ------------------------------------------------------------- Python HTTP
    def opener(self) -> urllib.request.OpenerDirector:
        """A urllib opener for http/https only; every connection, redirects included, is pinned. No env proxy, no
        ftp/file/data handlers (urllib's default opener would follow a redirect to ftp:// unchecked)."""
        opener = urllib.request.OpenerDirector()
        for handler in (
            urllib.request.ProxyHandler({}),
            urllib.request.UnknownHandler(),
            _PinnedHTTPHandler(self),
            _PinnedHTTPSHandler(self),
            urllib.request.HTTPDefaultErrorHandler(),
            urllib.request.HTTPRedirectHandler(),
            urllib.request.HTTPErrorProcessor(),
        ):
            opener.add_handler(handler)
        return opener

    def urlopen(self, request: urllib.request.Request | str, timeout: float = 15):
        return self.opener().open(request, timeout=timeout)


def _pinned_create_connection(egress: ScanEgress):
    def create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        host, port = address
        sock_timeout = None if timeout is socket._GLOBAL_DEFAULT_TIMEOUT else timeout
        return egress.connect(host, port, sock_timeout)
    return create_connection


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, egress: ScanEgress, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _pinned_create_connection(egress)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS to the pinned address; SNI and certificate checks use the URL's host name (http.client does that)."""

    def __init__(self, *args, egress: ScanEgress, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _pinned_create_connection(egress)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, egress: ScanEgress):
        super().__init__()
        self._egress = egress

    def http_open(self, req):
        return self.do_open(lambda host, **kw: _PinnedHTTPConnection(host, egress=self._egress, **kw), req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, egress: ScanEgress):
        super().__init__()
        self._egress = egress

    def https_open(self, req):
        return self.do_open(lambda host, **kw: _PinnedHTTPSConnection(host, egress=self._egress, **kw), req,
                            context=self._context)


# --------------------------------------------------------------------- SOCKS5
_SOCKS_OK, _SOCKS_FAIL, _SOCKS_NOT_ALLOWED, _SOCKS_REFUSED = 0, 1, 2, 5
_SOCKS_BAD_COMMAND, _SOCKS_BAD_ADDRESS = 7, 8


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("client closed")
        data += chunk
    return data


def _reply(conn: socket.socket, code: int) -> None:
    conn.sendall(bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0]))


def _pipe(a: socket.socket, b: socket.socket, idle_seconds: float) -> None:
    open_ends = {a: b, b: a}
    for s in (a, b):
        s.setblocking(True)
        s.settimeout(None)
    while open_ends:
        readable, _, _ = select.select(list(open_ends), [], [], idle_seconds)
        if not readable:
            return
        for src in readable:
            dst = open_ends.get(src)
            if dst is None:
                continue
            try:
                data = src.recv(65536)
            except OSError:
                data = b""
            if data:
                try:
                    dst.sendall(data)
                except OSError:
                    return
                continue
            open_ends.pop(src, None)
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    block_on_close = False


class EgressProxy:
    """A local SOCKS5 proxy (no auth, CONNECT only) for nuclei and its Chromium, owned by one scan. Each CONNECT goes
    to a checked address of an in-scope host or is refused (reply 0x02)."""

    def __init__(self, egress: ScanEgress, connect_timeout: float = 15.0, idle_seconds: float = 300.0):
        self.egress = egress
        egress_ref = egress

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: D401 - socketserver API
                conn: socket.socket = self.request
                upstream = None
                try:
                    conn.settimeout(connect_timeout)
                    version, n_methods = _recv_exact(conn, 2)
                    if version != 5:
                        return
                    if 0 not in _recv_exact(conn, n_methods):
                        conn.sendall(b"\x05\xff")
                        return
                    conn.sendall(b"\x05\x00")
                    _, command, _, atyp = _recv_exact(conn, 4)
                    if atyp == 1:
                        host = socket.inet_ntop(socket.AF_INET, _recv_exact(conn, 4))
                    elif atyp == 4:
                        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(conn, 16))
                    elif atyp == 3:
                        host = _recv_exact(conn, _recv_exact(conn, 1)[0]).decode("ascii", "replace")
                    else:
                        _reply(conn, _SOCKS_BAD_ADDRESS)
                        return
                    port = int.from_bytes(_recv_exact(conn, 2), "big")
                    if command != 1:
                        _reply(conn, _SOCKS_BAD_COMMAND)
                        return
                    try:
                        upstream = egress_ref.connect(host, port, connect_timeout)
                    except EgressRefused:
                        _reply(conn, _SOCKS_NOT_ALLOWED)
                        return
                    except OSError:
                        _reply(conn, _SOCKS_REFUSED)
                        return
                    _reply(conn, _SOCKS_OK)
                    _pipe(conn, upstream, idle_seconds)
                except (OSError, ValueError, IndexError):
                    return
                finally:
                    if upstream is not None:
                        upstream.close()

        self._server = _Server(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="dast-egress-proxy", daemon=True)
        self._thread.start()
        self.url = f"socks5://127.0.0.1:{self._server.server_address[1]}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "EgressProxy":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
