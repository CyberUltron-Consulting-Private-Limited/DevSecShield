"""Targets, the never-scan list and rate limits.

* Target lines (IP, CIDR, ``a-b`` range, hostname) are expanded lazily and de-duplicated by IP.
* A hostname is resolved once and the node connects only to an address it checked (no second lookup, so DNS
  rebinding cannot redirect it).  The never-scan list applies to the whole name: if the name, or ANY address it
  resolves to, is on the list, the name is skipped (a dual-stack host listed by its IPv4 address is not scanned
  over IPv6).  An IP literal is checked as itself; CIDR and ``a-b`` ranges are checked address by address.
* The never-scan list can change while a job runs (heartbeat); ``NeverScan.update`` swaps it atomically.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import weakref
import time
from dataclasses import dataclass
from typing import Iterator

MAX_EXPANDED = 262_144


class NeverScan:
    def __init__(self, lines: list[str] | None = None) -> None:
        self._lock = threading.Lock()
        self._nets: list[ipaddress._BaseNetwork] = []
        self._hosts: set[str] = set()
        self.update(lines or [])

    def update(self, lines: list[str]) -> None:
        nets: list[ipaddress._BaseNetwork] = []
        hosts: set[str] = set()
        for raw in lines or []:
            text = str(raw).strip()
            if not text:
                continue
            try:
                if "-" in text and "/" not in text and ":" not in text:
                    first, last = (ipaddress.ip_address(p.strip()) for p in text.split("-", 1))
                    nets.extend(ipaddress.summarize_address_range(first, last))
                else:
                    nets.append(ipaddress.ip_network(text, strict=False))
            except ValueError:
                hosts.add(text.lower().rstrip("."))
        with self._lock:
            self._nets, self._hosts = nets, hosts

    def blocks_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        with self._lock:
            return any(addr.version == n.version and addr in n for n in self._nets)

    def blocks_host(self, name: str) -> bool:
        with self._lock:
            return name.lower().rstrip(".") in self._hosts


@dataclass
class Target:
    label: str  # what the customer wrote (IP or hostname)
    ip: str | None  # checked address to connect to (None = could not resolve)
    error: str | None = None
    addresses: tuple[str, ...] = ()  # a hostname: every address it resolved to (all checked); an IP: empty


def resolve(name: str, timeout: float = 5.0) -> list[str]:
    """Resolve a hostname to unique addresses (IPv4 first).  Raises OSError on failure."""
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    finally:
        socket.setdefaulttimeout(None)
    out: list[str] = []
    for family, *_rest, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in out:
            out.append(ip)
    out.sort(key=lambda a: (":" in a, a))
    return out


# ----------------------------------------------------------------------------- the network gate
# Every connection a collector makes to a customer target goes through one of these, so the never-scan list is applied
# to the exact address that is connected to, at the moment of connecting (it can change while a job runs):
#   resolve_checked(host, never)        resolve once; refuse the name if it or ANY of its addresses is never-scan
#   checked_ip(ip, never)               re-check an address just before a driver (psycopg, paramiko ...) connects to it
#   checked_target(target, never)       re-check an expanded target: a name by every address it resolved to
#   connect(ip, port, never, timeout)   check + open the TCP socket to that address
#   udp_connect(ip, port, never, ...)   check + a connected UDP socket to that address (IKE)
#   http_client(url, ip, never, ...)    an httpx client pinned to the checked address (Host/SNI/certificate name kept)
# tests/test_network_gate.py fails when a collector module opens sockets or HTTP clients any other way.


class Blocked(Exception):
    """The target (name or address) is on the never-scan list, or ``what`` is a name and ``address``, one of the
    addresses it resolves to, is."""

    status = "skipped_never_scan"
    address: str | None = None

    def __init__(self, what: str, address: str | None = None) -> None:
        super().__init__(f"{what} resolves to {address}, which is on the never-scan list" if address
                         else f"{what} is on the never-scan list")
        self.what, self.address = what, address


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def checked_ip(ip: str, never: NeverScan) -> str:
    """The address itself, after checking it against the current never-scan list (raises Blocked)."""
    if never.blocks_ip(ip):
        raise Blocked(ip)
    return ip


def _check_name(name: str, addresses, never: NeverScan) -> None:
    """Raise Blocked if the name or ANY of its addresses is on the never-scan list."""
    if never.blocks_host(name):
        raise Blocked(name)
    for ip in addresses:
        if never.blocks_ip(ip):
            raise Blocked(name, ip)


def resolve_checked(host: str, never: NeverScan, timeout: float = 5.0) -> list[str]:
    """Resolve once and apply never-scan to the whole name: if the name or ANY address it resolves to is on the list,
    the name is refused, so a dual-stack host listed by one address is not scanned over the other, and a client that
    resolves the name again itself (WinRM, a driver) cannot reach a listed address either.  Returns every address
    (IPv4 first); connect only to one of them.  An IP literal is checked as itself.
    Raises Blocked, or OSError when the name does not resolve (or resolves to no address)."""
    text = str(host or "").strip().strip("[]")
    if _is_ip(text):
        return [checked_ip(text, never)]
    name = text.lower().rstrip(".")
    _check_name(name, (), never)  # a listed name is not looked up
    addresses = resolve(name, timeout)
    if not addresses:
        raise socket.gaierror(socket.EAI_NONAME, f"{name} has no address")
    _check_name(name, addresses, never)
    return addresses


def checked_target(target: Target, never: NeverScan) -> str:
    """Re-check an expanded target just before connecting (the list can change while a job runs): an address by
    itself, a name by its own entry and by EVERY address it resolved to.  Returns the address to connect to (it is
    checked again at connect time).  Raises Blocked."""
    if target.ip is None:
        raise ValueError(f"{target.label} has no address to connect to")
    if target.addresses:
        _check_name(target.label, target.addresses, never)
    return checked_ip(target.ip, never)


def connect(ip: str, port: int, never: NeverScan, timeout: float) -> socket.socket:
    """TCP connection to a checked address.  Raises Blocked or OSError (socket.timeout, ConnectionRefusedError ...)."""
    checked_ip(ip, never)
    return socket.create_connection((ip, int(port)), timeout=timeout)


def udp_connect(ip: str, port: int, never: NeverScan, timeout: float) -> socket.socket:
    """A connected UDP socket to a checked address (IKE).  Connected, so only that address's datagrams are read and
    an ICMP port-unreachable shows up as ConnectionRefusedError.  Raises Blocked or OSError."""
    checked_ip(ip, never)
    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ip, int(port)))
    except BaseException:
        sock.close()
        raise
    return sock


def http_client(url: str, ip: str, never: NeverScan, **kwargs):
    """An httpx.Client for ``url`` that connects only to ``ip`` (checked here), while the Host header, TLS SNI and
    certificate name check still use the URL's host name.  So the HTTP client never resolves the name again: DNS
    cannot move it to an address that was not checked.  kwargs go to httpx.Client (verify, headers, timeout ...);
    redirects are never followed and the environment's proxies are not used."""
    import httpx
    from urllib.parse import urlsplit

    checked_ip(ip, never)
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    default_port = port == (443 if parts.scheme == "https" else 80)
    literal = f"[{ip}]" if ":" in ip else ip
    pinned = f"{parts.scheme}://{literal}:{port}{parts.path or ''}"
    host_header = (f"[{host}]" if ":" in host else host) + ("" if default_port else f":{port}")
    sni = None if _is_ip(host) else host

    class _Pinned(httpx.HTTPTransport):
        def handle_request(self, request):
            if sni:
                request.extensions = {**request.extensions, "sni_hostname": sni}
            return super().handle_request(request)

    verify = kwargs.pop("verify", True)
    headers = {**(kwargs.pop("headers", None) or {}), "Host": host_header}
    kwargs.pop("follow_redirects", None)
    kwargs.pop("trust_env", None)
    return httpx.Client(base_url=pinned, headers=headers, transport=_Pinned(verify=verify), follow_redirects=False,
                        trust_env=False, **kwargs)


def iter_line_ips(line: str) -> Iterator[str] | None:
    """Addresses of an IP / CIDR / range line, or None if the line is a hostname."""
    text = line.strip()
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            if net.num_addresses == 1:
                return iter([str(net.network_address)])
            hosts = net.hosts() if net.version == 4 and net.prefixlen <= 30 else iter(net)
            return (str(a) for a in hosts)
        if "-" in text:
            left, right = text.split("-", 1)
            try:
                a, b = ipaddress.ip_address(left.strip()), ipaddress.ip_address(right.strip())
            except ValueError:
                a = b = None
            if a is not None and b is not None and a.version == b.version and int(b) >= int(a):
                return (str(ipaddress.ip_address(i)) if a.version == 4 else str(ipaddress.IPv6Address(i))
                        for i in range(int(a), int(b) + 1))
        return iter([str(ipaddress.ip_address(text))])
    except ValueError:
        return None


def expand_targets(lines: list[str], never: NeverScan, limit: int = MAX_EXPANDED,
                   reasons: dict[str, str] | None = None) -> tuple[list[Target], list[str]]:
    """(targets to scan, labels skipped by never-scan).  Duplicate IPs are scanned once.  A hostname is skipped when
    it or any address it resolves to is on the list; IP, CIDR and range lines are checked address by address.
    ``reasons``, when given, receives why each skipped hostname was skipped (label -> text naming the address)."""
    seen: set[str] = set()
    targets: list[Target] = []
    skipped: list[str] = []
    for line in lines:
        ips = iter_line_ips(line)
        if ips is None:
            name = line.strip().lower().rstrip(".")
            try:
                addrs = resolve_checked(name, never)
            except Blocked as exc:
                skipped.append(name)
                if reasons is not None:
                    reasons[name] = str(exc)
                continue
            except OSError as exc:
                targets.append(Target(name, None, f"could not resolve {name}: {exc.__class__.__name__}"))
                continue
            ip = addrs[0]
            if ip in seen:
                continue
            seen.add(ip)
            targets.append(Target(name, ip, addresses=tuple(addrs)))
            continue
        for ip in ips:
            if len(seen) >= limit:
                break
            if ip in seen:
                continue
            seen.add(ip)
            if never.blocks_ip(ip):
                skipped.append(ip)
                continue
            targets.append(Target(ip, ip))
    return targets, skipped


class RateLimiter:
    """Global connections-per-second token bucket plus a per-address concurrency cap."""

    def __init__(self, per_second: float = 20, per_server: int = 2) -> None:
        self.rate = max(float(per_second or 1), 0.1)
        self.capacity = max(1.0, self.rate)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self.lock = threading.Lock()
        self.per_server = max(int(per_server or 1), 1)
        # weak: a semaphore lives only while a connection holds it, so a /16 sweep does not grow this forever
        self._sems: weakref.WeakValueDictionary[str, threading.BoundedSemaphore] = weakref.WeakValueDictionary()
        self._sem_lock = threading.Lock()
        self.connections = 0

    def configure(self, per_second: float, per_server: int) -> None:
        with self.lock:
            self.rate = max(float(per_second or 1), 0.1)
            self.capacity = max(1.0, self.rate)
            self.tokens = min(self.tokens, self.capacity)
        with self._sem_lock:
            self.per_server = max(int(per_server or 1), 1)

    def acquire(self, stop: threading.Event | None = None, deadline: float | None = None) -> bool:
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    self.connections += 1
                    return True
                wait = (1 - self.tokens) / self.rate
            if stop is not None and stop.is_set():
                return False
            if deadline is not None and time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 0.5))

    def server(self, ip: str) -> threading.BoundedSemaphore:
        with self._sem_lock:
            sem = self._sems.get(ip)
            if sem is None:
                sem = self._sems[ip] = threading.BoundedSemaphore(self.per_server)
            return sem


_NODE_LIMITER: RateLimiter | None = None
_NODE_LIMITER_LOCK = threading.Lock()


def node_limiter(per_second: float, per_server: int) -> RateLimiter:
    """The one limiter of this node process.  The agreed connections per second bind the node as a whole, however
    many network jobs it runs at once; the newest job's limits (the team's current settings) apply to all of them."""
    global _NODE_LIMITER
    with _NODE_LIMITER_LOCK:
        if _NODE_LIMITER is None:
            _NODE_LIMITER = RateLimiter(per_second, per_server)
        else:
            _NODE_LIMITER.configure(per_second, per_server)
        return _NODE_LIMITER


def local_ips() -> list[str]:
    out: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in out and not ip.startswith("127.") and ip != "::1":
                out.append(ip)
    except OSError:
        pass
    try:  # the address used for the default route
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ip = s.getsockname()[0]
            if ip not in out:
                out.insert(0, ip)
    except OSError:
        pass
    return out[:32]


def has_ipv6() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2001:db8::1", 9))
        return True
    except OSError:
        return False
