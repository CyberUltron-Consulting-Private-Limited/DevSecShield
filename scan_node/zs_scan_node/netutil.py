"""Targets, the never-scan list and rate limits.

* Target lines (IP, CIDR, ``a-b`` range, hostname) are expanded lazily and de-duplicated by IP.
* A hostname is resolved once and the node connects only to an address it checked (no second lookup, so DNS
  rebinding cannot redirect it).  The never-scan list applies to the whole name: if the name, or ANY address it
  resolves to, is on the list, the name is skipped (a dual-stack host listed by its IPv4 address is not scanned
  over IPv6).  An IP literal is checked as itself; CIDR and ``a-b`` ranges are checked address by address.
* The never-scan list can change while a job runs (heartbeat); ``NeverScan.update`` swaps it atomically.
* Entries: an address, a CIDR, an ``a-b`` range (IPv4 or IPv6) or a host name.  IPv4-mapped entries count as their
  IPv4 addresses.  A host name entry is matched by name AND by every address it resolves to from the node (looked up
  when the list is set or changes, and again every few minutes), so a listed host is not reached by its short name,
  a CNAME, an address target or a range sweep either.
* Never scanned whatever the list says: the unspecified addresses 0.0.0.0/8 and :: (a connection to them reaches the
  node itself; DNS sinkholes answer 0.0.0.0).  An IPv4-mapped (::ffff:a.b.c.d) or NAT64 (64:ff9b::/96, RFC 6052)
  IPv6 address is also checked as the IPv4 address it reaches.
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import socket
import threading
import weakref
import time
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import urlsplit

MAX_EXPANDED = 262_144
_UNSPECIFIED_NETS = (ipaddress.ip_network("0.0.0.0/8"), ipaddress.ip_network("::/128"))
UNSPECIFIED = "unspecified address"  # what match_ip answers for 0.0.0.0/8 and ::
_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
# Looking up the host names on the list: bounded per update (a slow resolver must not hold a job or its heartbeat),
# then again every NAME_REFRESH_S, and a name that did not resolve every NAME_RETRY_S.
NAME_LOOKUP_S = 15.0
NAME_REFRESH_S = 300.0
NAME_RETRY_S = 60.0
MAX_LISTED_NAMES = 1000
_LOOKUP_WORKERS = 16


def _reaches(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple:
    """The address, plus the IPv4 address that an IPv4-mapped or NAT64 (64:ff9b::/96) IPv6 address reaches.  A zone
    (fe80::1%eth0) is dropped: it names the interface, not another host."""
    if addr.version == 6:
        if addr.scope_id:
            addr = ipaddress.IPv6Address(int(addr))
        if addr.ipv4_mapped is not None:
            return addr, addr.ipv4_mapped
        if addr in _NAT64:
            return addr, ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return (addr,)


def _v4_if_mapped(addr):
    return addr.ipv4_mapped if addr.version == 6 and addr.ipv4_mapped is not None else addr


def _parse_entry(text: str) -> tuple[list, str] | None:
    """(networks, canonical label) for an address, CIDR or ``a-b`` range entry (IPv4-mapped ones as IPv4); None for
    anything else, which is a host name entry."""
    try:
        if "/" not in text and "-" in text:
            first, last = (_v4_if_mapped(ipaddress.ip_address(p.strip())) for p in text.split("-", 1))
            if first.version == last.version and last < first:  # the backend refuses these; here, never fail open
                first, last = last, first
            return list(ipaddress.summarize_address_range(first, last)), f"{first}-{last}"
        net = ipaddress.ip_network(text, strict=False)
    except (ValueError, TypeError):  # TypeError: the two ends of a range are not the same IP version
        return None
    if net.version == 6 and net.prefixlen >= 96 and net.subnet_of(_MAPPED):
        net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    return [net], str(net.network_address) if net.num_addresses == 1 else str(net)


def _look_up(names: list[str], limit: float) -> dict[str, list[str]]:
    """Addresses of each name that answered within ``limit`` seconds (looked up in parallel)."""
    out: dict[str, list[str]] = {}
    pool = cf.ThreadPoolExecutor(max_workers=min(_LOOKUP_WORKERS, len(names)), thread_name_prefix="zs-never-dns")
    try:
        futures = {pool.submit(resolve, name): name for name in names}
        done, _late = cf.wait(futures, timeout=limit)
        for future in done:
            try:
                out[futures[future]] = list(future.result())
            except Exception:  # noqa: BLE001 - a name that does not resolve is reported as unresolved
                pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)  # a lookup still running finishes on its own; it is not used
    return out


class NeverScan:
    """The never-scan list of one job.  ``match_ip`` / ``blocks_ip`` answer for an address, ``blocks_host`` for a name
    exactly as listed.  Host name entries also block every address they resolve to (``unresolved`` lists those that
    did not resolve yet; they are retried)."""

    def __init__(self, lines: list[str] | None = None) -> None:
        self._lock = threading.Lock()
        self._nets: list[tuple[ipaddress._BaseNetwork, str]] = []
        self._hosts: set[str] = set()
        self._name_addrs: dict[str, set] = {}  # listed name -> every address it resolved to during this job
        self._by_addr: dict = {}  # address -> the listed name it belongs to
        self._next_lookup: dict[str, float] = {}
        self.unresolved: list[str] = []
        self.update(lines or [])

    def update(self, lines: list[str]) -> None:
        """Set the list (a new list from a heartbeat replaces the old one); its host names are looked up again."""
        nets: list[tuple[ipaddress._BaseNetwork, str]] = []
        hosts: set[str] = set()
        for raw in lines or []:
            text = str(raw).strip()
            if not text:
                continue
            parsed = _parse_entry(text)
            if parsed is None:
                hosts.add(text.lower().rstrip("."))
            else:
                nets.extend((net, parsed[1]) for net in parsed[0])
        with self._lock:
            self._nets, self._hosts = nets, hosts
            self._name_addrs = {n: a for n, a in self._name_addrs.items() if n in hosts}
            self._next_lookup = {n: 0.0 for n in hosts}  # a changed list: look every name up again now
            self._index()
        self.refresh()

    def refresh(self) -> None:
        """Look up the listed host names that are due (new, unresolved for NAME_RETRY_S, or resolved NAME_REFRESH_S
        ago).  Answers add to what the name resolved to before during this job: the list never gets narrower."""
        now = time.monotonic()
        with self._lock:
            due = sorted(n for n in self._hosts if self._next_lookup.get(n, 0.0) <= now)[:MAX_LISTED_NAMES]
        if not due:
            return
        answers = _look_up(due, NAME_LOOKUP_S)
        now = time.monotonic()
        with self._lock:
            for name in due:
                if name not in self._hosts:
                    continue  # taken off the list while it was being looked up
                found = set()
                for ip in answers.get(name) or ():
                    try:
                        found.update(_reaches(ipaddress.ip_address(ip)))
                    except ValueError:
                        continue
                if found:
                    self._name_addrs.setdefault(name, set()).update(found)
                    self._next_lookup[name] = now + NAME_REFRESH_S
                else:
                    self._next_lookup[name] = now + NAME_RETRY_S
            self._index()

    def _index(self) -> None:  # with the lock held
        self._by_addr = {addr: name for name, addrs in sorted(self._name_addrs.items()) for addr in addrs}
        self.unresolved = sorted(n for n in self._hosts if not self._name_addrs.get(n))

    def match_ip(self, ip: str) -> str | None:
        """Why ``ip`` must not be scanned: the matching entry (an address, CIDR or range; "an address of <name>" for
        a listed host name; UNSPECIFIED for 0.0.0.0/8 and ::), or None when it may be scanned.  Anything that is not
        an IP address is refused."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "not an IP address"
        forms = _reaches(addr)
        if any(f.version == n.version and f in n for f in forms for n in _UNSPECIFIED_NETS):
            return UNSPECIFIED
        with self._lock:
            for f in forms:
                for net, label in self._nets:
                    if f.version == net.version and f in net:
                        return label
                name = self._by_addr.get(f)
                if name is not None:
                    return f"an address of {name}"
        return None

    def blocks_ip(self, ip: str) -> bool:
        return self.match_ip(ip) is not None

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
    """Resolve a hostname to unique addresses (IPv4 first).  Raises OSError on failure.  ``timeout`` is kept for
    callers: getaddrinfo uses the system resolver's own timeout (socket.setdefaulttimeout does not apply to it, and
    setting that process-wide default here changed the timeout of sockets other threads created meanwhile)."""
    infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
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
#   requests_adapter(host, ip, never)   the same for a requests session (pywinrm): no second lookup, no proxy
# tests/test_network_gate.py fails when a collector module opens sockets or HTTP clients any other way.


class Blocked(Exception):
    """The target (name or address) is on the never-scan list, or ``what`` is a name and ``address``, one of the
    addresses it resolves to, is.  ``entry`` is the list entry that matched (NeverScan.match_ip)."""

    status = "skipped_never_scan"
    address: str | None = None
    entry: str | None = None

    def __init__(self, what: str, address: str | None = None, entry: str | None = None) -> None:
        head = f"{what} resolves to {address}, which is" if address else f"{what} is"
        if entry == UNSPECIFIED:
            text = f"{head} an unspecified address (0.0.0.0/8 or ::) and is never scanned"
        else:
            text = f"{head} on the never-scan list" + (f" ({entry})" if entry and entry not in (what, address) else "")
        super().__init__(text)
        self.what, self.address, self.entry = what, address, entry


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def checked_ip(ip: str, never: NeverScan) -> str:
    """The address itself, after checking it against the current never-scan list (raises Blocked)."""
    entry = never.match_ip(ip)
    if entry is not None:
        raise Blocked(ip, entry=entry)
    return ip


def _check_name(name: str, addresses, never: NeverScan) -> None:
    """Raise Blocked if the name or ANY of its addresses is on the never-scan list."""
    if never.blocks_host(name):
        raise Blocked(name)
    for ip in addresses:
        entry = never.match_ip(ip)
        if entry is not None:
            raise Blocked(name, ip, entry)


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
    """An httpx.Client for ``url`` that connects only to ``ip`` (checked here and again before every request, so a
    never-scan change applies to a client that is already open: Blocked), while the Host header, TLS SNI and
    certificate name check still use the URL's host name.  So the HTTP client never resolves the name again: DNS
    cannot move it to an address that was not checked.  kwargs go to httpx.Client (verify, headers, timeout ...);
    redirects are never followed and the environment's proxies are not used."""
    import httpx

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
            checked_ip(ip, never)  # raises Blocked out of client.get / send / stream
            if sni:
                request.extensions = {**request.extensions, "sni_hostname": sni}
            return super().handle_request(request)

    verify = kwargs.pop("verify", True)
    headers = {**(kwargs.pop("headers", None) or {}), "Host": host_header}
    kwargs.pop("follow_redirects", None)
    kwargs.pop("trust_env", None)
    return httpx.Client(base_url=pinned, headers=headers, transport=_Pinned(verify=verify), follow_redirects=False,
                        trust_env=False, **kwargs)


def requests_adapter(host: str, ip: str, never: NeverScan):
    """A ``requests`` HTTPAdapter for a client that connects by name (pywinrm): every request to ``host`` connects to
    ``ip`` only (checked here and again before each request, so the list applies live), while the Host header, TLS SNI
    and the certificate name check keep ``host``.  The name is never resolved again, no proxy is used (not even one
    from the environment), and a request for any other host is refused."""
    import requests
    from requests.adapters import HTTPAdapter

    if not hasattr(HTTPAdapter, "get_connection_with_tls_context"):  # requests < 2.32.2 would bypass the pin
        raise RuntimeError("requests is too old to pin connections (2.32.2 or later is needed)")
    checked_ip(ip, never)
    want = str(host).strip("[]").lower().rstrip(".")
    by_name = not _is_ip(want)

    class _Pinned(HTTPAdapter):
        def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
            host_params, pool_kwargs = self.build_connection_pool_key_attributes(request, verify, cert)
            got = str(host_params.get("host") or "").strip("[]").lower().rstrip(".")
            if got != want:
                raise requests.exceptions.ConnectionError(f"{got or 'a request'} is not {want}, the host that was "
                                                          "checked; refused", request=request)
            checked_ip(ip, never)
            if by_name:
                pool_kwargs = {**pool_kwargs, "server_hostname": want, "assert_hostname": want}
            return self.poolmanager.connection_from_host(**{**host_params, "host": ip}, pool_kwargs=pool_kwargs)

        def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
            netloc = urlsplit(request.url).netloc.rsplit("@", 1)[-1]
            request.headers["Host"] = netloc  # the pool's host is the address; the server sees the name
            return super().send(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=None)

    return _Pinned()


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
    ``reasons``, when given, receives why each label was skipped (the address and the entry that matched)."""
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
            entry = never.match_ip(ip)
            if entry is not None:
                skipped.append(ip)
                if reasons is not None:
                    reasons[ip] = str(Blocked(ip, entry=entry))
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
