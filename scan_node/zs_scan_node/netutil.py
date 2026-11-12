"""Targets, the never-scan list and rate limits.

* Target lines (IP, CIDR, ``a-b`` range, hostname) are expanded lazily and de-duplicated by IP.
* A hostname is resolved once and the node connects only to an address it checked (no second lookup, so DNS
  rebinding cannot redirect it).  The never-scan list applies to the whole name: if the name, or ANY address it
  resolves to, is on the list, the name is skipped (a dual-stack host listed by its IPv4 address is not scanned
  over IPv6).  An IP literal is checked as itself; CIDR and ``a-b`` ranges are checked address by address.
* The never-scan list can change while a job runs (heartbeat); ``NeverScan.update`` swaps it atomically.
* Entries: an address, a CIDR, an ``a-b`` range (IPv4 or IPv6) or a host name.  IPv4-mapped entries count as their
  IPv4 addresses.  A host name entry is matched by name AND by every address it resolves to from the node, so a
  listed host is not reached by its short name, a CNAME, an address target or a range sweep either.
* Listed host names are looked up by ONE resolver per node process (``NameResolver``), on a few background threads:
  never on a job's claim or watcher thread, never more than LOOKUP_WORKERS lookups at once however long they hang.
* Fail closed: while a listed host name has no known address (its lookup is pending, hangs, fails or answers "no such
  name"), the node cannot tell which address is that host, so it scans no address at all; each target is skipped
  as ``skipped_never_scan`` with a reason that names the host name.  A newly listed name is waited for, on the job's
  own thread, for at most NAME_LOOKUP_S first, so a normal lookup costs no target.
* Never scanned whatever the list says: the unspecified addresses 0.0.0.0/8 and :: (a connection to them reaches the
  node itself; DNS sinkholes answer 0.0.0.0).  An IPv4-mapped (::ffff:a.b.c.d) or NAT64 (64:ff9b::/96, RFC 6052)
  IPv6 address is also checked as the IPv4 address it reaches.
"""
from __future__ import annotations

import heapq
import ipaddress
import socket
import threading
import weakref
import time
from dataclasses import dataclass
from typing import Iterable, Iterator
from urllib.parse import urlsplit

MAX_EXPANDED = 262_144
_UNSPECIFIED_NETS = (ipaddress.ip_network("0.0.0.0/8"), ipaddress.ip_network("::/128"))
UNSPECIFIED = "unspecified address"  # what match_ip answers for 0.0.0.0/8 and ::
_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
# Listed host names: a job waits at most NAME_LOOKUP_S (on its own thread) for a newly listed name's first answer;
# the resolver looks a name up again NAME_REFRESH_S after an answer and NAME_RETRY_S after a failure.
NAME_LOOKUP_S = 15.0
NAME_REFRESH_S = 300.0
NAME_RETRY_S = 60.0
LOOKUP_WORKERS = 8  # lookups in flight at most, node-wide (a hung getaddrinfo cannot be cancelled, only capped)


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


def _without_zone(net):
    """fe80::1%eth0/128 -> fe80::1/128: a zone names the interface, not another host."""
    if net.version == 6 and net.network_address.scope_id:
        return ipaddress.IPv6Network((int(net.network_address), net.prefixlen))
    return net


def _parse_entry(text: str) -> tuple[list, str] | None:
    """(networks, canonical label) for an address, CIDR or ``a-b`` range entry (IPv4-mapped ones as IPv4; an IPv6
    address may be in brackets or carry a zone, even one with a dash: fe80::1%br-ab12); None for anything else, which
    is a host name entry."""
    try:
        net = _without_zone(ipaddress.ip_network(text.strip("[]"), strict=False))
    except ValueError:
        net = None
    try:
        if net is None and "/" not in text and "-" in text:
            first, last = (_v4_if_mapped(ipaddress.ip_address(p.strip().strip("[]"))) for p in text.split("-", 1))
            if first.version == last.version and last < first:  # the backend refuses these; here, never fail open
                first, last = last, first
            nets = [_without_zone(n) for n in ipaddress.summarize_address_range(first, last)]
            return nets, f"{nets[0].network_address}-{nets[-1].broadcast_address}"
    except (ValueError, TypeError):  # TypeError: the two ends of a range are not the same IP version
        return None
    if net is None:
        return None
    if net.version == 6 and net.prefixlen >= 96 and net.subnet_of(_MAPPED):
        net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    return [net], str(net.network_address) if net.num_addresses == 1 else str(net)


class NameResolver:
    """Looks up the never-scan host names of every job on this node, on at most LOOKUP_WORKERS daemon threads named
    ``zs-never-dns-N``.  A lookup that hangs holds its thread and nothing else, so no more than LOOKUP_WORKERS lookups
    are ever outstanding, whatever the DNS does, and no job's claim or watcher thread ever waits for one.  Due names
    are taken in the order they became due, never-tried names first, so names that hang go to the back once they
    return and cannot keep the others from being looked up.  A name is looked up while some job lists it:
    NAME_REFRESH_S after an answer, NAME_RETRY_S after a failure, and at once when a job's list changes."""

    def __init__(self, workers: int | None = None) -> None:
        self._cond = threading.Condition()
        self._max_workers = max(1, int(workers or LOOKUP_WORKERS))
        self._threads: list[threading.Thread] = []
        self._refs: dict[str, int] = {}  # name -> how many job lists carry it
        self._addrs: dict[str, frozenset] = {}  # name -> every address its latest answer reaches
        self._answered: set[str] = set()  # names whose lookup has finished at least once (answer or failure)
        self._due: dict[str, float] = {}  # name -> when it is due next (monotonic)
        self._queue: list[tuple[float, int, str]] = []  # heap of (due, order, name); stale rows are skipped
        self._order = 0
        self._busy: set[str] = set()
        self._closed = False
        self.generation = 0  # bumped by every answer: a NeverScan merges answers only when it moved

    # -------------------------------------------------------------- what jobs call (never waits for DNS)
    def acquire(self, names: Iterable[str]) -> None:
        with self._cond:
            for name in names:
                self._refs[name] = self._refs.get(name, 0) + 1
                if self._refs[name] == 1:
                    self._schedule(name, 0.0)
            while len(self._threads) < self._max_workers and not self._closed:
                thread = threading.Thread(target=self._work, name=f"zs-never-dns-{len(self._threads) + 1}",
                                          daemon=True)
                self._threads.append(thread)
                thread.start()
            self._cond.notify_all()

    def release(self, names: Iterable[str]) -> None:
        with self._cond:
            for name in list(names):
                left = self._refs.get(name, 0) - 1
                if left > 0:
                    self._refs[name] = left
                    continue
                for table in (self._refs, self._addrs, self._due):
                    table.pop(name, None)
                self._answered.discard(name)

    def look_up_soon(self, names: Iterable[str]) -> None:
        """A job's list changed: look these (already listed) names up again now."""
        with self._cond:
            for name in names:
                if name in self._refs and name not in self._busy:
                    self._schedule(name, 0.0)
            self._cond.notify_all()

    def answers(self, names: Iterable[str]) -> dict[str, tuple[frozenset, bool]]:
        """name -> (addresses of its latest answer, whether any lookup of it has finished)."""
        with self._cond:
            return {n: (self._addrs.get(n, frozenset()), n in self._answered) for n in names}

    def wait_answered(self, names: Iterable[str], deadline: float) -> None:
        """Wait (on the caller's thread) until each name has been answered once, or until ``deadline``."""
        names = list(names)
        with self._cond:
            while not self._closed and any(n in self._refs and n not in self._answered for n in names):
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                self._cond.wait(left)

    def close(self) -> None:
        """Stop the workers (tests): idle ones at once, one in a lookup when that lookup returns."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    # -------------------------------------------------------------- workers
    def _schedule(self, name: str, due: float) -> None:  # with the lock held
        self._due[name] = due
        self._order += 1
        heapq.heappush(self._queue, (due, self._order, name))

    def _next(self) -> tuple[str | None, float]:  # with the lock held: (a due name, or None and how long to wait)
        while self._queue:
            due, _order, name = self._queue[0]
            if self._due.get(name) != due or name in self._busy:  # stale row, or released, or being looked up
                heapq.heappop(self._queue)
                continue
            now = time.monotonic()
            if due > now:
                return None, due - now
            heapq.heappop(self._queue)
            return name, 0.0
        return None, 60.0

    def _work(self) -> None:
        while True:
            with self._cond:
                while True:
                    if self._closed:
                        return
                    name, wait = self._next()
                    if name is not None:
                        break
                    self._cond.wait(wait)
                self._busy.add(name)
            found: set = set()
            try:
                for ip in resolve(name):  # the module's resolve (tests replace it)
                    try:
                        found.update(_reaches(ipaddress.ip_address(ip)))
                    except ValueError:
                        continue
            except Exception:  # noqa: BLE001 - a name that does not resolve stays unresolved and is retried
                found = set()
            with self._cond:
                self._busy.discard(name)
                if name not in self._refs:
                    continue  # no job lists it any more
                self._answered.add(name)
                if found:
                    self._addrs[name] = frozenset(found)
                    self._schedule(name, time.monotonic() + NAME_REFRESH_S)
                else:  # a failed refresh keeps the addresses learned before
                    self._schedule(name, time.monotonic() + NAME_RETRY_S)
                self.generation += 1
                self._cond.notify_all()


_RESOLVER: NameResolver | None = None
_RESOLVER_LOCK = threading.Lock()


def name_resolver() -> NameResolver:
    """The resolver of this node process (one for every job)."""
    global _RESOLVER
    with _RESOLVER_LOCK:
        if _RESOLVER is None:
            _RESOLVER = NameResolver()
        return _RESOLVER


class Unresolved(str):
    """What ``match_ip`` answers while listed host names have no known address: the address may be one of them."""

    names: tuple[str, ...] = ()

    def __new__(cls, names) -> "Unresolved":
        names = tuple(names)
        shown = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
        self = super().__new__(cls, f"never-scan host name{'s' if len(names) > 1 else ''} {shown}")
        self.names = names
        return self


class NeverScan:
    """The never-scan list of one job.  ``match_ip`` / ``blocks_ip`` answer for an address, ``blocks_host`` for a name
    exactly as listed.  Host name entries also block every address they resolve to; the node-wide NameResolver looks
    them up, never the caller.  While a listed name has no known address, every address is refused (``Unresolved``):
    ``unresolved`` lists those names, ``held_by`` the ones that held a target during this job."""

    def __init__(self, lines: list[str] | None = None, resolver: NameResolver | None = None) -> None:
        self._lock = threading.Lock()
        self._nets: list[tuple[ipaddress._BaseNetwork, str]] = []
        self._hosts: set[str] = set()
        self._resolver = resolver or name_resolver()
        self._listed: set[str] = set()  # names this list holds on the resolver (released when the list goes away)
        self._release = weakref.finalize(self, self._resolver.release, self._listed)
        self._name_addrs: dict[str, set] = {}  # listed name -> every address it resolved to during this job
        self._answered: set[str] = set()  # listed names whose lookup has finished since they were listed
        self._hold_until: dict[str, float] = {}  # listed name -> until when a check waits for its first answer
        self._by_addr: dict = {}  # address -> the listed name it belongs to
        self._unresolved: tuple[str, ...] = ()
        self._waiting: tuple[str, ...] = ()  # unresolved names not answered yet, still inside their hold
        self._hold_end = 0.0
        self._seen = -1  # resolver generation merged so far
        self.held_by: set[str] = set()
        self.update(lines or [])

    def update(self, lines: list[str]) -> None:
        """Set the list (a new list from a heartbeat replaces the old one), at once: no DNS here.  New host names are
        registered with the resolver; every listed name is looked up again soon."""
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
            added, removed = hosts - self._hosts, self._hosts - hosts
            self._nets, self._hosts = nets, hosts
            self._name_addrs = {n: a for n, a in self._name_addrs.items() if n in hosts}
            self._answered &= hosts
            now = time.monotonic()
            self._hold_until = {n: self._hold_until.get(n, now + NAME_LOOKUP_S) for n in hosts}
            self._listed.difference_update(removed)
            self._listed.update(added)
            self._resolver.release(removed)
            self._resolver.acquire(added)
            self._resolver.look_up_soon(hosts - added)  # a changed list: its names are looked up again now
            self._seen = -1
            self._index()

    def close(self) -> None:
        """The job ended: give its names back to the resolver (also done when the list is garbage collected)."""
        self._release()

    def _merge(self, hold: bool) -> None:
        """Take the resolver's answers into this job's list.  ``hold``: first wait (bounded) for names that were
        listed less than NAME_LOOKUP_S ago and have no answer yet, so a normal lookup costs no target."""
        if hold and self._waiting and time.monotonic() < self._hold_end:
            self._resolver.wait_answered(self._waiting, self._hold_end)
        generation = self._resolver.generation
        if generation == self._seen:
            return
        with self._lock:
            hosts = list(self._hosts)
        answers = self._resolver.answers(hosts)
        with self._lock:
            for name, (addrs, answered) in answers.items():
                if name not in self._hosts:
                    continue  # taken off the list meanwhile
                if addrs:  # answers add to what the name resolved to before: never narrower during a job
                    self._name_addrs.setdefault(name, set()).update(addrs)
                if answered:
                    self._answered.add(name)
            self._seen = generation
            self._index()

    def _index(self) -> None:  # with the lock held
        self._by_addr = {addr: name for name, addrs in sorted(self._name_addrs.items()) for addr in addrs}
        self._unresolved = tuple(sorted(n for n in self._hosts if not self._name_addrs.get(n)))
        now = time.monotonic()
        waiting = [n for n in self._unresolved if n not in self._answered and self._hold_until.get(n, 0.0) > now]
        self._waiting = tuple(waiting)
        self._hold_end = max((self._hold_until[n] for n in waiting), default=0.0)

    def sync(self) -> None:
        """Take in the resolver's latest answers without waiting (the job's watcher calls this every few seconds, so
        a job keeps every address a listed name answered while it ran, even between its own checks)."""
        self._merge(hold=False)

    @property
    def unresolved(self) -> list[str]:
        """Listed host names with no known address yet (every address is refused while there is one)."""
        self._merge(hold=False)
        return list(self._unresolved)

    def match_ip(self, ip: str) -> str | None:
        """Why ``ip`` must not be scanned: the matching entry (an address, CIDR or range; "an address of <name>" for
        a listed host name; UNSPECIFIED for 0.0.0.0/8 and ::; ``Unresolved`` while a listed host name has no known
        address, since ``ip`` may be that host), or None when it may be scanned.  Anything that is not an IP address
        is refused.  May wait up to NAME_LOOKUP_S for a newly listed name's first answer (job threads only)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "not an IP address"
        forms = _reaches(addr)
        if any(f.version == n.version and f in n for f in forms for n in _UNSPECIFIED_NETS):
            return UNSPECIFIED
        self._merge(hold=True)
        with self._lock:
            for f in forms:
                for net, label in self._nets:
                    if f.version == net.version and f in net:
                        return label
                name = self._by_addr.get(f)
                if name is not None:
                    return f"an address of {name}"
            if self._unresolved:
                self.held_by.update(self._unresolved)
                return Unresolved(self._unresolved)
        return None

    def held_names(self) -> list[str]:
        """Listed host names that held a target during this job (they had no known address when it was checked)."""
        with self._lock:
            return sorted(self.held_by)

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
        if isinstance(entry, Unresolved):
            subject = f"{what} ({address})" if address else what
            many = len(entry.names) > 1
            text = (f"{subject} was not scanned: the {entry} {'have' if many else 'has'} not resolved from the scan "
                    f"node, so the node cannot tell which addresses are {'those hosts' if many else 'that host'}")
        elif entry == UNSPECIFIED:
            reaches = ()
            try:
                reaches = _reaches(ipaddress.ip_address(str(address or what).strip("[]")))
            except ValueError:
                pass
            form = f"an IPv6 form of {reaches[1]}, " if len(reaches) > 1 else ""  # IPv4-mapped or NAT64
            head = f"{what} resolves to {address}," if address else f"{what} is"
            text = f"{head} {form}in 0.0.0.0/8 or ::, which reaches the scan node itself, so it is never scanned"
        else:
            head = f"{what} resolves to {address}, which is" if address else f"{what} is"
            text = f"{head} on the never-scan list" + (f" ({entry})" if entry and entry not in (what, address) else "")
        super().__init__(text)
        self.what, self.address, self.entry = what, address, entry


def is_ip(text) -> bool:
    """Whether ``text`` is an IP address literal (IPv4, or IPv6 with or without a zone; no brackets)."""
    try:
        ipaddress.ip_address(str(text))
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
    if is_ip(text):
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
    sni = None if is_ip(host) else host

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
    by_name = not is_ip(want)

    class _Pinned(HTTPAdapter):
        zs_pinned_to = (want, ip)  # what this adapter connects (for callers that must check a session is pinned)

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
