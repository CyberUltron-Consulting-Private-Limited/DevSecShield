"""Network TLS/SSH collection and discovery sweeps over the ranges and ports the customer allowed.

Per open endpoint a prioritised list of handshakes runs, capped by ``handshakes_per_endpoint``:
  1. one full handshake (``openssl s_client``; Python ``ssl`` if openssl is missing) -> version, cipher, group,
     peer signature, certificate chain.  When it fails, one ClientHello decides whether the port speaks TLS at all:
     a TLS alert means TLS (an SNI-only server is then read with the team's "Hostnames for SNI" that resolve to the
     address, and that name is sent in every probe of the endpoint); a close or non-TLS bytes, to a modern and to a
     legacy hello, mean "not TLS": a ``not_tls`` coverage row, never a TLS asset (CB-12, KF-4/KF-5);
  2. raw ClientHello per protocol version (SSLv3 .. TLS 1.3) -> what the server accepts;
  3. TLS 1.3 post-quantum group probe (HelloRetryRequest) -> hybrid ML-KEM support;
  4. TLS_FALLBACK_SCSV probe -> downgrade protection;
  5. weak cipher classes (obsolete, static RSA, CBC, DHE with its group size);
  6-9. enumeration (``tlsenum``, #100): every TLS 1.3 group and suite, every suite of each accepted legacy version
     (best first), TLS <= 1.2 curves when there is no TLS 1.3.  Budget: (accepted + 2) per legacy version,
     (accepted + 1) for TLS 1.3 suites, (groups + 2); a pass the budget or time cuts is marked incomplete in the
     facts (``enumeration``), never a coverage gap, because steps 1-5 already judged the findings.
``fragile`` ranges get only steps 1-2.  Other SNI names that resolve into the address add one full handshake each,
from a share of the endpoint's budget; names are resolved once per job, all at once, within ``SNI_DNS_BUDGET_S``.
Every connection goes through the rate limiter, re-checks never-scan, stop-all and the deadline, so a stop or a closed
window takes effect within one handshake.

IKE (UDP 500, 4500 with the non-ESP marker): ``ikeprobe`` proposal probing, one packet at a time, at least
``IKE_SPACING`` apart, each through the same gate and limiter, within a per-endpoint packet budget.  OT: OPC UA
GetEndpoints (``otprobe``), Modbus/TCP (port only, nothing sent), Modbus/TCP Security (TLS).  An address with an open
OT port is scanned in fragile mode, one endpoint at a time (OT devices may not cope with parallel handshakes).
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import socket
import threading
import time
from typing import Any

from zs_scan_node import ikeprobe
from zs_scan_node import otprobe
from zs_scan_node import tls_registry as R
from zs_scan_node import tlsenum as E
from zs_scan_node import tlsprobe as T
from zs_scan_node.certparse import cert_facts, load_certs
from zs_scan_node.jobctx import JobContext, LeaseLost, register_asset_types
from zs_scan_node import netutil
from zs_scan_node.netutil import Blocked, checked_ip, iter_line_ips, node_limiter

TCP_PROTOCOLS = {"tls", "starttls-ldap", "starttls-smtp", "starttls-imap", "starttls-postgres", "starttls-mysql",
                 "tds", "ssh", "rdp", "opcua", "modbus", "modbus-tls"}
TLS_LIKE = {"tls", "starttls-ldap", "starttls-smtp", "starttls-imap", "starttls-postgres", "starttls-mysql", "rdp",
            "modbus-tls"}
OT_PROTOCOLS = {"opcua", "modbus", "modbus-tls"}
MAX_OPEN_ENDPOINTS = 5000
CONNECT_TIMEOUT = 2.0  # the sweep's TCP connect: a silent (filtered or absent) address costs this per port
# Addresses swept at once.  The sweep is latency-bound (a silent port holds a worker for CONNECT_TIMEOUT), so enough
# workers that the agreed connections per second, not the timeouts, set the pace; the TLS/SSH probes of open
# endpoints keep their own, smaller concurrency (``deep``) so live hosts see no more parallel handshakes than before.
MAX_SWEEP_PARALLEL = 64
# Hosts that answered on no listed port get a coverage row each (drift: their earlier assets are "not read", never
# removed or resolved); past this many, one job-wide row says so instead of thousands of rows.
MAX_NO_ANSWER_ROWS = 2048
TARPIT_TIMEOUTS = 3
ENDPOINT_MAX_S = 90
IKE_SPACING = 0.2  # seconds between two packets to the same IKE endpoint (at least)
IKE_TIMEOUT = 3.0  # wait for an answer per packet
IKE_FRAGILE_BUDGET = 6
NON_ESP_MARKER = b"\x00\x00\x00\x00"  # RFC 3948 section 2.2: IKE on port 4500
SNI_MAX_NAMES = 200  # SNI host names used per job (the settings allow 10,000): the rest are named in a coverage row
SNI_DNS_BUDGET_S = 20.0  # every name is resolved at once per job, within this time (a black-holed resolver)
SNI_DNS_WORKERS = 16

register_asset_types("ike_endpoint", "ot_endpoint")


class Budget:
    def __init__(self, limit: int) -> None:
        self.limit = max(int(limit or 1), 1)
        self.used = 0

    def take(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


def _scope_ranges(scope: dict) -> list[tuple[str, str]]:
    out = []
    for item in scope.get("ranges") or []:
        if isinstance(item, dict) and item.get("cidr"):
            out.append((str(item["cidr"]), str(item.get("mode") or "full")))
        elif isinstance(item, str):
            out.append((item, "full"))
    return out


def _ports(scope: dict) -> list[dict]:
    ports = []
    for p in scope.get("ports") or []:
        try:
            port = int(p.get("port"))
        except (TypeError, ValueError, AttributeError):
            continue
        if 1 <= port <= 65535:
            ports.append({"port": port, "protocol": str(p.get("protocol") or "tls"), "label": str(p.get("label") or "")})
    return ports


def _sni_names(scope: dict) -> tuple[list[str], int]:
    """The team's SNI host names, normalised and de-duplicated: the first SNI_MAX_NAMES, and how many were left out."""
    seen: list[str] = []
    for raw in scope.get("sni_hostnames") or []:
        name = str(raw or "").strip().lower().rstrip(".")
        if name and name not in seen:
            seen.append(name)
    return seen[:SNI_MAX_NAMES], max(len(seen) - SNI_MAX_NAMES, 0)


def _resolve_all(names: list[str], budget_s: float) -> tuple[dict[str, set[str]], list[str]]:
    """Resolve every name at once (only to match them against the addresses scanned; nothing connects to a name).
    Names without an answer within ``budget_s`` are returned as unresolved; their lookups end in the background
    (getaddrinfo cannot be cancelled), so a black-holed resolver costs the job ``budget_s`` once, not per name."""
    out: dict[str, set[str]] = {}
    if not names:
        return out, []
    pool = cf.ThreadPoolExecutor(max_workers=min(SNI_DNS_WORKERS, len(names)), thread_name_prefix="sni-dns")
    futures = {pool.submit(netutil.resolve, name): name for name in names}
    done, pending = cf.wait(futures, timeout=budget_s)
    for fut in done:
        try:
            out[futures[fut]] = set(fut.result())
        except Exception:  # NXDOMAIN, no answer, a malformed name: it matches no address
            out[futures[fut]] = set()
    pool.shutdown(wait=False, cancel_futures=True)
    return out, [n for n in names if n not in out]


def _tcp(ip: str, port: int, never, timeout: float) -> socket.socket:
    """A TCP connection through the network gate, with tlsprobe's error codes."""
    try:
        return netutil.connect(ip, port, never, timeout)
    except OSError as exc:  # timeout, refused, no route, no IPv6 on this node: one mapping (tlsprobe)
        raise T.connect_error(exc, ip) from None


class Endpoint:
    def __init__(self, ip: str, port: int, protocol: str, label: str) -> None:
        self.ip, self.port, self.protocol, self.label = ip, port, protocol, label

    @property
    def where(self) -> str:
        return f"[{self.ip}]:{self.port}" if ":" in self.ip else f"{self.ip}:{self.port}"


class NetworkScan:
    def __init__(self, ctx: JobContext, scope: dict) -> None:
        self.ctx = ctx
        self.scope = scope
        rl = scope.get("rate_limits") or {}
        self.limiter = node_limiter(rl.get("connections_per_second") or 20, rl.get("parallel_per_server") or 2)
        self.per_endpoint = int(rl.get("handshakes_per_endpoint") or 12)
        self.timeouts: dict[str, int] = {}
        self.open_count = 0
        self._sni_lock = threading.Lock()
        self._sni_order: list[str] | None = None  # the names, in the team's order, resolved once per job
        self._sni_addresses: dict[str, set[str]] = {}
        self.sni_left_out = ""  # names never tried anywhere in this job (over the cap, unresolved), said per endpoint
        self.own_rows: set[str] = set()  # endpoints whose read wrote its own coverage row (no generic second row)

    def sni_names_for(self, ip: str) -> list[str]:
        """The team's SNI names that resolve to ``ip`` and are not on the never-scan list (by name or address)."""
        with self._sni_lock:
            if self._sni_order is None:
                names, over = _sni_names(self.scope)
                self._sni_addresses, unresolved = _resolve_all(names, SNI_DNS_BUDGET_S)
                self._sni_order = names
                parts = []
                if over:
                    parts.append(f"{over} SNI host names beyond the first {SNI_MAX_NAMES} are not used")
                if unresolved:
                    parts.append(f"{len(unresolved)} SNI host names did not resolve within {int(SNI_DNS_BUDGET_S)} s "
                                 f"and were not tried ({', '.join(unresolved[:5])}{', ...' if len(unresolved) > 5 else ''})")
                self.sni_left_out = "; ".join(parts)
        never = self.ctx.never_scan
        out = []
        for name in self._sni_order:
            addresses = self._sni_addresses.get(name) or set()
            if ip in addresses and not never.blocks_host(name) and not any(never.blocks_ip(a) for a in addresses):
                out.append(name)
        return out

    # --------------------------------------------------------------- guarded connection helpers
    def _gate(self, ip: str) -> str | None:
        stop = self.ctx.should_stop(network=True)
        if stop:
            return stop
        try:
            checked_ip(ip, self.ctx.never_scan)  # the network gate: the list can change while the job runs
        except Blocked:
            return "skipped_never_scan"
        if not self.limiter.acquire(self.ctx.cancel, self.ctx.deadline):
            return self.ctx.should_stop(network=True) or self.ctx.deadline_reason
        return None

    def tcp_open(self, ip: str, port: int) -> str:
        """'open' | 'closed' (refused: the host answered) | 'silent' (no answer: filtered or no host) | a skip
        status."""
        gate = self._gate(ip)
        if gate:
            return gate
        try:
            sock = _tcp(ip, port, self.ctx.never_scan, CONNECT_TIMEOUT)
            sock.close()
            return "open"
        except Blocked:
            return "skipped_never_scan"
        except T.ProbeError as exc:
            return "closed" if exc.code == "refused" else "silent"

    def handshake(self, ep: Endpoint, budget: Budget, fn, *args):
        if not budget.take():
            return "budget"
        gate = self._gate(ep.ip)
        if gate:
            raise _Skip(gate)
        with self.limiter.server(ep.ip):
            return fn(*args)

    # --------------------------------------------------------------- per endpoint
    def scan_endpoint(self, ep: Endpoint, mode: str) -> tuple[str, str | None, int]:
        started = time.monotonic()
        if self.timeouts.get(ep.ip, 0) >= TARPIT_TIMEOUTS:
            self.ctx.coverage(ep.ip, "tarpit", "error", f"{ep.ip} answered TCP but timed out on every handshake; "
                              "remaining ports were not probed")
            return "timeout", "tarpit: handshakes time out", 0
        try:
            if ep.protocol in TLS_LIKE:
                return self._tls(ep, mode)
            if ep.protocol == "ssh":
                return self._ssh(ep)
            if ep.protocol == "tds":
                return self._tds(ep)
            if ep.protocol == "opcua":
                return self._opcua(ep)
            if ep.protocol == "modbus":
                return self._modbus(ep)
            return "not_supported", f"{ep.protocol} is not supported by this node version", 0
        except _Skip as skip:
            return skip.status, None, 0
        except Blocked:
            return "skipped_never_scan", None, 0
        except T.ProbeError as exc:
            if exc.code == "timeout":
                self.timeouts[ep.ip] = self.timeouts.get(ep.ip, 0) + 1
            return exc.code if exc.code != "refused" else "refused", exc.detail[:200], 0
        except LeaseLost:
            raise
        except Exception as exc:  # a hostile endpoint must cost one endpoint, never the whole job
            self.ctx.log("probe error", endpoint=ep.where, error=exc.__class__.__name__, level="warn")
            return "error", f"unexpected answer ({exc.__class__.__name__})", 0
        finally:
            _ = started

    def _tls(self, ep: Endpoint, mode: str) -> tuple[str, str | None, int]:
        ctx = self.ctx
        limit = self.per_endpoint if mode != "fragile" else min(self.per_endpoint, 6)
        names = [] if ep.protocol == "rdp" else self.sni_names_for(ep.ip)
        # SNI names other than the one the endpoint is read with get their own share of the endpoint's budget, so the
        # enumeration cannot starve them nor they the enumeration (the total stays the customer's cap)
        reserve = min(max(len(names) - 1, 0), limit // 4) if limit > 1 else 0
        budget = Budget(limit - reserve)
        facts: dict[str, Any] = {"protocol_label": ep.label, "service": ep.protocol, "mode": mode}
        endpoint_deadline = time.monotonic() + ENDPOINT_MAX_S

        def raw(hello: bytes, want_kex: bool = False, timeout: float = 8.0):
            return self.handshake(ep, budget, T.probe, ep.ip, ep.port, ep.protocol, hello, timeout, want_kex)

        def send(hello: bytes, want_kex: bool) -> T.HelloResult:  # enumeration passes: budget and time end a pass
            if time.monotonic() > endpoint_deadline:
                raise E.Stop("endpoint time cap")
            r = raw(hello, want_kex)
            if r == "budget":
                raise E.Stop(f"handshake budget ({limit})")
            return r

        def plaintext(exc: Exception):
            ctx.emit("tls_endpoint", ep.ip, ep.where, name=f"{ep.label or ep.protocol} {ep.where}", protocol=ep.protocol,
                     facts={**facts, "tls": False, "plaintext_only": True, "detail": str(exc)})
            return "ok", None, 1

        # 1. full handshake (without SNI, as a client that knows only the address)
        try:
            if T.have_openssl() and ep.protocol != "rdp":
                fh = self.handshake(ep, budget, T.s_client, ep.ip, ep.port, ep.protocol, None,
                                    min(15.0, max(ctx.time_left(), 1)))
            else:
                fh = self.handshake(ep, budget, T.python_handshake, ep.ip, ep.port, ep.protocol, None, 10.0)
        except T.StarttlsUnavailable as exc:
            return plaintext(exc)
        if fh == "budget":
            fh = T.FullHandshake(error="no budget")
        if not fh.ok and fh.error == "timeout":
            # one cheap raw probe decides whether this endpoint speaks TLS at all; a second silence ends it
            try:
                quick = raw(T.build_client_hello(T.TLS12, T.LEGACY_SUITES), timeout=6.0)
            except T.ProbeError as exc:
                return exc.code, f"no TLS answer ({exc.detail})", 0
            except T.StarttlsUnavailable:
                quick = None
            if quick is not None and quick != "budget" and not quick.ok and not quick.alert:
                return "timeout", "no TLS answer", 0
        sni: str | None = None
        alerts: list[str] = []
        if not fh.ok:
            # 1b. TLS at all?  Any TLS alert = it speaks TLS (it may want a server name); only a close or non-TLS
            # bytes, to a modern and to a legacy hello, mean "not TLS" (CB-04 EC-4: alert != closed)
            try:
                kind, seen, not_tls = self._speaks_tls(ep, budget, None)
                if kind == "not_tls" and names:
                    kind, seen, not_tls = self._speaks_tls(ep, budget, names[0], legacy=False)
            except T.StarttlsUnavailable as exc:
                return plaintext(exc)
            alerts += seen
            if kind == "not_tls":
                ctx.coverage(ep.ip, f"not TLS {ep.where}", "not_tls",
                             f"{ep.label or ep.protocol} {ep.where} answered TCP on a port listed as TLS but did not "
                             f"speak TLS: {not_tls}", scope=[ep.where], incomplete=False)
                self.own_rows.add(ep.where)
                return "ok", None, 0
            if kind == "alert" and names and T.have_openssl() and ep.protocol != "rdp":
                # 1c. it rejects a client without a server name: read it with the names the team configured
                for name in names[:3]:
                    sfh = self.handshake(ep, budget, T.s_client, ep.ip, ep.port, ep.protocol, name, 15.0)
                    if sfh == "budget":
                        break
                    if sfh.ok:
                        fh, sni = sfh, name
                        break
        cipher_code = R.suite_code(fh.cipher)
        facts.update({"negotiated_version": fh.version,
                      "negotiated_cipher": R.suite_name(cipher_code) if cipher_code is not None else fh.cipher,
                      "negotiated_cipher_code": R.code_hex(cipher_code) if cipher_code is not None else None,
                      "negotiated_group": E.iana_group(fh.group),
                      "server_temp_key": fh.temp_key, "peer_signature_type": fh.peer_sig_type,
                      "peer_signing_digest": fh.peer_sig_digest, "secure_renegotiation": fh.secure_renegotiation,
                      "client_auth_requested": fh.client_auth_requested, "handshake_tool": fh.tool})
        if sni:
            facts.update({"sni": sni, "sni_required": True})
        chain = []
        for der in fh.certs_der[:50]:
            for cert in load_certs(der):
                chain.append(cert_facts(cert, "tls"))
        facts["chain_length"] = len(chain)
        if chain:
            facts["leaf"] = {k: chain[0].get(k) for k in ("subject", "issuer", "not_after", "key_alg", "key_size",
                                                         "curve", "sig_alg", "fingerprint_sha256", "self_signed", "san")}
        # 2. protocol versions (with the server name the endpoint was read with)
        versions: dict[str, bool | None] = {}
        known: dict[str, set[int]] = {}  # version -> suites seen accepted (the enumeration starts from them)
        unread: list[str] = []  # checks that could not run: their findings must not read as fixed (drift)
        tls13 = fh.ok and fh.version == "TLSv1.3"
        if fh.ok and cipher_code is not None and fh.version in T.VERSION_NAMES.values():
            known.setdefault(fh.version, set()).add(cipher_code)
        sni_refused = not fh.ok and "unrecognized_name" in alerts and not names
        for v in (T.SSL3, T.TLS10, T.TLS11, T.TLS12):
            name = T.VERSION_NAMES[v]
            if time.monotonic() > endpoint_deadline:
                versions[name] = None
                facts["endpoint_time_cap"] = True
                unread.append(f"{name}: endpoint time cap")
                continue
            if fh.ok and fh.version == name:
                versions[name] = True
                continue
            if sni_refused:  # it said it needs a server name: every probe without one gets the same alert
                versions[name] = None
                continue
            try:
                r = raw(T.build_client_hello(v, T.LEGACY_SUITES, sni=sni))
            except T.StarttlsUnavailable as exc:
                return plaintext(exc)
            except T.ProbeError as exc:
                versions[name] = None
                facts.setdefault("probe_errors", []).append(f"{name}: {exc.code}")
                if exc.code != "refused":  # a reset is this server's way to refuse a version, every time
                    unread.append(f"{name}: {exc.code}")
                continue
            if r == "budget":
                versions[name] = None
                unread.append(f"{name}: handshake budget")
                continue
            versions[name] = bool(r.ok and r.version == v)
            if versions[name] and r.cipher is not None:
                known.setdefault(name, set()).add(r.cipher)
            elif r.alert:
                alerts.append(r.alert)
        if tls13:
            versions["TLSv1.3"] = True
        elif sni_refused:
            versions["TLSv1.3"] = None
        else:
            try:
                r = raw(T.build_client_hello(T.TLS12, T.TLS13_SUITES, sni=sni, tls13=True, key_share_groups=[29]))
                versions["TLSv1.3"] = None if r == "budget" else bool(r.ok and (r.version == T.TLS13 or r.hrr))
                if r == "budget":
                    unread.append("TLSv1.3: handshake budget")
                elif versions["TLSv1.3"] and r.cipher is not None:
                    known.setdefault("TLSv1.3", set()).add(r.cipher)
                elif r.alert:
                    alerts.append(r.alert)
            except (T.ProbeError, T.StarttlsUnavailable) as exc:
                versions["TLSv1.3"] = None
                if getattr(exc, "code", None) != "refused":
                    unread.append(f"TLSv1.3: {getattr(exc, 'code', 'starttls')}")
        facts["versions"] = versions
        supported = [k for k, v in versions.items() if v]
        if not fh.ok and not supported:
            if alerts or sni_refused:
                facts.update({"handshakes_used": budget.used, "handshake_budget": limit})
                return self._no_common_parameters(ep, facts, alerts, names, sni_refused)
            status = "timeout" if fh.error == "timeout" else "error"
            return status, fh.error or "no TLS handshake", 0
        # 3. post-quantum groups (TLS 1.3): the node's one PQ probe (the rest of the PQ groups come with step 6)
        groups: dict[str, list[int]] = {}
        groups_done: dict[str, bool] = {}
        not_complete: list[str] = []
        pq = E.Pass()
        if mode != "fragile" and versions.get("TLSv1.3"):
            pq = E.tls13_groups(send, E.PQ_OFFER, sni, max_probes=1)
            # as the single PQ probe always read it: any answer decides; an error or no budget leaves it unknown
            facts["pq_hybrid"] = bool(pq.found) if pq.answered else None
            if pq.answered:
                facts["pq_group"] = (T.GROUPS.get(pq.found[0]) or R.group_name(pq.found[0])) if pq.found else None
        elif mode != "fragile":
            facts["pq_hybrid"] = False
        # 4. downgrade protection
        order = [T.TLS13, T.TLS12, T.TLS11, T.TLS10]
        sup = [v for v in order if versions.get(T.VERSION_NAMES[v])]
        if mode != "fragile" and len(sup) >= 2:
            below = sup[1]
            try:
                r = raw(T.build_client_hello(below, T.LEGACY_SUITES, sni=sni, fallback_scsv=True))
                if r != "budget":
                    facts["fallback_scsv"] = (r.alert == "inappropriate_fallback")
                    facts["downgrade_exposed"] = bool(r.ok)
            except (T.ProbeError, T.StarttlsUnavailable):
                pass
        # 5. weak classes on the best legacy version (a small budget still finds the weak suites first)
        legacy = next((v for v in (T.TLS12, T.TLS11, T.TLS10, T.SSL3) if versions.get(T.VERSION_NAMES[v])), None)
        kex: dict[str, Any] = {}
        if mode != "fragile" and legacy is not None:
            for label, suites in (("obsolete", T.OBSOLETE), ("static_rsa", T.STATIC_RSA), ("cbc", T.CBC_FS),
                                  ("dhe", T.DHE_SUITES)):
                try:
                    r = raw(T.build_client_hello(legacy, suites, sni=sni), label == "dhe")
                except (T.ProbeError, T.StarttlsUnavailable) as exc:
                    if getattr(exc, "code", None) != "refused":
                        unread.append(f"{label} ciphers: {getattr(exc, 'code', 'starttls')}")
                    continue
                if r == "budget":
                    facts["budget_exhausted"] = True
                    unread.append(f"{label} ciphers: handshake budget")
                    break
                if r.ok and r.version == legacy and r.cipher in suites:
                    known.setdefault(T.VERSION_NAMES[legacy], set()).add(r.cipher)
                    if label == "dhe" and r.dh_bits:
                        kex["dh_bits"] = r.dh_bits
            facts["weak_cipher_probe_version"] = T.VERSION_NAMES[legacy]
        # 6-9. enumeration (#100): TLS 1.3 groups and suites, then every legacy version's suites, best first
        complete: dict[str, bool] = {}
        if mode == "fragile":
            not_complete.append("fragile mode: suites and groups are not enumerated")
        else:
            if versions.get("TLSv1.3"):
                if pq.reason == "continued later":  # the PQ probe found one: every other PQ group the server takes
                    more = E.tls13_groups(send, [g for g in E.PQ_OFFER if g not in pq.found], sni)
                    pq = E.Pass(found=pq.found + more.found, complete=more.complete, reason=more.reason, answered=True)
                groups["pq"], groups_done["pq"] = pq.found, pq.complete
                facts["pq_groups"] = [R.group_name(g) for g in pq.found]
                facts["pq_groups_enumerated"] = pq.complete
                if not pq.complete:
                    not_complete.append(f"PQ groups: {pq.reason}")
                p = E.tls13_groups(send, E.CLASSICAL13_OFFER, sni)
                groups["classical"], groups_done["classical"] = p.found, p.complete
                facts["classical_tls13_accepted"] = bool(p.found) if (p.found or p.complete) else None
                if not p.complete:
                    not_complete.append(f"TLS 1.3 groups: {p.reason}")
                p = E.tls13_suites(send, known.get("TLSv1.3", set()), sni)
                known.setdefault("TLSv1.3", set()).update(p.found)
                complete["TLSv1.3"] = p.complete
                if not p.complete:
                    not_complete.append(f"TLSv1.3 suites: {p.reason}")
            for v in E.VERSION_ORDER:
                vname = T.VERSION_NAMES[v]
                if not versions.get(vname):
                    continue
                p = E.legacy_suites(send, v, known.get(vname, set()), sni, kex)
                known.setdefault(vname, set()).update(p.found)
                complete[vname] = p.complete
                if not p.complete:
                    not_complete.append(f"{vname} suites: {p.reason}")
            if not versions.get("TLSv1.3") and legacy is not None:
                ecdhe = sorted(c for c in known.get(T.VERSION_NAMES[legacy], set()) if E.is_ecdhe(c))
                if ecdhe:
                    p = E.legacy_curves(send, legacy, ecdhe, set(), sni)
                    groups["legacy"], groups_done["legacy"] = p.found, p.complete
                    if not p.complete:
                        not_complete.append(f"{T.VERSION_NAMES[legacy]} curves: {p.reason}")
                else:  # no ECDHE suite: no named group is used, and that is complete when the suite list is
                    groups["legacy"] = sorted(kex.get("curves") or [])
                    groups_done["legacy"] = bool(complete.get(T.VERSION_NAMES[legacy]))
        all_codes = sorted({c for s in known.values() for c in s})
        facts["ciphers"] = [R.suite_name(c) for c in all_codes]
        facts["cipher_suites"] = {v: [E.suite_entry(c) for c in sorted(known[v])] for v in sorted(known)}
        facts["cipher_suites_complete"] = {v: complete.get(v, False) for v in sorted(known)}
        found_groups = [g for part in ("pq", "classical", "legacy") for g in groups.get(part, [])]
        facts["groups"] = sorted({R.group_name(g) for g in found_groups})
        facts["groups_complete"] = bool(groups_done) and all(groups_done.values()) and mode != "fragile"
        weak: dict[str, list[str]] = {}
        for vname, codes in known.items():
            if vname == "TLSv1.3":
                continue
            for c in codes:
                for label in sorted(E.suite_classes(R.suite_name(c))):
                    if R.suite_name(c) not in weak.setdefault(label, []):
                        weak[label].append(R.suite_name(c))
        if mode != "fragile" and legacy is not None:
            facts["weak_ciphers_accepted"] = {k: sorted(v) for k, v in sorted(weak.items())}
        if kex.get("dh_bits"):
            facts["dh_bits"] = kex["dh_bits"]
        facts["enumeration"] = {"complete": not not_complete, "not_complete": not_complete[:12]}
        facts["handshakes_used"] = budget.used
        facts["handshake_budget"] = limit
        facts["tls"] = True
        if unread:
            facts["checks_not_run"] = unread[:20]
            # listed, with some facts missing: a finding that vanishes from this endpoint is not proven fixed
            ctx.coverage(ep.ip, f"TLS checks {ep.where}", "incomplete", "; ".join(unread)[:900],
                         scope=[ep.where], incomplete=True)
        top = next((v for v in ("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3") if versions.get(v)), fh.version)
        assets = 0
        ctx.emit("tls_endpoint", ep.ip, ep.where, name=f"{ep.label or ep.protocol} {ep.where}",
                 algorithm=facts["negotiated_cipher"], protocol=top, facts=facts)
        assets += 1
        for i, c in enumerate(chain):
            extra = {"sni": sni} if sni else {}
            ctx.emit("certificate", ep.ip, f"{ep.where}#chain[{i}]", name=c.get("subject", ""),
                     algorithm=c.get("key_alg"), key_size=c.get("key_size"), facts={**c, "chain_index": i, **extra})
            assets += 1
        return "ok", None, assets + self._sni_variants(ep, names, sni, chain, Budget(reserve) if reserve else budget)

    def _speaks_tls(self, ep: Endpoint, budget: Budget, sni: str | None,
                    legacy: bool = True) -> tuple[str, list[str], str]:
        """('hello' | 'alert' | 'not_tls', alerts seen, what a non-TLS answer was) from a modern ClientHello (TLS
        1.0-1.3 offered) and, when that gets no TLS answer, a legacy TLS 1.0 one (some old stacks drop TLS 1.3-style
        hellos).  A timeout raises."""
        hellos = [T.build_client_hello(T.TLS12, T.TLS13_SUITES + T.LEGACY_SUITES, sni=sni, tls13=True,
                                       groups=T.CLASSICAL_GROUPS + T.PQ_GROUPS, key_share_groups=[29],
                                       versions13=[T.TLS13, T.TLS12, T.TLS11, T.TLS10])]
        if legacy:
            hellos.append(T.build_client_hello(T.TLS10, T.LEGACY_SUITES, sni=sni))
        details: list[str] = []
        for hello in hellos:
            try:
                r = self.handshake(ep, budget, T.probe, ep.ip, ep.port, ep.protocol, hello, 8.0)
            except T.NotTls as exc:
                details.append(f"answered '{exc.first}'")
                continue
            except T.ProbeError as exc:
                if exc.code != "refused":  # a timeout or a garbled flight decides nothing
                    raise
                details.append("reset the connection without a TLS answer")
                continue
            if r == "budget":
                return "alert", [], ""  # not decided: never call it "not TLS" without the evidence
            if r.ok:
                return "hello", [], ""
            if r.alert:
                return "alert", [r.alert], ""
            details.append("closed the connection without a TLS answer")
        said = (f"{details[0]} ({len(details)} handshake{'s' if len(details) > 1 else ''})"
                if len(set(details)) == 1 else "; ".join(details))
        return "not_tls", [], said

    def _no_common_parameters(self, ep: Endpoint, facts: dict[str, Any], alerts: list[str], names: list[str],
                              sni_refused: bool) -> tuple[str, str | None, int]:
        """It speaks TLS (it sent alerts) but no handshake succeeded: a TLS endpoint with nothing read, and a gap that
        keeps its earlier findings from reading as fixed.  Never "ok"."""
        needs_name = "unrecognized_name" in alerts
        seen = sorted(set(alerts))
        if needs_name and not names:
            why = ("the server answers only clients that send a server name (SNI; alert unrecognized_name): add the "
                   "host names it serves under Hostnames for SNI")
        elif needs_name:
            why = ("the server rejected the configured SNI host names that resolve to this address "
                   f"({', '.join(names[:3])}) and every handshake without one (alert unrecognized_name)")
        else:
            why = (f"the server answered every handshake with a TLS alert ({', '.join(seen)}): it offers no protocol "
                   "version, cipher suite or group this scan node can negotiate")
        facts.update({"tls": True, "negotiation": "sni_required" if needs_name else "no_common_parameters",
                      "alerts": seen, "detail": why})
        for key in ("negotiated_version", "negotiated_cipher", "negotiated_cipher_code", "negotiated_group"):
            if facts.get(key) is None:
                facts.pop(key, None)
        self.ctx.emit("tls_endpoint", ep.ip, ep.where, name=f"{ep.label or ep.protocol} {ep.where}",
                      protocol=ep.protocol, facts=facts)
        self.ctx.coverage(ep.ip, f"TLS {ep.where}", "sni_required" if needs_name else "no_common_parameters",
                          f"{ep.label or ep.protocol} {ep.where}: {why}", scope=[ep.where], incomplete=True)
        self.own_rows.add(ep.where)
        return ("tls_unavailable" if needs_name else "not_supported"), why[:200], 1

    def _sni_variants(self, ep: Endpoint, names: list[str], used: str | None, chain: list[dict], budget: Budget) -> int:
        """One full handshake per further SNI name (its certificate, when it differs); names not tried get one row."""
        ctx = self.ctx
        assets, untried = 0, []
        others = [n for n in names if n != used]
        if not T.have_openssl() or ep.protocol == "rdp":
            return 0
        for i, name in enumerate(others):
            try:
                sfh = self.handshake(ep, budget, T.s_client, ep.ip, ep.port, ep.protocol, name, 15.0)
            except _Skip:
                untried = others[i:]
                break
            if sfh == "budget":
                untried = others[i:]
                break
            for der in sfh.certs_der[:1]:
                for cert in load_certs(der):
                    cf_ = cert_facts(cert, "tls")
                    if chain and cf_.get("fingerprint_sha256") == chain[0].get("fingerprint_sha256"):
                        continue  # same certificate as without SNI: nothing new
                    ctx.emit("certificate", ep.ip, f"{ep.where}#sni={name}", name=cf_.get("subject", ""),
                             algorithm=cf_.get("key_alg"), key_size=cf_.get("key_size"),
                             facts={**cf_, "sni": name, "negotiated_version": sfh.version})
                    assets += 1
        reasons = []
        if untried:
            reasons.append(f"{len(untried)} of {len(others)} SNI host names were not tried (handshake budget): "
                           f"{', '.join(untried[:5])}{', ...' if len(untried) > 5 else ''}")
        if self.sni_left_out:
            reasons.append(self.sni_left_out)
        if reasons:
            # their certificates seen before are "not read", never removed
            ctx.coverage(ep.ip, f"SNI names {ep.where}", "truncated", "; ".join(reasons)[:900],
                         scope=[f"{ep.where}#sni="], incomplete=False)
        return assets

    def _ssh(self, ep: Endpoint) -> tuple[str, str | None, int]:
        budget = Budget(2)
        algs = self.handshake(ep, budget, T.ssh_kexinit, ep.ip, ep.port, 8.0)
        host = self.handshake(ep, budget, T.ssh_host_key, ep.ip, ep.port, 10.0)
        facts = {"banner": algs.pop("banner", None), **algs, "host_key": host if isinstance(host, dict) else None}
        self.ctx.emit("ssh_endpoint", ep.ip, ep.where, name=f"SSH {ep.where}",
                      algorithm=(host or {}).get("key_type") if isinstance(host, dict) else None,
                      key_size=(host or {}).get("bits") if isinstance(host, dict) else None, protocol="ssh", facts=facts)
        return "ok", None, 1

    def _tds(self, ep: Endpoint) -> tuple[str, str | None, int]:
        budget = Budget(1)

        def run():
            sock = _tcp(ep.ip, ep.port, self.ctx.never_scan, 3.0)
            try:
                return T.tds_prelogin(sock, time.monotonic() + 8.0)
            finally:
                sock.close()

        info = self.handshake(ep, budget, run)
        self.ctx.emit("tls_endpoint", ep.ip, ep.where, name=f"SQL Server {ep.where}", protocol="tds",
                      facts={"service": "tds", **info, "detail": "TDS PRELOGIN encryption flag only"})
        return "ok", None, 1

    # --------------------------------------------------------------- OT
    def _modbus(self, ep: Endpoint) -> tuple[str, str | None, int]:
        """Modbus/TCP has no encryption or authentication.  The sweep's TCP connect is all that happens: no Modbus
        request (not even a read) is sent to the device."""
        self.ctx.emit("ot_endpoint", ep.ip, ep.where, name=f"{ep.label or 'Modbus/TCP'} {ep.where}", protocol="modbus",
                      facts={"service": "modbus", "port": ep.port, "tls": False, "identified_by": "port",
                             "detail": "TCP port accepts connections; no Modbus request was sent"})
        return "ok", None, 1

    def _opcua(self, ep: Endpoint) -> tuple[str, str | None, int]:
        url = f"opc.tcp://{ep.where}"

        def run():
            sock = _tcp(ep.ip, ep.port, self.ctx.never_scan, 3.0)
            try:
                return otprobe.get_endpoints(sock, url, time.monotonic() + min(20.0, max(self.ctx.time_left(), 1)))
            finally:
                sock.close()

        try:
            endpoints = self.handshake(ep, Budget(1), run)
        except otprobe.UaError as exc:
            if exc.code == "refused":  # an OPC UA server that refuses discovery on an unsecured channel
                self.ctx.emit("ot_endpoint", ep.ip, ep.where, name=f"{ep.label or 'OPC UA'} {ep.where}",
                              protocol="opcua", facts={"service": "opcua", "port": ep.port, "discovery": "refused",
                                                       "detail": exc.detail[:200]})
                return "ok", None, 1
            return ("timeout" if exc.code == "timeout" else "error"), exc.detail[:200], 0
        facts = {"service": "opcua", "port": ep.port, **otprobe.summarize(endpoints)}
        n = 0
        seen: set[str] = set()
        for e in endpoints:
            for cert in load_certs(e.get("certificate_der") or b""):
                cfacts = cert_facts(cert, "opcua")
                fp = cfacts.get("fingerprint_sha256")
                if fp in seen:
                    continue
                seen.add(fp)
                self.ctx.emit("certificate", ep.ip, f"{ep.where}#opcua-cert[{len(seen) - 1}]",
                              name=cfacts.get("subject", ""), algorithm=cfacts.get("key_alg"),
                              key_size=cfacts.get("key_size"), facts={**cfacts, "role": "opcua-server"})
                n += 1
        self.ctx.emit("ot_endpoint", ep.ip, ep.where, name=f"{ep.label or 'OPC UA'} {ep.where}", protocol="opcua",
                      facts=facts)
        return "ok", None, n + 1

    # --------------------------------------------------------------- IKE
    def _pause(self, seconds: float) -> bool:
        """Wait (for a gateway's half-open IKE SAs to expire) unless a stop, a closed window or the deadline comes."""
        if self.ctx.time_left() < seconds + 10:
            return False
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self.ctx.should_stop(network=True) or self.ctx.cancel.wait(min(1.0, end - time.monotonic())):
                return False
        return True

    def scan_ike(self, ep: Endpoint, mode: str, primary: bool) -> tuple[str, str | None, int]:
        """('ok', None, assets) when the gateway answered, ('no_answer', reason, 0) when it stayed silent."""
        nat_t = ep.port == 4500
        budget = IKE_FRAGILE_BUDGET if mode == "fragile" else min(max(2 * self.per_endpoint, 12), 40)
        last = [0.0]
        try:
            sock = netutil.udp_connect(ep.ip, ep.port, self.ctx.never_scan, IKE_TIMEOUT)
        except Blocked:
            return "skipped_never_scan", None, 0
        except OSError as exc:
            return "no_answer", exc.__class__.__name__, 0

        def send(packet: bytes, ident: bytes) -> bytes | None:
            gate = self._gate(ep.ip)  # stop-all, never-scan (live), deadline, rate limiter: per packet
            if gate:
                raise _Skip(gate)
            wait = IKE_SPACING - (time.monotonic() - last[0])
            if wait > 0 and self.ctx.cancel.wait(wait):
                raise _Skip("skipped_cancelled")
            with self.limiter.server(ep.ip):
                last[0] = time.monotonic()
                try:
                    sock.send((NON_ESP_MARKER if nat_t else b"") + packet)
                except OSError:
                    return None
                end = time.monotonic() + IKE_TIMEOUT
                while time.monotonic() < end:
                    sock.settimeout(max(end - time.monotonic(), 0.05))
                    try:
                        data = sock.recv(65535)
                    except socket.timeout:
                        return None
                    except OSError:  # ICMP port unreachable on a connected socket
                        return None
                    if nat_t:
                        if data[:4] != NON_ESP_MARKER:
                            continue
                        data = data[4:]
                    if data[:8] == ident:  # an answer to this message (late answers to older ones are dropped)
                        return data
                return None

        try:
            facts = ikeprobe.IkeProber(send, budget, mode, primary, pause=self._pause).run()
        finally:
            sock.close()
        if not ikeprobe.answered(facts):
            return "no_answer", "no IKE answer", 0
        v2, v1 = facts.get("ikev2") or {}, facts.get("ikev1") or {}
        version = "IKEv2" if v2.get("supported") and v2.get("proposals_accepted") is not False else \
            ("IKEv1" if v1.get("accepts") else "IKE")
        chosen = (v2.get("chosen") or v1.get("chosen") or {}).get("encryption")
        self.ctx.emit("ike_endpoint", ep.ip, ep.where, name=f"{ep.label or 'IKE'} {ep.where}/udp", algorithm=chosen,
                      protocol=version, facts={"service": "ike", "port": ep.port, "nat_t": nat_t, **facts})
        return "ok", None, 1


class _Skip(Exception):
    def __init__(self, status: str) -> None:
        super().__init__(status)
        self.status = status


def _addresses(ctx: JobContext, ranges: list[tuple[str, str]]):
    seen: set[str] = set()
    for cidr, mode in ranges:
        ips = iter_line_ips(cidr)
        if ips is None:
            continue
        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)
            yield ip, mode


def run_network(ctx: JobContext, scope: dict, discovery_only: bool = False) -> str | None:
    """Returns a summary line.  Outcomes are recorded per address (and per endpoint for failures)."""
    scan = NetworkScan(ctx, scope)
    ports = _ports(scope)
    tcp_ports = [p for p in ports if p["protocol"] in TCP_PROTOCOLS]
    ike_ports = [] if discovery_only else [p for p in ports if p["protocol"] == "ike"]  # discovery is a TCP sweep
    ranges = _scope_ranges(scope)
    if not ranges:
        return "no ranges in scope"
    cps = max(1, int((scope.get("rate_limits") or {}).get("connections_per_second") or 20))
    per_server = max(1, int((scope.get("rate_limits") or {}).get("parallel_per_server") or 2))
    # handshakes (openssl, raw probes, SSH, IKE) on open endpoints: as many addresses at once as before
    deep = threading.BoundedSemaphore(max(1, min(cps // 2, 16)))
    # the TCP sweep: each address sweeps its ports ``per_server`` at a time; enough addresses at once that silent
    # ports (CONNECT_TIMEOUT each) do not set the pace -- the agreed connections per second do (the limiter)
    parallel = max(1, min(int(cps * CONNECT_TIMEOUT) + 1, MAX_SWEEP_PARALLEL))
    open_endpoints = 0
    truncated = False
    no_answer = [0]  # addresses that answered on no listed port
    no_answer_lock = threading.Lock()

    def note_silent(ip: str, ports_tried: list[dict]) -> None:
        """Coverage for an address that answered on no listed port: drift lists its earlier assets as "not read"
        (it may be down, filtered or gone; one sweep cannot tell), never as removed or fixed."""
        with no_answer_lock:
            no_answer[0] += 1
            n = no_answer[0]
        if n <= MAX_NO_ANSWER_ROWS:
            listed = ", ".join(str(p["port"]) for p in ports_tried[:20])
            ctx.coverage(ip, "no answer", "unreachable",
                         f"{ip} did not answer on any listed port ({listed}{', ...' if len(ports_tried) > 20 else ''}); "
                         "filtered, down or no host at this address")
        else:
            ctx.coverage("", "no answer", "unreachable", f"more than {MAX_NO_ANSWER_ROWS} addresses did not answer on "
                         "any listed port; the rest are not listed one by one", once=True)

    def sweep(ip: str) -> tuple[str | None, list[tuple[dict, str]]]:
        """(skip status or None, [(port, state)]) -- ports ``per_server`` at a time, each through the limiter."""
        if not tcp_ports:
            return None, []
        with cf.ThreadPoolExecutor(max_workers=min(per_server, len(tcp_ports))) as sp:
            states = list(sp.map(lambda p: (p, scan.tcp_open(ip, p["port"])), tcp_ports))
        skip = next((s for _p, s in states if s.startswith("skipped_")), None)
        return skip, states

    def do_address(ip: str, mode: str):
        try:
            return _do_address(ip, mode)
        except LeaseLost:
            raise
        except Exception as exc:  # one address must never end the whole range
            ctx.log("address error", target=ip, error=exc.__class__.__name__, level="warn")
            ctx.outcome(ip, "error", f"node error ({exc.__class__.__name__})")
            return 0
        finally:
            ctx.address_done()

    def _do_address(ip: str, mode: str):
        started = time.monotonic()
        stop = ctx.should_stop(network=True)
        if stop:
            ctx.outcome(ip, stop, started=started)
            return 0
        if ctx.never_scan.blocks_ip(ip):
            ctx.outcome(ip, "skipped_never_scan", started=started)
            return 0
        skip, states = sweep(ip)
        if skip:
            ctx.outcome(ip, skip, started=started)
            return 0
        open_eps = [Endpoint(ip, p["port"], p["protocol"], p["label"]) for p, s in states if s == "open"]
        tcp_answered = any(s in ("open", "closed") for _p, s in states)
        silent_ports = [p for p, s in states if s == "silent"]
        if discovery_only:
            for ep in open_eps:
                ctx.emit("open_port", ip, ep.where, name=f"{ep.label or ep.protocol} {ep.where}", protocol=ep.protocol,
                         facts={"port": ep.port, "protocol": ep.protocol, "label": ep.label})
            # no coverage rows here: a discovery job's assets are its open ports (the UI counts them as "open
            # endpoints"), and discovery is never compared for drift
            ctx.outcome(ip, "ok", started=started, assets=len(open_eps))
            return len(open_eps)
        failures: list[str] = []
        assets = 0
        skip_status = None
        workers = per_server
        if any(ep.protocol in OT_PROTOCOLS for ep in open_eps):
            # an OT device: fragile mode for every endpoint of the address, one connection at a time
            mode, workers = "fragile", 1
            ctx.coverage(ip, "ot fragile mode", "truncated", "OT port open: only fragile-mode checks were run on this "
                         "address, one connection at a time")

        def one(ep: Endpoint):
            t0 = time.monotonic()
            status, err, n = scan.scan_endpoint(ep, mode)
            return ep, status, err, n, t0

        if open_eps:
            with deep, cf.ThreadPoolExecutor(max_workers=workers) as eps_pool:
                for ep, status, err, n, t0 in eps_pool.map(one, open_eps):
                    assets += n
                    if status.startswith("skipped_"):
                        skip_status = skip_status or status
                        continue
                    if status != "ok":
                        failures.append(f"{ep.port}:{status}")
                        ctx.outcome(ep.where, status, err, started=t0, assets=n, counted=False)
                        if ep.where in scan.own_rows:
                            continue
                        # the port is open but was not read: what it showed before is "not read", not fixed
                        ctx.coverage(ip, f"endpoint {ep.where}", "error" if status in ("not_supported",) else status,
                                     f"{ep.label or ep.protocol} {ep.where}: {err or status}"[:900],
                                     scope=[ep.where], incomplete=False)
        # IKE over UDP: no connect to tell an open port, so every listed IKE port gets a probe; the first silent one
        # (no answer to IKEv2 or IKEv1) ends IKE on this address
        ike_answered = False
        for i, p in enumerate(ike_ports):
            ep = Endpoint(ip, p["port"], "ike", p["label"])
            t0 = time.monotonic()
            try:
                status, err, n = scan.scan_ike(ep, mode, primary=i == 0)
            except _Skip as skip:
                status, err, n = skip.status, None, 0
            except LeaseLost:
                raise
            except Exception as exc:  # a hostile gateway must cost one endpoint, never the whole job
                ctx.log("ike probe error", endpoint=ep.where, error=exc.__class__.__name__, level="warn")
                status, err, n = "error", f"unexpected answer ({exc.__class__.__name__})", 0
            assets += n
            if status.startswith("skipped_"):
                skip_status = skip_status or status
                break
            if status == "no_answer":
                break
            ike_answered = True
            if status != "ok":
                failures.append(f"{ep.port}/udp:{status}")
                ctx.outcome(f"{ep.where}/udp", status, err, started=t0, assets=n, counted=False)
        if skip_status and assets == 0:
            ctx.outcome(ip, skip_status, started=started)
            return len(open_eps)
        if not tcp_answered and not ike_answered:
            note_silent(ip, tcp_ports + ike_ports)
        elif silent_ports and not skip_status:
            # the host is up, these ports did not answer (filtered): an endpoint seen there before is "not read"
            ctx.coverage(ip, "ports not answering", "timeout",
                         "no answer on " + ", ".join(str(p["port"]) for p in silent_ports[:40]) +
                         " (filtered, or a host firewall drops the connection)",
                         scope=[f"{ip}:{p['port']}" if ":" not in ip else f"[{ip}]:{p['port']}" for p in silent_ports],
                         incomplete=False)
        ctx.outcome(ip, "ok", "; ".join(failures)[:250] if failures else None, started=started, assets=assets)
        return len(open_eps)

    # every address in scope, once: the job reports "N of M addresses" while it runs
    addresses = list(_addresses(ctx, ranges))
    ctx.set_progress_total(len(addresses))
    with cf.ThreadPoolExecutor(max_workers=parallel) as pool:
        pending: set[cf.Future] = set()
        for ip, mode in addresses:
            if open_endpoints >= MAX_OPEN_ENDPOINTS:
                truncated = True
                ctx.outcome(ip, "skipped_deadline", "open-endpoint cap reached")
                ctx.address_done()
                continue
            if ctx.should_stop(network=True):
                ctx.outcome(ip, ctx.should_stop(network=True) or "skipped_deadline")
                ctx.address_done()
                continue
            pending.add(pool.submit(do_address, ip, mode))
            if len(pending) >= parallel * 2:
                done, pending = cf.wait(pending, return_when=cf.FIRST_COMPLETED)
                for f in done:
                    open_endpoints += f.result() or 0
        for f in cf.as_completed(pending):
            open_endpoints += f.result() or 0
    if truncated:
        ctx.truncated = True
        ctx.coverage("", "open endpoints", "truncated", f"stopped after {MAX_OPEN_ENDPOINTS} open endpoints", once=True)
    return f"{open_endpoints} open endpoints"


def test_range(ctx: JobContext, scope: dict) -> str:
    """Connection test for a range: can the node route to a few addresses?  A refused port counts as reachable
    (the host answered); only silence is 'unreachable'.  At most 5 addresses x 4 ports, no TLS handshakes."""
    scan = NetworkScan(ctx, scope)
    ports = [p for p in _ports(scope) if p["protocol"] in TCP_PROTOCOLS][:4] or [{"port": 443, "protocol": "tls", "label": ""}]
    picked = []
    for ip, _mode in _addresses(ctx, _scope_ranges(scope)):
        if ctx.never_scan.blocks_ip(ip):
            continue
        picked.append(ip)
        if len(picked) >= 5:
            break
    for ip in picked:
        open_ports, answered, note = [], False, ""
        for p in ports:
            gate = scan._gate(ip)
            if gate:
                note = gate
                break
            try:
                _tcp(ip, p["port"], ctx.never_scan, 2.0).close()
                open_ports.append(p["port"])
                answered = True
            except Blocked:
                note = "skipped_never_scan"
                break
            except T.ProbeError as exc:
                if exc.code == "refused":
                    answered = True
        ctx.samples.append({"target": ip, "status": "ready" if answered else "unreachable", "reachable": answered,
                            "login": None, "privilege": None,
                            "note": note or (f"open: {', '.join(map(str, open_ports))}" if open_ports else
                                             ("host answered; no listed port open" if answered else
                                              "no answer on the listed ports"))})
        ctx.outcome(ip, "ok" if answered else "unreachable")
    if not picked:
        ctx.samples.append({"target": "-", "status": "skipped_never_scan", "reachable": None, "login": None,
                            "privilege": None, "note": "every address is on the never-scan list"})
    return f"{sum(1 for s in ctx.samples if s['status'] == 'ready')} of {len(picked)} sample addresses answered"


def is_ipv6_range(cidr: str) -> bool:
    try:
        return ipaddress.ip_network(cidr, strict=False).version == 6
    except ValueError:
        return False
