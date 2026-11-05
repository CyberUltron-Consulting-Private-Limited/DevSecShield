"""Network TLS/SSH collection and discovery sweeps over the ranges and ports the customer allowed.

Per open endpoint a prioritised list of handshakes runs, capped by ``handshakes_per_endpoint``:
  1. one full handshake (``openssl s_client``; Python ``ssl`` if openssl is missing) -> version, cipher, group,
     peer signature, certificate chain;
  2. raw ClientHello per protocol version (SSLv3 .. TLS 1.3) -> what the server accepts;
  3. TLS 1.3 post-quantum group probe (HelloRetryRequest) -> hybrid ML-KEM support;
  4. TLS_FALLBACK_SCSV probe -> downgrade protection;
  5. weak cipher classes (obsolete, static RSA, CBC, DHE with its group size).
``fragile`` ranges get only steps 1-2.  SNI names from the team settings that resolve into the address add one
full handshake each.  Every connection goes through the rate limiter, re-checks never-scan, stop-all and the
deadline, so a stop or a closed window takes effect within one handshake.

IKE (UDP 500, 4500 with the non-ESP marker): ``ikeprobe`` proposal probing, one packet at a time, at least
``IKE_SPACING`` apart, each through the same gate and limiter, within a per-endpoint packet budget.  OT: OPC UA
GetEndpoints (``otprobe``), Modbus/TCP (port only, nothing sent), Modbus/TCP Security (TLS).  An address with an open
OT port is scanned in fragile mode, one endpoint at a time (OT devices may not cope with parallel handshakes).
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import socket
import time
from typing import Any

from zs_scan_node import ikeprobe
from zs_scan_node import otprobe
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
TARPIT_TIMEOUTS = 3
ENDPOINT_MAX_S = 90
IKE_SPACING = 0.2  # seconds between two packets to the same IKE endpoint (at least)
IKE_TIMEOUT = 3.0  # wait for an answer per packet
IKE_FRAGILE_BUDGET = 6
NON_ESP_MARKER = b"\x00\x00\x00\x00"  # RFC 3948 section 2.2: IKE on port 4500

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


def _sni_for(scope: dict, ip: str, cache: dict) -> list[str]:
    names = scope.get("sni_hostnames") or []
    out = []
    for name in names[:200]:
        if name not in cache:  # only matched against the address being scanned, never connected to
            try:
                cache[name] = set(netutil.resolve(name))
            except OSError:
                cache[name] = set()
        if ip in cache[name]:
            out.append(name)
    return out


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
        self.sni_cache: dict[str, set] = {}
        self.timeouts: dict[str, int] = {}
        self.open_count = 0

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
        """'open' | 'closed' | a skip status."""
        gate = self._gate(ip)
        if gate:
            return gate
        try:
            sock = _tcp(ip, port, self.ctx.never_scan, 2.0)
            sock.close()
            return "open"
        except Blocked:
            return "skipped_never_scan"
        except T.ProbeError as exc:
            return "closed" if exc.code in ("refused", "timeout", "unreachable", "no_route") else "closed"

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
        budget = Budget(self.per_endpoint if mode != "fragile" else min(self.per_endpoint, 6))
        facts: dict[str, Any] = {"protocol_label": ep.label, "service": ep.protocol, "mode": mode}
        assets = 0
        # 1. full handshake
        try:
            if T.have_openssl() and ep.protocol != "rdp":
                fh = self.handshake(ep, budget, T.s_client, ep.ip, ep.port, ep.protocol, None,
                                    min(15.0, max(ctx.time_left(), 1)))
            else:
                fh = self.handshake(ep, budget, T.python_handshake, ep.ip, ep.port, ep.protocol, None, 10.0)
        except T.StarttlsUnavailable as exc:
            ctx.emit("tls_endpoint", ep.ip, ep.where, name=f"{ep.label or ep.protocol} {ep.where}", protocol=ep.protocol,
                     facts={**facts, "tls": False, "plaintext_only": True, "detail": str(exc)})
            return "ok", None, 1
        if fh == "budget":
            fh = T.FullHandshake(error="no budget")
        endpoint_deadline = time.monotonic() + ENDPOINT_MAX_S
        if not fh.ok and fh.error == "timeout":
            # one cheap raw probe decides whether this endpoint speaks TLS at all; a second silence ends it
            try:
                quick = self.handshake(ep, budget, T.probe, ep.ip, ep.port, ep.protocol,
                                       T.build_client_hello(T.TLS12, T.LEGACY_SUITES), 6.0)
            except T.ProbeError as exc:
                return exc.code, f"no TLS answer ({exc.detail})", 0
            except T.StarttlsUnavailable:
                quick = None
            if quick is not None and quick != "budget" and not quick.ok and not quick.alert:
                return "timeout", "no TLS answer", 0
        facts.update({"negotiated_version": fh.version, "negotiated_cipher": fh.cipher, "negotiated_group": fh.group,
                      "server_temp_key": fh.temp_key, "peer_signature_type": fh.peer_sig_type,
                      "peer_signing_digest": fh.peer_sig_digest, "secure_renegotiation": fh.secure_renegotiation,
                      "client_auth_requested": fh.client_auth_requested, "handshake_tool": fh.tool})
        chain = []
        for der in fh.certs_der[:50]:
            for cert in load_certs(der):
                chain.append(cert_facts(cert, "tls"))
        facts["chain_length"] = len(chain)
        if chain:
            facts["leaf"] = {k: chain[0].get(k) for k in ("subject", "issuer", "not_after", "key_alg", "key_size",
                                                         "curve", "sig_alg", "fingerprint_sha256", "self_signed", "san")}
        # 2. protocol versions
        versions: dict[str, bool | None] = {}
        tls13 = fh.ok and fh.version == "TLSv1.3"
        for v in (T.SSL3, T.TLS10, T.TLS11, T.TLS12):
            name = T.VERSION_NAMES[v]
            if time.monotonic() > endpoint_deadline:
                versions[name] = None
                facts["endpoint_time_cap"] = True
                continue
            if fh.ok and fh.version == name:
                versions[name] = True
                continue
            try:
                r = self.handshake(ep, budget, T.probe, ep.ip, ep.port, ep.protocol,
                                   T.build_client_hello(v, T.LEGACY_SUITES), 8.0)
            except T.StarttlsUnavailable as exc:
                ctx.emit("tls_endpoint", ep.ip, ep.where, name=f"{ep.label or ep.protocol} {ep.where}",
                         protocol=ep.protocol, facts={**facts, "tls": False, "plaintext_only": True, "detail": str(exc)})
                return "ok", None, 1
            except T.ProbeError as exc:
                versions[name] = None
                facts.setdefault("probe_errors", []).append(f"{name}: {exc.code}")
                continue
            if r == "budget":
                versions[name] = None
                continue
            versions[name] = bool(r.ok and r.version == v)
        if tls13:
            versions["TLSv1.3"] = True
        else:
            try:
                r = self.handshake(ep, budget, T.probe, ep.ip, ep.port, ep.protocol,
                                   T.build_client_hello(T.TLS12, T.TLS13_SUITES, tls13=True, key_share_groups=[29]), 8.0)
                versions["TLSv1.3"] = None if r == "budget" else bool(r.ok and (r.version == T.TLS13 or r.hrr))
            except (T.ProbeError, T.StarttlsUnavailable):
                versions["TLSv1.3"] = None
        facts["versions"] = versions
        supported = [k for k, v in versions.items() if v]
        if not fh.ok and not supported:
            status = "timeout" if fh.error == "timeout" else "error"
            if fh.error and fh.error != "timeout" and all(v is False for v in versions.values()):
                status = "ok"  # it answered every probe with an alert: a server that speaks no TLS we offer
                ctx.emit("tls_endpoint", ep.ip, ep.where, name=f"{ep.label or ep.protocol} {ep.where}",
                         protocol=ep.protocol, facts={**facts, "tls": None, "detail": "no TLS version accepted"})
                return status, None, 1
            return status, fh.error or "no TLS handshake", 0
        # 3. post-quantum groups
        if mode != "fragile" and versions.get("TLSv1.3"):
            try:
                r = self.handshake(ep, budget, T.probe, ep.ip, ep.port, ep.protocol,
                                   T.build_client_hello(T.TLS12, T.TLS13_SUITES, tls13=True, groups=T.PQ_GROUPS,
                                                        key_share_groups=[]), 8.0)
                if r != "budget":
                    facts["pq_hybrid"] = bool(r.ok and r.group in T.PQ_GROUPS)
                    facts["pq_group"] = T.GROUPS.get(r.group) if r.ok and r.group in T.PQ_GROUPS else None
            except (T.ProbeError, T.StarttlsUnavailable):
                facts["pq_hybrid"] = None
        elif mode != "fragile":
            facts["pq_hybrid"] = False
        # 4. downgrade protection
        order = [T.TLS13, T.TLS12, T.TLS11, T.TLS10]
        sup = [v for v in order if versions.get(T.VERSION_NAMES[v])]
        if mode != "fragile" and len(sup) >= 2:
            below = sup[1]
            try:
                r = self.handshake(ep, budget, T.probe, ep.ip, ep.port, ep.protocol,
                                   T.build_client_hello(below, T.LEGACY_SUITES, fallback_scsv=True), 8.0)
                if r != "budget":
                    facts["fallback_scsv"] = (r.alert == "inappropriate_fallback")
                    facts["downgrade_exposed"] = bool(r.ok)
            except (T.ProbeError, T.StarttlsUnavailable):
                pass
        # 5. weak classes on the best legacy version
        legacy = next((v for v in (T.TLS12, T.TLS11, T.TLS10, T.SSL3) if versions.get(T.VERSION_NAMES[v])), None)
        if mode != "fragile" and legacy is not None:
            accepted: dict[str, list[str]] = {}
            for label, suites in (("obsolete", T.OBSOLETE), ("static_rsa", T.STATIC_RSA), ("cbc", T.CBC_FS),
                                  ("dhe", T.DHE_SUITES)):
                try:
                    r = self.handshake(ep, budget, T.probe, ep.ip, ep.port, ep.protocol,
                                       T.build_client_hello(legacy, suites), 8.0, label == "dhe")
                except (T.ProbeError, T.StarttlsUnavailable):
                    continue
                if r == "budget":
                    facts["budget_exhausted"] = True
                    break
                if r.ok and r.cipher in suites:
                    accepted.setdefault(label, []).append(r.cipher_name)
                    if label == "dhe" and r.dh_bits:
                        facts["dh_bits"] = r.dh_bits
            # spend what is left enumerating more obsolete suites
            remaining = [c for c in T.OBSOLETE if T.CIPHERS[c] not in accepted.get("obsolete", [])]
            while accepted.get("obsolete") and remaining and budget.used < budget.limit:
                try:
                    r = self.handshake(ep, budget, T.probe, ep.ip, ep.port, ep.protocol,
                                       T.build_client_hello(legacy, remaining), 8.0)
                except (T.ProbeError, T.StarttlsUnavailable):
                    break
                if r == "budget" or not (r.ok and r.cipher in remaining):
                    break
                accepted["obsolete"].append(r.cipher_name)
                remaining.remove(r.cipher)
            facts["weak_ciphers_accepted"] = accepted
            facts["weak_cipher_probe_version"] = T.VERSION_NAMES[legacy]
        facts["handshakes_used"] = budget.used
        facts["handshake_budget"] = budget.limit
        facts["tls"] = True
        top = next((v for v in ("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3") if versions.get(v)), fh.version)
        ctx.emit("tls_endpoint", ep.ip, ep.where, name=f"{ep.label or ep.protocol} {ep.where}",
                 algorithm=fh.cipher, protocol=top, facts=facts)
        assets += 1
        for i, c in enumerate(chain):
            ctx.emit("certificate", ep.ip, f"{ep.where}#chain[{i}]", name=c.get("subject", ""),
                     algorithm=c.get("key_alg"), key_size=c.get("key_size"), facts={**c, "chain_index": i})
            assets += 1
        # SNI variants
        for name in _sni_for(self.scope, ep.ip, self.sni_cache):
            if ep.protocol == "rdp" or not T.have_openssl():
                break
            try:
                sfh = self.handshake(ep, budget, T.s_client, ep.ip, ep.port, ep.protocol, name, 15.0)
            except _Skip:
                break
            if sfh == "budget":
                ctx.coverage(ep.ip, f"sni:{name}", "truncated", "handshake budget used up before this SNI name")
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
        return "ok", None, assets

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
    parallel = max(1, min(int((scope.get("rate_limits") or {}).get("connections_per_second") or 20) // 2, 16))
    open_endpoints = 0
    truncated = False

    per_server = max(1, int((scope.get("rate_limits") or {}).get("parallel_per_server") or 2))

    def do_address(ip: str, mode: str):
        try:
            return _do_address(ip, mode)
        except LeaseLost:
            raise
        except Exception as exc:  # one address must never end the whole range
            ctx.log("address error", target=ip, error=exc.__class__.__name__, level="warn")
            ctx.outcome(ip, "error", f"node error ({exc.__class__.__name__})")
            return 0

    def _do_address(ip: str, mode: str):
        started = time.monotonic()
        stop = ctx.should_stop(network=True)
        if stop:
            ctx.outcome(ip, stop, started=started)
            return 0
        if ctx.never_scan.blocks_ip(ip):
            ctx.outcome(ip, "skipped_never_scan", started=started)
            return 0
        open_eps: list[Endpoint] = []
        for p in tcp_ports:
            state = scan.tcp_open(ip, p["port"])
            if state.startswith("skipped_"):
                ctx.outcome(ip, state, started=started)
                return 0
            if state == "open":
                open_eps.append(Endpoint(ip, p["port"], p["protocol"], p["label"]))
        if discovery_only:
            for ep in open_eps:
                ctx.emit("open_port", ip, ep.where, name=f"{ep.label or ep.protocol} {ep.where}", protocol=ep.protocol,
                         facts={"port": ep.port, "protocol": ep.protocol, "label": ep.label})
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

        with cf.ThreadPoolExecutor(max_workers=workers) as eps_pool:
            for ep, status, err, n, t0 in eps_pool.map(one, open_eps):
                assets += n
                if status.startswith("skipped_"):
                    skip_status = skip_status or status
                    continue
                if status != "ok":
                    failures.append(f"{ep.port}:{status}")
                    ctx.outcome(ep.where, status, err, started=t0, assets=n, counted=False)
        # IKE over UDP: no connect to tell an open port, so every listed IKE port gets a probe; the first silent one
        # (no answer to IKEv2 or IKEv1) ends IKE on this address
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
            if status != "ok":
                failures.append(f"{ep.port}/udp:{status}")
                ctx.outcome(f"{ep.where}/udp", status, err, started=t0, assets=n, counted=False)
        if skip_status and assets == 0:
            ctx.outcome(ip, skip_status, started=started)
            return len(open_eps)
        ctx.outcome(ip, "ok", "; ".join(failures)[:250] if failures else None, started=started, assets=assets)
        return len(open_eps)

    with cf.ThreadPoolExecutor(max_workers=parallel) as pool:
        pending: set[cf.Future] = set()
        for ip, mode in _addresses(ctx, ranges):
            if open_endpoints >= MAX_OPEN_ENDPOINTS:
                truncated = True
                ctx.outcome(ip, "skipped_deadline", "open-endpoint cap reached")
                continue
            if ctx.should_stop(network=True):
                ctx.outcome(ip, ctx.should_stop(network=True) or "skipped_deadline")
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
