"""KMIP key managers, read-only, over TLS with a client certificate (own TTLV client: zs_scan_node/kmip_ttlv.py).

PyKMIP is unmaintained and does not run on Python 3.12, so the node speaks the four operations it needs itself:
Discover Versions (pick the highest common protocol version, KMIP 1.0-2.0), Query (vendor, server information,
supported operations and object types), Locate (every managed object, paged) and Get Attributes (algorithm, length,
state, dates, usage mask, object type, sensitive/extractable).  Get and Export, which return key material, are never
sent.  The connection goes through the network gate (``netutil.connect``) to the checked address; the server is
verified against the uploaded CA certificate when there is one (TLS client authentication never reveals the client
key, even to an impostor).  The client certificate and key exist on disk only while the TLS context loads them.
"""
from __future__ import annotations

import socket
import ssl
import struct
import time
from typing import Any

from zs_scan_node import kmip_ttlv as K
from zs_scan_node import netutil
from zs_scan_node.certparse import cert_facts, load_certs
from zs_scan_node.jobctx import JobContext, register_asset_types
from zs_scan_node.netutil import Blocked, Target, resolve_checked
from zs_scan_node.tlsclient import client_context

register_asset_types("key_store", "managed_key")

VERSIONS = ((2, 0), (1, 4), (1, 3), (1, 2), (1, 1), (1, 0))
PAGE = 500
MAX_OBJECTS = 10_000
KEY_CLASS = {"Symmetric Key": "secret", "Private Key": "private", "Public Key": "public", "Secret Data": "secret_data",
             "Split Key": "split", "Certificate": "certificate", "PGP Key": "public", "Opaque Object": "opaque"}


class KmipFail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


def _context(config: dict, secrets: dict) -> ssl.SSLContext:
    # server verified against the uploaded CA when there is one; without it, TLS client authentication still never
    # reveals the client key, so the node may connect (the facts then say server_verified: false)
    ctx = client_context(config.get("ca_pem"), secrets.get("client_cert"), secrets.get("client_key"), verify=False,
                         what="KMIP client")
    ctx.check_hostname = False  # the address was checked by the network gate; the chain by the CA
    return ctx


class Client:
    def __init__(self, ctx: JobContext, target: Target, port: int, sslctx: ssl.SSLContext) -> None:
        self.ctx, self.target, self.port, self.sslctx = ctx, target, port, sslctx
        self.sock: ssl.SSLSocket | None = None
        self.version: tuple[int, int] = (1, 2)

    def open(self) -> dict[str, Any]:
        raw = netutil.connect(self.target.ip, self.port, self.ctx.never_scan, 10)
        sni = None if _is_ip(self.target.label) else self.target.label
        try:
            self.sock = self.sslctx.wrap_socket(raw, server_hostname=sni)
        except ssl.SSLCertVerificationError:
            raw.close()
            raise KmipFail("identity_unverified", "the KMIP server's certificate does not chain to the uploaded CA "
                           "certificate") from None
        except (ssl.SSLError, OSError) as exc:
            raw.close()
            text = str(exc).lower()
            if "certificate" in text or "handshake" in text or "alert" in text:
                raise KmipFail("auth_failed", "the KMIP server refused the TLS handshake (is the client certificate "
                               f"one it trusts?): {exc.__class__.__name__}") from None
            raise KmipFail("tls_unavailable", f"TLS to the KMIP port failed ({exc.__class__.__name__})") from None
        self.sock.settimeout(30)
        cipher = self.sock.cipher()
        return {"negotiated_version": self.sock.version(), "negotiated_cipher": cipher[0] if cipher else None,
                "cert_der": self.sock.getpeercert(binary_form=True)}

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass

    def _recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise KmipFail("error", "the KMIP server closed the connection")
            buf += chunk
        return buf

    def call(self, operation: str, payload: list[K.Item], version: tuple[int, int] | None = None) -> K.Response:
        if self.ctx.should_stop():
            raise KmipFail(self.ctx.should_stop() or "skipped_deadline", "stopped")
        self.sock.sendall(K.request(version or self.version, operation, payload))
        try:
            head = self._recv(8)
            length = struct.unpack("!I", head[4:8])[0]
            if length > K.MAX_MESSAGE:
                raise KmipFail("error", "KMIP response larger than 4 MB")
            body = self._recv(length)
            return K.parse_response(head + body)
        except socket.timeout:
            raise KmipFail("timeout", f"the KMIP server did not answer {operation}") from None
        except K.TTLVError as exc:
            raise KmipFail("error", f"not a KMIP answer to {operation}: {exc}") from None
        except ssl.SSLError as exc:
            # TLS 1.3 servers report a refused client certificate after the handshake, on the first read
            raise KmipFail("auth_failed", f"the KMIP server ended TLS ({exc.__class__.__name__}): is the client "
                           "certificate one it trusts?") from None


def _is_ip(text: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def negotiate(client: Client) -> list[str]:
    resp = client.call("Discover Versions", K.discover_versions(), version=(1, 1))
    offered: list[tuple[int, int]] = []
    if resp.ok and resp.payload is not None:
        for pv in resp.payload.all("Protocol Version"):
            offered.append((pv.get("Protocol Version Major", 0), pv.get("Protocol Version Minor", 0)))
    usable = [v for v in VERSIONS if v in offered] or ([resp.version] if resp.version else [(1, 0)])
    client.version = usable[0]
    return [f"{a}.{b}" for a, b in offered]


def read(ctx: JobContext, client: Client, where: str) -> tuple[int, dict[str, Any]]:
    offered = negotiate(client)
    info: dict[str, Any] = {"store": "kmip", "protocol_versions": offered,
                            "protocol_version": f"{client.version[0]}.{client.version[1]}"}
    q = client.call("Query", K.query())
    if q.ok and q.payload is not None:
        info["vendor"] = (q.payload.get("Vendor Identification") or "")[:200] or None
        server = q.payload.first("Server Information")
        if server is not None:
            info["server_information"] = {c.name: (c.value if isinstance(c.value, (str, int, bool)) else None)
                                          for c in server.children[:20]}
        info["operations"] = sorted({K.OPERATION_NAME.get(op.value, f"0x{op.value:x}")
                                     for op in q.payload.all("Operation")})
        info["object_types"] = sorted({K.OBJECT_TYPE.get(o.value, f"0x{o.value:x}")
                                       for o in q.payload.all("Object Type")})
    else:
        ctx.coverage(client.target.label, "KMIP Query", "error", q.error_text())
    uids: list[str] = []
    offset = 0
    while len(uids) < MAX_OBJECTS:
        resp = client.call("Locate", K.locate(client.version, PAGE, offset))
        if not resp.ok:
            status = "denied" if resp.reason in (3, 12, 57) else "error"
            ctx.coverage(client.target.label, "KMIP Locate", status, resp.error_text())
            break
        page = [str(u.value) for u in resp.payload.all("Unique Identifier")] if resp.payload is not None else []
        uids += [u for u in page if u not in uids]
        if len(page) < PAGE or client.version < (1, 3):
            break
        offset += PAGE
    if len(uids) >= MAX_OBJECTS:
        ctx.coverage(client.target.label, "KMIP Locate", "error", f"more than {MAX_OBJECTS} objects; the rest were not read")
    n = 0
    counts: dict[str, int] = {}
    for uid in uids[:MAX_OBJECTS]:
        resp = client.call("Get Attributes", K.get_attributes(uid))
        if not resp.ok:
            ctx.coverage(client.target.label, f"KMIP Get Attributes {uid[:40]}", "denied" if resp.reason in (12, 57)
                         else "error", resp.error_text(), once=True)
            continue
        facts = K.attributes_to_facts(resp.payload)
        object_type = facts.get("object_type") or "unknown"
        counts[object_type] = counts.get(object_type, 0) + 1
        if object_type in ("Opaque Object", "Template", "Certificate Request"):
            continue
        size = facts.get("length") or K.CURVE_BITS.get(str(facts.get("curve") or ""))
        name = (facts.get("names") or [uid])[0]
        ctx.emit("managed_key", client.target.label, f"{where}/{uid}", name=str(name), algorithm=facts.get("algorithm"),
                 key_size=size if isinstance(size, int) else None,
                 facts={**facts, "store": "kmip", "uid": uid[:128], "key_class": KEY_CLASS.get(object_type, "other"),
                        "key_state": facts.get("state")})
        n += 1
    info["objects"] = counts
    return n, info


def _target(ctx: JobContext, config: dict) -> Target:
    host = str(config.get("host") or "").strip()
    label = host.strip("[]").lower().rstrip(".")
    try:
        return Target(label, resolve_checked(host, ctx.never_scan)[0])  # the network gate: resolve once, check
    except Blocked as exc:
        raise KmipFail("skipped_never_scan", str(exc)) from None
    except OSError as exc:
        raise KmipFail("unreachable", f"could not resolve {label}: {exc.__class__.__name__}") from None


def run(ctx: JobContext, config: dict, secrets: dict, test_only: bool = False) -> tuple[Target | None, str, str | None, int]:
    port = int(config.get("port") or 5696)
    target = None
    try:
        target = _target(ctx, config)
    except KmipFail as fail:
        return target, fail.status, fail.error, 0
    sslctx = _context(config, secrets)
    where = f"kmip://{target.label}:{port}"
    client = Client(ctx, target, port, sslctx)
    n = 0
    try:
        tls = client.open()
        der = tls.pop("cert_der", None)
        for cert in (load_certs(der) if der else [])[:1]:
            f = cert_facts(cert, "tls")
            ctx.emit("certificate", target.label, f"{target.label}:{port}#chain[0]", name=f.get("subject", ""),
                     algorithm=f.get("key_alg"), key_size=f.get("key_size"), facts={**f, "chain_index": 0, "role": "kmip"})
            n += 1
        ctx.emit("tls_endpoint", target.label, f"{target.label}:{port}", name=f"kmip {target.ip}:{port}",
                 algorithm=tls.get("negotiated_cipher"), protocol=tls.get("negotiated_version") or "kmip",
                 facts={**tls, "service": "kmip", "tls": True, "client_certificate": True,
                        "server_verified": bool(config.get("ca_pem"))})
        n += 1
        if test_only:
            offered = negotiate(client)
            resp = client.call("Locate", K.locate(client.version, 1, 0))
            if not resp.ok:
                return target, "auth_failed" if resp.reason in (3, 12, 57) else "error", resp.error_text(), n
            return target, "ok", f"KMIP {'/'.join(offered) or client.version}", n
        objects, info = read(ctx, client, where)
        n += objects
        ctx.emit("key_store", target.label, where, name=info.get("vendor") or f"KMIP server {target.label}",
                 facts={**info, **{k: v for k, v in tls.items() if k != "cert_der"}})
        n += 1
        return target, "ok", None, n
    except KmipFail as fail:
        return target, fail.status, fail.error, n
    except Blocked:
        return target, "skipped_never_scan", None, n
    except socket.timeout:
        return target, "timeout", "the KMIP server did not answer", n
    except ConnectionRefusedError:
        return target, "refused", "connection refused", n
    except OSError as exc:
        return target, "unreachable", exc.__class__.__name__, n
    finally:
        client.close()


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    target, status, error, n = run(ctx, config, secrets)
    label = target.label if target else str(config.get("host"))
    ctx.outcome(label, status, error, started=started, assets=n)
    return f"kmip {label}: {status}"


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    target, status, note, n = run(ctx, config, secrets, test_only=True)
    label = target.label if target else str(config.get("host"))
    ctx.samples.append({"target": label, "status": "ready" if status == "ok" else status,
                        "reachable": status not in ("unreachable", "refused", "timeout", "no_route"),
                        "login": status == "ok", "privilege": None, "note": note or ""})
    return note or status
