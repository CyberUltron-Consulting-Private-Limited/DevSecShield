"""OT (OPC UA, Modbus) and service-mesh collection (WP7): recorded asyncua answers, the discovery-only message
allow-list, a replay server end to end, Modbus sends nothing, OT addresses forced into fragile mode, Istio and
Linkerd facts."""
from __future__ import annotations

import json
import socket
import struct
import threading
import time
from pathlib import Path

from zs_scan_node import otprobe as O
from zs_scan_node import tlsprobe as T
from zs_scan_node.collectors import kubernetes as K
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

REC = json.loads((Path(__file__).parent / "fixtures/opcua/asyncua_legacy.json").read_text())


def _ctx(**kw):
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind=kw.pop("kind", "network_range"),
                      scrubber=Scrubber(), never_scan=NeverScan(kw.pop("never", [])),
                      deadline=time.monotonic() + 60)


# ----------------------------------------------------------------------------- OPC UA
def test_recorded_get_endpoints_answer_parses():
    msg = next(c for c in REC["chunks"] if c["type"] == "MSG")
    eps = O.parse_endpoints(bytes.fromhex(msg["body"])[16:])
    s = O.summarize(eps)
    assert s["policies"] == ["Basic128Rsa15", "Basic256Sha256", "None"] and s["modes"] == ["None", "SignAndEncrypt"]
    none_ep = next(e for e in s["endpoints"] if e["security_policy"] == "None")
    assert {t["type"] for t in none_ep["user_tokens"]} == {"Anonymous", "UserName"}
    assert all(e["certificate_der"] for e in eps)  # the server certificate travels with every endpoint


def test_client_messages_are_discovery_only():
    """HEL, OPN (SecurityPolicy None, RequestType Issue), MSG GetEndpoints, CLO: no session, read, write or call."""
    msgs = [O.build_hello("opc.tcp://h:4840"), O.build_open(), O.build_get_endpoints(7, 1, "opc.tcp://h:4840"),
            O.build_close(7, 1)]
    assert [m[:4] for m in msgs] == [b"HELF", b"OPNF", b"MSGF", b"CLOF"]
    assert all(struct.unpack("<I", m[4:8])[0] == len(m) for m in msgs)
    assert O.POLICY_NONE.encode() in msgs[1]
    type_ids = []
    for m, offset in ((msgs[1], None), (msgs[2], 24), (msgs[3], 24)):
        if offset is None:  # OPN: skip channel id, policy uri, two null byte strings and the sequence header
            r = O.Reader(m[8:])
            r.u32(), r.string(), r.bytestring(), r.bytestring(), r.u32(), r.u32()
        else:
            r = O.Reader(m[offset:])
        type_ids.append(r.nodeid())
    assert type_ids == [O.ENC_OPN_REQ, O.ENC_GETEP_REQ, O.ENC_CLO_REQ]
    # OPN parameters: client protocol version 0, RequestType Issue (0), MessageSecurityMode None (1)
    r = O.Reader(msgs[1][8:])
    r.u32(), r.string(), r.bytestring(), r.bytestring(), r.u32(), r.u32(), r.nodeid()
    r.nodeid(), r.i64(), r.u32(), r.u32(), r.string(), r.u32(), r.extension_object()
    assert (r.u32(), r.i32(), r.i32()) == (0, 0, 1)


class ReplayServer:
    """Answers with the recorded asyncua chunks and records the message types it receives."""

    def __init__(self, chunks):
        self.chunks = chunks
        self.received: list[bytes] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(2)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        conn, _ = self.sock.accept()
        replies = {b"HEL": "ACK", b"OPN": "OPN", b"MSG": "MSG"}
        buf = b""
        while True:
            try:
                data = conn.recv(65536)
            except OSError:
                return
            if not data:
                return
            buf += data
            while len(buf) >= 8 and len(buf) >= struct.unpack("<I", buf[4:8])[0]:
                size = struct.unpack("<I", buf[4:8])[0]
                mtype, buf = buf[:3], buf[size:]
                self.received.append(mtype)
                want = replies.get(mtype)
                for c in self.chunks:
                    if c["type"] == want:
                        body = bytes.fromhex(c["body"])
                        conn.sendall(c["type"].encode() + c["chunk"].encode() + struct.pack("<I", 8 + len(body)) + body)


def test_get_endpoints_end_to_end_against_replayed_answers():
    srv = ReplayServer(REC["chunks"])
    sock = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    eps = O.get_endpoints(sock, f"opc.tcp://127.0.0.1:{srv.port}", time.monotonic() + 10)
    sock.close()
    time.sleep(0.2)
    assert len(eps) == 3 and srv.received == [b"HEL", b"OPN", b"MSG", b"CLO"]


def test_err_and_garbage_answers_are_reported_not_raised_further():
    for payload in (b"ERRF" + struct.pack("<I", 16) + struct.pack("<I", 0x80550000) + struct.pack("<i", -1),
                    b"HTTP/1.1 400 Bad Request\r\n\r\n"):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def answer(s=srv, p=payload):
            c, _ = s.accept()
            c.recv(4096)
            c.sendall(p)
            time.sleep(0.2)
            c.close()

        threading.Thread(target=answer, daemon=True).start()
        sock = socket.create_connection(srv.getsockname(), timeout=5)
        try:
            O.get_endpoints(sock, "opc.tcp://x", time.monotonic() + 5)
            raise AssertionError("expected UaError")
        except O.UaError as exc:
            assert exc.code in ("refused", "error")
        sock.close()
        srv.close()


def test_opcua_collector_emits_endpoint_and_certificate_rows():
    srv = ReplayServer(REC["chunks"])
    ctx = _ctx()
    scan = N.NetworkScan(ctx, {})
    status, _err, n = scan.scan_endpoint(N.Endpoint("127.0.0.1", srv.port, "opcua", "OPC UA"), "fragile")
    ctx.flush()
    assert status == "ok" and n == 2
    ot = next(a for a in ctx.collected if a["type"] == "ot_endpoint")
    assert ot["facts"]["policies"] == ["Basic128Rsa15", "Basic256Sha256", "None"]
    cert = next(a for a in ctx.collected if a["type"] == "certificate")
    assert cert["facts"]["role"] == "opcua-server" and cert["key_size"] == 1024


# ----------------------------------------------------------------------------- Modbus and OT fragile mode
def test_modbus_endpoint_sends_nothing(monkeypatch):
    def no_connect(*a, **k):
        raise AssertionError("the Modbus check must not open a connection of its own")

    monkeypatch.setattr(N.netutil, "connect", no_connect)
    ctx = _ctx()
    status, _e, n = N.NetworkScan(ctx, {}).scan_endpoint(N.Endpoint("192.0.2.5", 502, "modbus", ""), "full")
    ctx.flush()
    assert status == "ok" and n == 1 and ctx.collected[0]["facts"]["tls"] is False


def test_an_open_ot_port_forces_fragile_mode_and_one_connection_at_a_time(monkeypatch):
    seen, active, peak = [], [0], [0]
    lock = threading.Lock()

    def fake_endpoint(self, ep, mode):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        seen.append((ep.ip, ep.protocol, mode))
        return "ok", None, 0

    monkeypatch.setattr(N.NetworkScan, "tcp_open", lambda self, ip, port: "open")
    monkeypatch.setattr(N.NetworkScan, "scan_endpoint", fake_endpoint)
    ports = [{"port": 443, "protocol": "tls"}, {"port": 8443, "protocol": "tls"}, {"port": 22, "protocol": "ssh"}]
    ctx = _ctx()
    N.run_network(ctx, {"ranges": ["192.0.2.1/32"], "ports": ports + [{"port": 502, "protocol": "modbus"}],
                        "rate_limits": {"parallel_per_server": 4}})
    assert {m for _ip, _p, m in seen} == {"fragile"} and peak[0] == 1
    seen.clear()
    peak[0] = 0
    N.run_network(_ctx(), {"ranges": ["192.0.2.2/32"], "ports": ports, "rate_limits": {"parallel_per_server": 4}})
    assert {m for _ip, _p, m in seen} == {"full"} and peak[0] > 1


def test_s_client_reports_client_certificate_request_in_tls13():
    """Modbus/TCP Security (802) requires a client certificate: over TLS 1.3 s_client prints neither CA names nor
    certificate types, only the CertificateRequest's signature algorithms (lines recorded from OpenSSL 3)."""
    tls13 = ("No client certificate CA names sent\nRequested Signature Algorithms: ECDSA+SHA256:RSA-PSS+SHA256\n"
             "---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n")
    plain = "No client certificate CA names sent\n---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
    assert T.parse_s_client(tls13).client_auth_requested is True
    assert T.parse_s_client(plain).client_auth_requested is False


# ----------------------------------------------------------------------------- service mesh
def test_istio_root_namespace_from_the_mesh_config():
    cm = {"metadata": {"namespace": "istio-system", "name": "istio"}, "data": {"mesh": "rootNamespace: mesh-root\n"}}
    assert K.istio_root_namespace(cm) == "mesh-root"
    cm["data"]["mesh"] = "defaultConfig:\n  discoveryAddress: istiod:15012\n"
    assert K.istio_root_namespace(cm) == "istio-system"
    assert K.istio_root_namespace({"metadata": {"namespace": "a", "name": "istio-ca-root-cert"},
                                   "data": {"root-cert.pem": "x"}}) is None
    assert K.istio_root_namespace({"metadata": {"namespace": "a", "name": "istio"}, "data": {"mesh": "[: bad"}}) is None


def test_destination_rule_tls_modes():
    dr = {"metadata": {"namespace": "pay", "name": "legacy"},
          "spec": {"host": "legacy.pay.svc.cluster.local",
                   "trafficPolicy": {"tls": {"mode": "ISTIO_MUTUAL"},
                                     "portLevelSettings": [{"port": {"number": 8080}, "tls": {"mode": "DISABLE"}}]},
                   "subsets": [{"name": "v1", "trafficPolicy": {"tls": {"mode": "DISABLE"}}},
                               {"name": "v2", "trafficPolicy": {"tls": {"mode": "SIMPLE", "insecureSkipVerify": True,
                                                                        "caCertificates": "/etc/x.pem"}}}]}}
    f = K.destination_rule_facts(dr)
    assert f["tls_mode"] == "ISTIO_MUTUAL" and f["port_tls_modes"] == {"8080": "DISABLE"}
    assert f["subset_tls_modes"] == {"v1": "DISABLE", "v2": "SIMPLE"} and f["insecure_skip_verify"] is True
    assert "/etc/x.pem" not in json.dumps(f)


def _linkerd_items():
    server = lambda ns, name, port, labels=None, access=None: {  # noqa: E731
        "metadata": {"namespace": ns, "name": name, "labels": labels or {}},
        "spec": {"port": port, "podSelector": {"matchLabels": {"app": name}}, **({"accessPolicy": access} if access else {})}}
    return {
        "servers": [server("emoji", "web-http", "http", {"tier": "front"}), server("emoji", "api", 8080),
                    server("emoji", "admin", 9990, access="all-unauthenticated"), server("vote", "grpc", 8080),
                    server("vote", "metrics", 9100)],
        "serverauthorizations": [
            {"metadata": {"namespace": "emoji", "name": "web-public"},
             "spec": {"server": {"selector": {"matchLabels": {"tier": "front"}}},
                      "client": {"unauthenticated": True, "networks": [{"cidr": "0.0.0.0/0"}]}}},
            {"metadata": {"namespace": "emoji", "name": "api-mesh"},
             "spec": {"server": {"name": "api"}, "client": {"meshTLS": {"serviceAccounts": [{"name": "web"}]}}}}],
        "authorizationpolicies": [
            {"metadata": {"namespace": "vote", "name": "grpc-mtls"},
             "spec": {"targetRef": {"group": "policy.linkerd.io", "kind": "Server", "name": "grpc"},
                      "requiredAuthenticationRefs": [{"kind": "MeshTLSAuthentication", "name": "voters"}]}},
            {"metadata": {"namespace": "vote", "name": "metrics-net"},
             "spec": {"targetRef": {"group": "policy.linkerd.io", "kind": "Server", "name": "metrics"},
                      "requiredAuthenticationRefs": [{"kind": "NetworkAuthentication", "name": "cluster"}]}},
            {"metadata": {"namespace": "vote", "name": "dangling"},
             "spec": {"targetRef": {"kind": "Server", "name": "grpc"},
                      "requiredAuthenticationRefs": [{"kind": "NetworkAuthentication", "name": "missing"}]}}],
        "meshtlsauthentications": [{"metadata": {"namespace": "vote", "name": "voters"}, "spec": {"identities": ["*"]}}],
        "networkauthentications": [{"metadata": {"namespace": "vote", "name": "cluster"},
                                    "spec": {"networks": [{"cidr": "10.0.0.0/8"}]}}],
    }


def test_linkerd_servers_that_accept_clients_without_identity():
    rows = {r["name"]: r for r in K.linkerd_server_facts(_linkerd_items())}
    assert rows["web-http"]["unauthenticated"] and "web-public" in rows["web-http"]["unauthenticated_by"][0]
    assert rows["admin"]["unauthenticated_by"] == ["accessPolicy all-unauthenticated"]
    assert rows["metrics"]["unauthenticated_by"] == ["AuthorizationPolicy metrics-net requires no mesh identity (network only)"]
    assert not rows["api"]["unauthenticated"] and not rows["grpc"]["unauthenticated"]  # mesh identity / dangling ref
    assert rows["api"]["access_policy"] == "deny"


class MeshApi:
    """Kubernetes API double serving discovery for policy.linkerd.io and the mesh objects."""
    api_url, host, port = "https://k8s.test:6443", "k8s.test", 6443

    def __init__(self, *a):
        self.paths: list[str] = []
        self.items = _linkerd_items()

    def check_scope(self):
        return "10.0.0.1"

    def get(self, path, params=None):
        self.paths.append(path)
        if path == "/apis/policy.linkerd.io":
            return 200, {"versions": [{"version": "v1beta3"}, {"version": "v1beta1"}, {"version": "v1alpha1"}],
                         "preferredVersion": {"version": "v1beta3"}}
        if path.startswith("/apis/policy.linkerd.io/"):
            served = {"v1beta3": ["servers"], "v1beta1": ["servers", "serverauthorizations"],
                      "v1alpha1": ["authorizationpolicies", "meshtlsauthentications", "networkauthentications",
                                   "serverauthorizations"]}[path.rsplit("/", 1)[1]]
            return 200, {"resources": [{"name": r} for r in served]}
        return 200, {"gitVersion": "v1.31.0"}

    def list_all(self, path, params=None):
        self.paths.append(path)
        if path.endswith("/configmaps"):
            yield ("item", {"metadata": {"namespace": "istio-system", "name": "istio"}, "data": {"mesh": "{}"}})
        elif path.endswith("/destinationrules"):
            yield ("item", {"metadata": {"namespace": "pay", "name": "plain"},
                            "spec": {"host": "plain.pay.svc", "trafficPolicy": {"tls": {"mode": "DISABLE"}}}})
        elif path.startswith("/apis/policy.linkerd.io/"):
            for item in self.items[path.rsplit("/", 1)[1]]:
                yield ("item", item)

    def close(self):
        pass


def test_kubernetes_collect_reads_mesh_objects_at_discovered_versions(monkeypatch):
    api = MeshApi()
    monkeypatch.setattr(K, "Api", lambda *a: api)
    monkeypatch.setattr(K.T, "have_openssl", lambda: False)
    ctx = _ctx(kind="kubernetes")
    K.collect(ctx, {"api_url": MeshApi.api_url}, {}, {})
    ctx.flush()
    types = [a["type"] for a in ctx.collected]
    assert types.count("k8s_mesh_server") == 5 and types.count("k8s_mesh_destination") == 1
    implicit = [a for a in ctx.collected if a["type"] == "k8s_mesh_policy" and a["facts"].get("implicit")]
    assert len(implicit) == 1 and implicit[0]["facts"]["scope"] == "mesh"  # Istio installed, no mesh-wide policy
    assert "/apis/policy.linkerd.io/v1beta3/servers" in api.paths
    assert "/apis/policy.linkerd.io/v1beta1/serverauthorizations" in api.paths
    assert "/apis/policy.linkerd.io/v1alpha1/authorizationpolicies" in api.paths
    assert all(not p.startswith("/api/v1/secrets") for p in api.paths)  # Tier 1


def test_linkerd_not_installed_is_a_coverage_row(monkeypatch):
    class NoLinkerd(MeshApi):
        def get(self, path, params=None):
            return (404, None) if path.startswith("/apis/policy.linkerd.io") else (200, {"gitVersion": "v1.31.0"})

        def list_all(self, path, params=None):
            return iter(())

    monkeypatch.setattr(K, "Api", NoLinkerd)
    monkeypatch.setattr(K.T, "have_openssl", lambda: False)
    ctx = _ctx(kind="kubernetes")
    K.collect(ctx, {"api_url": MeshApi.api_url}, {}, {})
    ctx.flush()
    cov = [a["facts"] for a in ctx.collected if a["type"] == "coverage"]
    assert {"check": "linkerd policy", "status": "not_installed", "detail": ""} in cov
    assert not any(a["type"] == "k8s_mesh_policy" for a in ctx.collected)  # no mesh config: no implicit default
