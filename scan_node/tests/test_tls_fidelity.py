"""CB-12 TLS prober fidelity: SNI-only servers (KF-4), non-TLS listeners and alert-only TLS (KF-5, CB-04 EC-4), full
suite and group enumeration within the handshake budget (#100), IANA names and codes, no sentinels, PostgreSQL TLS
versions.  A fake TLS server (``FakeTls``) parses each ClientHello and answers the way the TLS RFCs prescribe for its
configuration, so every expected value below is the server's configuration, never the prober's output."""
from __future__ import annotations

import os
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from zs_scan_node import netutil
from zs_scan_node import tls_registry as R
from zs_scan_node import tlsenum as E
from zs_scan_node import tlsprobe as T
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

ALERT = {"handshake_failure": 40, "protocol_version": 70, "unrecognized_name": 112, "inappropriate_fallback": 86,
         "decode_error": 50, "illegal_parameter": 47}


def _alert(name: str) -> bytes:
    return b"\x15\x03\x03\x00\x02\x02" + bytes([ALERT[name]])


def _parse_hello(data: bytes) -> dict:
    hs = data[5:]
    body = hs[4:4 + int.from_bytes(hs[1:4], "big")]
    out = {"legacy_version": struct.unpack("!H", body[0:2])[0], "sni": None, "groups": None, "versions": None,
           "key_share": []}
    pos = 34
    pos += 1 + body[pos]
    n = struct.unpack("!H", body[pos:pos + 2])[0]
    out["suites"] = [struct.unpack("!H", body[pos + 2 + i:pos + 4 + i])[0] for i in range(0, n, 2)]
    pos += 2 + n
    pos += 1 + body[pos]
    if pos + 2 > len(body):
        return out
    end = pos + 2 + struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    while pos + 4 <= end:
        etype, elen = struct.unpack("!HH", body[pos:pos + 4])
        ext = body[pos + 4:pos + 4 + elen]
        pos += 4 + elen
        if etype == 0:
            out["sni"] = ext[5:5 + struct.unpack("!H", ext[3:5])[0]].decode()
        elif etype == 10:
            out["groups"] = [struct.unpack("!H", ext[2 + i:4 + i])[0] for i in range(0, len(ext) - 2, 2)]
        elif etype == 43:
            out["versions"] = [struct.unpack("!H", ext[1 + i:3 + i])[0] for i in range(0, ext[0], 2)]
        elif etype == 51:
            i = 2
            while i + 4 <= len(ext):
                grp, klen = struct.unpack("!HH", ext[i:i + 4])
                out["key_share"].append(grp)
                i += 4 + klen
    return out


def _record(msg_type: int, body: bytes) -> bytes:
    hs = bytes([msg_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def _server_hello(version: int, cipher: int, exts: bytes = b"", hrr: bool = False) -> bytes:
    body = struct.pack("!H", version) + (T.HRR_RANDOM if hrr else os.urandom(32)) + b"\x00" + struct.pack("!H", cipher) + b"\x00"
    if exts:
        body += struct.pack("!H", len(exts)) + exts
    return _record(2, body)


class FakeTls:
    """A TLS server that answers ClientHellos by the RFCs for its configuration (server preference order):
    ``suites`` {version: [codes]} for TLS <= 1.2, ``suites13`` and ``groups13`` for TLS 1.3, ``curves`` for ECDHE,
    ``sni`` (when set, a hello without that name gets alert unrecognized_name), ``mode`` "tls" | "close" | "http" |
    "alert" (every hello gets handshake_failure)."""

    def __init__(self, suites=None, suites13=(), groups13=(), curves=(23,), sni=None, mode="tls"):
        self.suites = suites or {}
        self.suites13, self.groups13, self.curves, self.sni, self.mode = list(suites13), list(groups13), list(curves), sni, mode
        self.hellos: list[dict] = []
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def close(self):
        self.srv.close()

    def _loop(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        try:
            conn.settimeout(3)
            data = b""
            while len(data) < 5 or len(data) < 5 + struct.unpack("!H", data[3:5])[0]:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            if self.mode == "close":
                return
            if self.mode == "http":
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
            if data[0] != 0x16:
                return
            hello = _parse_hello(data)
            self.hellos.append(hello)
            conn.sendall(self.answer(hello))
            time.sleep(0.05)
        except OSError:
            pass
        finally:
            conn.close()

    def answer(self, h: dict) -> bytes:
        if self.mode == "alert":
            return _alert("handshake_failure")
        if self.sni and h["sni"] != self.sni:
            return _alert("unrecognized_name")
        offered13 = h["versions"] or []
        if T.TLS13 in offered13 and self.suites13:
            cipher = next((c for c in self.suites13 if c in h["suites"]), None)
            if cipher is None:
                return _alert("handshake_failure")
            share = next((g for g in self.groups13 if g in h["key_share"]), None)
            if share is not None:
                return _server_hello(0x0303, cipher, struct.pack("!HHH", 43, 2, T.TLS13) +
                                     struct.pack("!HHHH", 51, 4 + 32, share, 32) + os.urandom(32))
            pick = next((g for g in self.groups13 if g in (h["groups"] or [])), None)
            if pick is None:
                return _alert("handshake_failure")
            return _server_hello(0x0303, cipher, struct.pack("!HHH", 43, 2, T.TLS13) + struct.pack("!HHH", 51, 2, pick),
                                 hrr=True)
        client = max([v for v in offered13 if v <= T.TLS12] or [h["legacy_version"]])
        legacy = sorted(self.suites)
        if not legacy:
            return _alert("protocol_version")
        chosen = max([v for v in legacy if v <= client] or [0])
        if not chosen:
            return _alert("protocol_version")
        if 0x5600 in h["suites"] and chosen < (T.TLS13 if self.suites13 else max(legacy)):
            return _alert("inappropriate_fallback")
        groups = h["groups"] if h["groups"] is not None else self.curves
        for cipher in self.suites[chosen]:
            if cipher not in h["suites"]:
                continue
            if E.is_ecdhe(cipher):
                curve = next((c for c in self.curves if c in groups), None)
                if curve is None:
                    continue
                return (_server_hello(chosen, cipher) + _record(12, b"\x03" + struct.pack("!HB", curve, 65) + bytes(65)) +
                        _record(14, b""))
            return _server_hello(chosen, cipher) + _record(14, b"")
        return _alert("handshake_failure")


def _ctx() -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                      scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 300)


def _scan(server: FakeTls, *, budget=128, sni_names=(), s_client=None, monkeypatch=None, mode="full"):
    ctx = _ctx()
    scan = N.NetworkScan(ctx, {"sni_hostnames": list(sni_names),
                               "rate_limits": {"connections_per_second": 500, "parallel_per_server": 4,
                                               "handshakes_per_endpoint": budget}})
    result = scan.scan_endpoint(N.Endpoint("127.0.0.1", server.port, "tls", "https"), mode)
    ctx.flush()
    return result, ctx.collected, scan


def _fake_s_client(server: FakeTls):
    """s_client as the node sees it (it does not connect: these servers have no certificate): a full handshake that
    succeeds where the server would answer, with the server's first suite printed the OpenSSL way, as the real tool
    prints it, and "<NULL>" as the group when nothing was negotiated (what openssl 3.5 prints)."""
    def run(ip, port, protocol, sni, timeout=15.0):
        if server.mode != "tls" or (server.sni and sni != server.sni) or not (server.suites or server.suites13):
            return T.FullHandshake(error="handshake failed", group="<NULL>")
        if server.suites13:
            return T.FullHandshake(ok=True, version="TLSv1.3", cipher=R.OPENSSL_NAMES[server.suites13[0]], group="X25519")
        top = max(server.suites)
        return T.FullHandshake(ok=True, version=T.VERSION_NAMES[top], cipher=R.OPENSSL_NAMES[server.suites[top][0]],
                               group="X25519")
    return run


@pytest.fixture
def lab(monkeypatch):
    servers: list[FakeTls] = []

    def make(**kw):
        s = FakeTls(**kw)
        servers.append(s)
        monkeypatch.setattr(T, "s_client", _fake_s_client(s))
        monkeypatch.setattr(T, "have_openssl", lambda: True)
        return s
    yield make
    for s in servers:
        s.close()


def _rows(collected, kind):
    return [a for a in collected if a["type"] == kind]


C = R.suite_code
TLS12_SUITES = [C("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), C("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
                C("TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"),  # only in the IANA registry chunk (not the probe table)
                C("TLS_RSA_WITH_AES_128_CBC_SHA"), C("TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384")]
TLS13 = [0x1302, 0x1301, 0x1303]


# ----------------------------------------------------------------------------- KF-4: SNI-only servers
def test_sni_only_server_is_read_with_the_configured_name(lab, monkeypatch):
    srv = lab(suites={T.TLS12: TLS12_SUITES[:2]}, suites13=TLS13, groups13=[29, 23], sni="app.example.test")
    monkeypatch.setattr(netutil, "resolve", lambda name, *a, **k: ["127.0.0.1"] if name == "app.example.test" else [])
    (status, err, n), rows, scan = _scan(srv, sni_names=["other.example.test", "App.Example.Test."])
    tls = _rows(rows, "tls_endpoint")
    assert status == "ok" and len(tls) == 1, (status, err, rows)
    f = tls[0]["facts"]
    assert f["tls"] is True and f["sni"] == "app.example.test" and f["sni_required"] is True
    assert f["versions"]["TLSv1.2"] is True and f["versions"]["TLSv1.3"] is True and f["versions"]["TLSv1.1"] is False
    assert f["cipher_suites"]["TLSv1.2"] == [E.suite_entry(c) for c in sorted(TLS12_SUITES[:2])]
    assert {e["name"] for e in f["cipher_suites"]["TLSv1.3"]} == {R.suite_name(c) for c in TLS13}
    assert f["groups"] == ["secp256r1", "x25519"] and f["groups_complete"] is True
    assert f["enumeration"]["complete"] is True
    # after the hellos that found out it needs a name, every probe carried it
    first_named = next(i for i, h in enumerate(srv.hellos) if h["sni"])
    assert all(h["sni"] == "app.example.test" for h in srv.hellos[first_named:])
    assert not [r for r in _rows(rows, "coverage") if r["facts"]["status"] in ("sni_required", "not_tls")]


def test_sni_only_server_without_a_name_is_never_ok_and_nothing(lab):
    srv = lab(suites={T.TLS12: TLS12_SUITES[:2]}, suites13=TLS13, groups13=[29], sni="app.example.test")
    (status, err, n), rows, scan = _scan(srv)
    assert status == "tls_unavailable" and "Hostnames for SNI" in err
    tls = _rows(rows, "tls_endpoint")
    assert len(tls) == 1 and tls[0]["facts"]["tls"] is True and tls[0]["facts"]["negotiation"] == "sni_required"
    assert "unrecognized_name" in tls[0]["facts"]["alerts"]
    assert "negotiated_group" not in tls[0]["facts"]  # no "<NULL>"
    cov = [r for r in _rows(rows, "coverage") if r["facts"]["status"] == "sni_required"]
    assert len(cov) == 1 and cov[0]["facts"]["incomplete"] is True and cov[0]["facts"]["scope"] == [f"127.0.0.1:{srv.port}"]
    assert len(srv.hellos) <= 3  # it said it needs a name: no version sweep without one
    assert scan.own_rows == {f"127.0.0.1:{srv.port}"}


# ----------------------------------------------------------------------------- KF-5 / EC-4: not TLS vs alert-only TLS
@pytest.mark.parametrize("mode,said", [("close", "closed the connection without a TLS answer"), ("http", "answered 'HTTP/'")])
def test_a_listener_that_does_not_speak_tls_is_not_a_tls_asset(lab, mode, said):
    srv = lab(mode=mode)
    (status, err, n), rows, scan = _scan(srv)
    assert (status, n) == ("ok", 0)
    assert not _rows(rows, "tls_endpoint") and not _rows(rows, "certificate")
    cov = _rows(rows, "coverage")
    assert len(cov) == 1 and cov[0]["facts"]["status"] == "not_tls" and said in cov[0]["facts"]["detail"]
    assert cov[0]["facts"]["scope"] == [f"127.0.0.1:{srv.port}"] and cov[0]["facts"]["incomplete"] is False


def test_parallel_endpoints_each_keep_their_own_not_tls_reason(lab):
    import concurrent.futures as cf

    closes, http = lab(mode="close"), lab(mode="http")
    ctx = _ctx()
    scan = N.NetworkScan(ctx, {"rate_limits": {"connections_per_second": 500, "parallel_per_server": 8}})
    eps = [N.Endpoint("127.0.0.1", s.port, "tls", "") for s in (closes, http) for _ in range(6)]
    with cf.ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda ep: scan.scan_endpoint(ep, "full"), eps))
    ctx.flush()
    for row in ctx.collected:
        port = int(row["facts"]["scope"][0].rsplit(":", 1)[1])
        assert ("answered 'HTTP/'" in row["facts"]["detail"]) is (port == http.port), row["facts"]["detail"]


def test_a_tls_server_that_only_alerts_is_tls_with_no_common_parameters(lab):
    srv = lab(mode="alert")
    (status, err, n), rows, scan = _scan(srv)
    assert status == "not_supported" and n == 1
    f = _rows(rows, "tls_endpoint")[0]["facts"]
    assert f["tls"] is True and f["negotiation"] == "no_common_parameters" and f["alerts"] == ["handshake_failure"]
    assert all(v is False for v in f["versions"].values())
    cov = [r for r in _rows(rows, "coverage") if r["facts"]["status"] == "no_common_parameters"]
    assert len(cov) == 1 and cov[0]["facts"]["incomplete"] is True


# ----------------------------------------------------------------------------- #100: enumeration and its budget
def _full_server(lab):
    return lab(suites={T.TLS10: TLS12_SUITES[3:4], T.TLS12: TLS12_SUITES}, suites13=TLS13 + [0x1304],
               groups13=[0x11EC, 0x0202, 29, 23, 24, 256], curves=(29, 23))


def test_every_suite_per_version_tls13_suites_and_groups_are_enumerated(lab):
    srv = _full_server(lab)
    (status, err, n), rows, scan = _scan(srv)
    f = _rows(rows, "tls_endpoint")[0]["facts"]
    assert status == "ok"
    assert {e["name"] for e in f["cipher_suites"]["TLSv1.2"]} == {R.suite_name(c) for c in TLS12_SUITES}
    assert f["cipher_suites"]["TLSv1.0"] == [E.suite_entry(TLS12_SUITES[3])]
    assert {e["code"] for e in f["cipher_suites"]["TLSv1.3"]} == {R.code_hex(c) for c in TLS13 + [0x1304]}
    assert f["cipher_suites_complete"] == {"TLSv1.0": True, "TLSv1.2": True, "TLSv1.3": True}
    assert f["ciphers"] == sorted({R.suite_name(c) for c in TLS12_SUITES + TLS13 + [0x1304]}, key=lambda n: R.suite_code(n))
    assert f["groups"] == sorted(["X25519MLKEM768", "MLKEM1024", "x25519", "secp256r1", "secp384r1", "ffdhe2048"])
    assert f["pq_hybrid"] is True and f["pq_groups"] == ["X25519MLKEM768", "MLKEM1024"] and f["pq_groups_enumerated"]
    assert f["classical_tls13_accepted"] is True and f["groups_complete"] is True
    assert f["weak_ciphers_accepted"] == {"static_rsa": sorted(R.suite_name(c) for c in TLS12_SUITES[3:])}
    assert f["enumeration"] == {"complete": True, "not_complete": []}
    # every suite has its IANA name and its code (#103: one name per suite)
    for entries in f["cipher_suites"].values():
        for e in entries:
            assert R.suite_code(e["name"]) == int(e["code"], 16)


def test_handshakes_are_bounded_by_the_documented_formula(lab):
    srv = _full_server(lab)
    (status, err, n), rows, scan = _scan(srv)
    f = _rows(rows, "tls_endpoint")[0]["facts"]
    # full handshake 1; versions SSL3, TLS1.0, 1.1, 1.2 = 4 (TLS 1.3 came from the full handshake); PQ groups 2 + 1;
    # SCSV 1; weak classes 4; classical groups 4 + 1; TLS 1.3 suites 3 more + 1; TLS 1.2: 5 known/new + 2 chunks;
    # TLS 1.0: 1 known + 2 chunks
    pq, classical = 2, 4
    expected = 1 + 4 + (pq + 1) + 1 + 4 + (classical + 1) + (3 + 1) + (5 - 1 - 1 + 2) + (0 + 2)
    # the fake s_client does not reach the server: the server saw every other handshake
    assert f["handshakes_used"] == len(srv.hellos) + 1 == expected, (f["handshakes_used"], len(srv.hellos), expected)


def test_a_small_budget_is_honoured_and_marks_the_lists_incomplete_without_a_gap(lab):
    srv = _full_server(lab)
    (status, err, n), rows, scan = _scan(srv, budget=12)
    f = _rows(rows, "tls_endpoint")[0]["facts"]
    assert status == "ok" and f["handshakes_used"] == len(srv.hellos) + 1 == 12 and f["handshake_budget"] == 12
    assert f["enumeration"]["complete"] is False
    assert any("handshake budget (12)" in r for r in f["enumeration"]["not_complete"])
    assert False in f["cipher_suites_complete"].values()
    # the checks that judge findings ran (versions, PQ, SCSV, weak classes): no coverage gap, drift stays as before
    assert not _rows(rows, "coverage")


def test_fragile_mode_does_not_enumerate(lab):
    srv = _full_server(lab)
    (status, err, n), rows, scan = _scan(srv, mode="fragile")
    f = _rows(rows, "tls_endpoint")[0]["facts"]
    assert f["handshakes_used"] <= 6 and f["enumeration"]["complete"] is False
    assert f["enumeration"]["not_complete"] == ["fragile mode: suites and groups are not enumerated"]


def test_a_pass_that_ends_without_a_refusal_is_incomplete(lab):
    srv = _full_server(lab)
    calls = []

    def send(hello, want_kex):
        calls.append(1)
        if len(calls) == 2:
            return T.HelloResult(alert="decode_error")
        return T.probe("127.0.0.1", srv.port, "tls", hello, 3.0, want_kex)

    p = E.legacy_suites(send, T.TLS12, set(), None, {})
    assert p.complete is False and p.reason == "alert decode_error" and len(p.found) == 1


# ----------------------------------------------------------------------------- names, codes, sentinels (#103)
def test_the_negotiated_suite_is_stored_with_its_iana_name_and_code_and_no_sentinel(lab):
    srv = lab(suites={T.TLS12: [C("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")]}, curves=(23,))
    (status, err, n), rows, scan = _scan(srv)
    f = _rows(rows, "tls_endpoint")[0]["facts"]
    assert f["negotiated_cipher"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" and f["negotiated_cipher_code"] == "0xC02F"
    assert _rows(rows, "tls_endpoint")[0]["algorithm"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert f["negotiated_group"] == "x25519"
    assert f["ciphers"] == ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]


@pytest.mark.parametrize("line", ["Peer Temp Key: <NULL>", "Negotiated TLS1.3 group: <NULL>", "Server Temp Key: (NONE)"])
def test_parse_s_client_never_returns_a_sentinel_group(line):
    fh = T.parse_s_client(f"CONNECTED(00000003)\n{line}\nNew, (NONE), Cipher is (NONE)\n")
    assert fh.group is None and fh.cipher is None and not fh.ok


def test_registry_is_the_iana_registry_and_openssl_names():
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen", Path(__file__).resolve().parents[1] / "scripts/gen_tls_registry.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert R.SUITES == gen.suites() and len(R.SUITES) == 356
    assert R.OPENSSL_NAMES == {c: v[1] for c, v in gen.openssl_names().items()}
    assert R.GROUP_NAMES == gen.groups()
    assert R.suite_code("ECDHE-RSA-AES128-SHA") == R.suite_code("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA") == 0xC013
    assert set(T.CIPHERS) <= set(R.SUITES) and all(R.SUITES[c] == n for c, n in T.CIPHERS.items())
    assert R.suite_code("(NONE)") is None and R.suite_code(None) is None


def test_registry_groups_are_algid_groups():
    from zs_scan_node import algid_tables as A

    assert R.GROUP_NAMES == dict(A.TLS_GROUPS)  # two tables from the same IANA registry agree code for code


def test_weak_classes_over_the_registry_are_the_node_rules():
    for label, table in (("obsolete", T.OBSOLETE), ("static_rsa", T.STATIC_RSA), ("cbc", T.CBC_FS), ("dhe", T.DHE_SUITES)):
        assert sorted(c for c, n in T.CIPHERS.items() if label in E.suite_classes(n)) == sorted(table), label


# ----------------------------------------------------------------------------- SNI names: bounded DNS, never-scan
def test_sni_names_resolve_once_per_job_within_a_bounded_time(monkeypatch):
    monkeypatch.setattr(N, "SNI_DNS_BUDGET_S", 0.5)
    calls = []

    def slow(name, *a, **k):
        calls.append(name)
        if name.startswith("slow"):
            time.sleep(3)
        return ["10.0.0.7"] if name == "fast.test" else []
    monkeypatch.setattr(netutil, "resolve", slow)
    ctx = _ctx()
    names = ["fast.test"] + [f"slow{i}.test" for i in range(250)]
    scan = N.NetworkScan(ctx, {"sni_hostnames": names})
    t0 = time.monotonic()
    assert scan.sni_names_for("10.0.0.7") == ["fast.test"]
    assert time.monotonic() - t0 < 2.0
    started = len(calls)
    assert scan.sni_names_for("10.0.0.8") == [] and len(calls) == started <= N.SNI_MAX_NAMES  # once per job
    assert "51 SNI host names beyond the first 200" in scan.sni_left_out and "did not resolve within" in scan.sni_left_out


def test_never_scan_names_are_never_sent(monkeypatch):
    monkeypatch.setattr(netutil, "resolve", lambda name, *a, **k: ["10.0.0.7"])
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range", scrubber=Scrubber(),
                     never_scan=NeverScan(["secret.test"]), deadline=time.monotonic() + 60)
    scan = N.NetworkScan(ctx, {"sni_hostnames": ["secret.test", "ok.test"]})
    assert scan.sni_names_for("10.0.0.7") == ["ok.test"]


# ----------------------------------------------------------------------------- PostgreSQL TLS versions
class FakePostgres(FakeTls):
    """SSLRequest -> 'S', then the TLS answers of FakeTls."""

    def _one(self, conn):
        try:
            conn.settimeout(3)
            if conn.recv(8) != struct.pack("!II", 8, 80877103):
                return
            conn.sendall(b"S")
        except OSError:
            conn.close()
            return
        super()._one(conn)


def test_postgres_tls_versions_are_every_version_the_server_accepts(monkeypatch):
    from zs_scan_node.collectors import database as D

    srv = FakePostgres(suites={T.TLS12: [C("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")]}, suites13=[0x1302, 0x1301],
                       groups13=[29], curves=(29,))
    monkeypatch.setattr(T, "have_openssl", lambda: True)
    monkeypatch.setattr(T, "s_client", lambda ip, port, proto, sni, timeout=15.0: T.FullHandshake(
        ok=True, version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", group="X25519"))
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="database", scrubber=Scrubber(),
                     never_scan=NeverScan([]), deadline=time.monotonic() + 60)
    facts, n = D._server_tls(ctx, D.Target("db.test", "127.0.0.1"), srv.port, "postgres")
    srv.close()
    assert facts["versions"] == {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}
    assert {e["name"] for e in facts["cipher_suites"]["TLSv1.3"]} == {"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"}
    assert facts["cipher_suites"]["TLSv1.2"] == [E.suite_entry(C("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"))]
    assert facts["negotiated_cipher"] == "TLS_AES_256_GCM_SHA384" and facts["negotiated_cipher_code"] == "0x1302"
    assert facts["groups"] == ["x25519"] and facts["handshakes_used"] <= D.DB_TLS_BUDGET
    assert all(h["legacy_version"] for h in srv.hellos)  # every probe went through the SSLRequest preamble
