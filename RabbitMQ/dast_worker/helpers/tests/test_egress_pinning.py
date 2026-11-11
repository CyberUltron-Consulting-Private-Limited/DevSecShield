"""DNS rebinding: every connection the DAST worker makes for a scan goes to an address checked with the backend's rule.

Before: the backend checked the target's DNS answer, then the worker resolved the name again for each request, so a
name answering a public address first and a private one second (DNS rebinding) sent the crawler, the headers check,
nuclei and Chromium to backend:8080 or 169.254.169.254. Now the scan's hosts are resolved once, checked and pinned
(helpers/net/egress.py); Python HTTP connects only to pinned addresses and nuclei/Chromium only through the scan's
SOCKS5 guard.

Servers here listen on 127.0.0.2 (the "allowed" address, opened through the operator allowlist) and 127.0.0.1 (the
"internal service" a rebinding answer points at). Hermetic: loopback only.
"""
from __future__ import annotations

import http.server
import socket
import threading
import urllib.error

import pytest

import helpers.agent.main as agent_main
from helpers.checks.nuclei import run_nuclei as nuclei_mod
from helpers.checks.security_headers import fetch_http_headers
from helpers.crawler.native_crawler import crawl
from helpers.net.address_rule import DastSsrfError, parse_allowlist
from helpers.net.egress import EgressProxy, EgressRefused, ScanEgress

ALLOWED = "127.0.0.2"
INTERNAL = "127.0.0.1"
OPERATOR = parse_allowlist("127.0.0.2/32")  # the operator opened 127.0.0.2 only


class Rebinding:
    """A resolver that answers ``first`` once, then ``then`` (a DNS-rebinding name)."""

    def __init__(self, first: list[str], then: list[str]):
        self.first, self.then, self.calls = first, then, 0

    def __call__(self, _host: str) -> list[str]:
        self.calls += 1
        return self.first if self.calls == 1 else self.then


def _serve(address: str, routes: dict[str, tuple[int, dict, bytes]]):
    hits: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            status, headers, body = routes.get(self.path, (200, {"Content-Type": "text/html"}, b"<html>ok</html>"))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass

    server = http.server.ThreadingHTTPServer((address, 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1], hits


@pytest.fixture
def internal():
    server, port, hits = _serve(INTERNAL, {"/": (200, {"Content-Type": "text/html"}, b"<html>SECRET</html>")})
    yield port, hits
    server.shutdown()


def _app(routes=None):
    return _serve(ALLOWED, routes or {})


# ---------------------------------------------------------------- the rule at scan start
def test_public_then_private_is_pinned_to_the_checked_public_address(monkeypatch):
    resolver = Rebinding(["93.184.216.34"], ["10.0.0.5"])
    egress = ScanEgress(["https://app.example/", "https://app.example/login"], rules=parse_allowlist(""),
                        resolve=resolver)
    dialed = []
    monkeypatch.setattr("helpers.net.egress.socket.create_connection",
                        lambda address, timeout=None: dialed.append(address) or socket.socket())
    for _ in range(3):
        egress.connect("app.example", 443, 5).close()
    assert dialed == [("93.184.216.34", 443)] * 3
    assert resolver.calls == 1  # the name is never resolved again, so the second (private) answer is never used


def test_a_host_that_answers_private_at_the_worker_stops_the_scan_before_any_connection():
    with pytest.raises(DastSsrfError, match="private address"):
        ScanEgress(["https://app.example/"], rules=parse_allowlist(""), resolve=lambda _h: ["10.0.0.5"])
    with pytest.raises(DastSsrfError, match="private address"):
        ScanEgress(["https://app.example/"], rules=parse_allowlist(""), resolve=lambda _h: ["93.184.216.34", "172.17.0.3"])


@pytest.mark.parametrize("address", ["169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254"])
def test_metadata_is_refused_even_when_the_operator_lists_it(address):
    everything = parse_allowlist("0.0.0.0/0,::/0,169.254.0.0/16,meta.example")
    with pytest.raises(DastSsrfError, match="metadata"):
        ScanEgress(["http://meta.example/"], rules=everything, resolve=lambda _h: [address])
    with pytest.raises(DastSsrfError, match="metadata"):
        ScanEgress([f"http://[{address}]/" if ":" in address else f"http://{address}/"], rules=everything)


def test_the_worker_reads_dast_allowed_private(monkeypatch):
    monkeypatch.delenv("DAST_ALLOWED_PRIVATE", raising=False)
    with pytest.raises(DastSsrfError, match="DAST_ALLOWED_PRIVATE"):
        ScanEgress(["http://app.internal/"], resolve=lambda _h: ["10.1.2.3"])
    monkeypatch.setenv("DAST_ALLOWED_PRIVATE", "10.1.0.0/16")
    assert ScanEgress(["http://app.internal/"], resolve=lambda _h: ["10.1.2.3"]).pinned == {"app.internal": ("10.1.2.3",)}


def test_agent_scan_fails_closed_when_the_target_rebinds_to_private(monkeypatch):
    monkeypatch.setattr(agent_main, "ScanEgress",
                        lambda urls: ScanEgress(urls, rules=parse_allowlist(""), resolve=lambda _h: ["169.254.169.254"]))
    monkeypatch.setattr(agent_main, "reap_orphan_browsers", lambda: None)
    crawled = []
    monkeypatch.setattr(agent_main, "Crawler", lambda **kw: crawled.append(kw))
    context = agent_main.StartDASTScanData(
        target_url="http://app.example/", auth=agent_main.AuthRequirements(
            login_url="http://app.example/login", username="u", password="p", xpath_of_username_field="//a",
            xpath_of_password_field="//b", xpath_of_submit_button="//c"))
    agent = agent_main.DASTAgent(context)
    with pytest.raises(DastSsrfError, match="metadata"):
        agent.run()
    assert crawled == []  # nothing was crawled
    assert agent.estimate_credits() == -1


# ---------------------------------------------------------------- Python HTTP (crawler, headers check)
def test_python_http_is_pinned_and_never_re_resolves(internal):
    internal_port, internal_hits = internal
    server, port, hits = _app({"/": (200, {"Content-Type": "text/html"}, b'<a href="/a">a</a><a href="/b">b</a>')})
    try:
        resolver = Rebinding([ALLOWED], [INTERNAL])
        egress = ScanEgress([f"http://app.test:{port}/"], rules=OPERATOR, resolve=resolver)
        found = crawl(f"http://app.test:{port}/", 5, egress)
        assert set(found) == {f"http://app.test:{port}/", f"http://app.test:{port}/a", f"http://app.test:{port}/b"}
        assert sorted(hits) == ["/", "/a", "/b"] and internal_hits == []
        assert "content-length" in {k.lower() for k in fetch_http_headers(f"http://app.test:{port}/", 5, egress)}
        assert resolver.calls == 1
    finally:
        server.shutdown()


@pytest.mark.parametrize("location", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:{internal}/",
    "http://localhost:{internal}/",
    "http://evil.test/",
    "ftp://127.0.0.1:{internal}/",
])
def test_redirects_to_private_metadata_or_out_of_scope_are_refused(internal, location):
    internal_port, internal_hits = internal
    target = location.format(internal=internal_port)
    server, port, _hits = _app({"/": (302, {"Location": target}, b"")})
    try:
        egress = ScanEgress([f"http://app.test:{port}/"], rules=OPERATOR, resolve=lambda _h: [ALLOWED])
        with pytest.raises(urllib.error.URLError):
            fetch_http_headers(f"http://app.test:{port}/", 5, egress)
        assert crawl(f"http://app.test:{port}/", 3, egress) == [f"http://app.test:{port}/"]
        assert internal_hits == []
        if not target.startswith("ftp"):
            assert egress.metadata()["refused_connections"] >= 1
    finally:
        server.shutdown()


def test_python_clients_refuse_to_run_without_the_scan_egress():
    with pytest.raises(EgressRefused):
        fetch_http_headers("http://app.test/", 5)
    with pytest.raises(EgressRefused):
        crawl("http://app.test/", 5)


# ---------------------------------------------------------------- SOCKS5 guard (nuclei + Chromium)
def _socks_connect(proxy_url: str, host: str, port: int) -> tuple[int, socket.socket]:
    proxy_port = int(proxy_url.rsplit(":", 1)[1])
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    try:
        packed, atyp = socket.inet_pton(socket.AF_INET, host), 1
    except OSError:
        try:
            packed, atyp = socket.inet_pton(socket.AF_INET6, host), 4
        except OSError:
            packed, atyp = bytes([len(host)]) + host.encode(), 3
    s.sendall(bytes([5, 1, 0, atyp]) + packed + port.to_bytes(2, "big"))
    reply = s.recv(10)
    return reply[1], s


def test_socks_guard_pins_names_and_refuses_everything_else(internal):
    internal_port, internal_hits = internal
    server, port, hits = _app()
    resolver = Rebinding([ALLOWED], [INTERNAL])
    egress = ScanEgress([f"http://app.test:{port}/"], rules=OPERATOR, resolve=resolver)
    try:
        with EgressProxy(egress) as proxy:
            for host in ("app.test", ALLOWED):  # the in-scope name, and its checked address as a literal
                code, s = _socks_connect(proxy.url, host, port)
                assert code == 0
                s.sendall(b"GET /via-guard HTTP/1.0\r\nHost: app.test\r\n\r\n")
                assert b"200" in s.recv(100)
                s.close()
            for host, p in (("evil.test", 80), (INTERNAL, internal_port), ("localhost", internal_port),
                            ("169.254.169.254", 80), ("::ffff:127.0.0.1", internal_port), ("::1", internal_port)):
                code, s = _socks_connect(proxy.url, host, p)
                s.close()
                assert code == 2, host  # 0x02: connection not allowed by ruleset
        assert hits.count("/via-guard") == 2 and internal_hits == []
        assert resolver.calls == 1
        assert egress.metadata()["refused_connections"] == 6
    finally:
        server.shutdown()


# ---------------------------------------------------------------- nuclei command
def test_nuclei_runs_only_through_the_guard(monkeypatch, tmp_path):
    started = []
    monkeypatch.setattr(nuclei_mod.subprocess, "Popen", lambda *a, **k: started.append(a))
    with pytest.raises(nuclei_mod.NucleiWithoutEgressGuard):
        nuclei_mod.run_nuclei("http://app.test/", str(tmp_path / "t.yaml"), 5)
    assert started == []

    command = nuclei_mod.build_nuclei_command("http://app.test/", "/t.yaml", 30, egress_proxy="socks5://127.0.0.1:4321")
    pairs = list(zip(command, command[1:]))
    assert ("-proxy", "socks5://127.0.0.1:4321") in pairs and "-pi" in command and "-duc" in command
    assert ("-pt", "headless,http") in pairs
    headless = [b for a, b in pairs if a == "-ho"]
    assert "proxy-server=socks5://127.0.0.1:4321" in headless
    assert "proxy-bypass-list=<-loopback>" in headless
    assert "host-resolver-rules=MAP * ~NOTFOUND,EXCLUDE 127.0.0.1" in headless
