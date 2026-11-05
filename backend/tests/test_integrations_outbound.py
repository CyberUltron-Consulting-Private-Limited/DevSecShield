"""The outbound guard every integration connection uses (WP11): SSRF refusals, the operator allowlist, address pinning,
TLS verification with a destination CA, no redirects, timeouts and the response cap."""
from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.utilities.integrations import outbound  # noqa: E402
from integrations_helpers import https_server, make_pki, server_context, silent_server  # noqa: E402

ALWAYS_BLOCKED = ["127.0.0.1", "127.9.9.9", "::1", "169.254.169.254", "fd00:ec2::254", "100.64.0.1", "100.100.100.200",
                  "0.0.0.0", "0.1.2.3", "192.0.0.192", "224.0.0.1", "240.0.0.1", "::ffff:127.0.0.1",
                  "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "fe80::1"]


def _fake_dns(monkeypatch, table: dict[str, list[str]]):
    def getaddrinfo(host, port, *a, **k):
        if host not in table:
            raise socket.gaierror("nope")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in table[host]]

    monkeypatch.setattr(outbound.socket, "getaddrinfo", getaddrinfo)


@pytest.mark.parametrize("address", ALWAYS_BLOCKED)
def test_loopback_link_local_metadata_cgnat_are_refused_even_when_the_operator_lists_everything(monkeypatch, address):
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "0.0.0.0/0,::/0,evil.example")
    _fake_dns(monkeypatch, {"evil.example": [address]})
    with pytest.raises(outbound.Refused, match="never allowed"):
        outbound.resolve("evil.example", 443)
    with pytest.raises(outbound.Refused):
        outbound.resolve(address, 443)  # an IP literal goes through the same check


def test_private_addresses_need_the_operator_allowlist(monkeypatch):
    _fake_dns(monkeypatch, {"siem.corp.local": ["10.20.30.40"], "splunk.corp.local": ["192.168.7.9"],
                            "mixed.example": ["93.184.216.34", "10.0.0.5"], "public.example": ["93.184.216.34"]})
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    with pytest.raises(outbound.Refused, match="INTEGRATION_ALLOWED_PRIVATE"):
        outbound.resolve("siem.corp.local", 6514)
    assert outbound.resolve("public.example", 443) == "93.184.216.34"
    with pytest.raises(outbound.Refused):  # one bad address is enough: DNS may pick it later
        outbound.resolve("mixed.example", 443)
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "10.20.0.0/16, splunk.corp.local")
    assert outbound.resolve("siem.corp.local", 6514) == "10.20.30.40"  # CIDR rule
    assert outbound.resolve("splunk.corp.local", 8088) == "192.168.7.9"  # host-name rule
    with pytest.raises(outbound.Refused):
        outbound.resolve("10.99.0.1", 514)  # outside the listed range
    with pytest.raises(outbound.TransportError, match="does not resolve"):
        outbound.resolve("unknown.example", 443)
    with pytest.raises(outbound.Refused):
        outbound.resolve("siem.corp.local", 0)


def test_https_url_rules():
    with pytest.raises(outbound.Refused, match="https"):
        outbound.check_https_url("http://hooks.example/x")
    with pytest.raises(outbound.Refused, match="user name"):
        outbound.check_https_url("https://user:pw@hooks.example/x")
    assert outbound.check_https_url("https://hooks.example:8443/a?b=1") == ("hooks.example", 8443, "/a?b=1")


def test_the_connection_goes_to_the_checked_address_not_a_second_lookup(monkeypatch):
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "10.0.0.0/8")
    answers = iter([["10.1.1.1"], ["127.0.0.1"]])  # a rebinding resolver: second answer would be loopback
    monkeypatch.setattr(outbound.socket, "getaddrinfo",
                        lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                                                     for ip in next(answers)])
    seen = []

    def connect(address, timeout=None, *a, **k):
        seen.append(address)
        raise ConnectionRefusedError()

    monkeypatch.setattr(outbound.socket, "create_connection", connect)
    with pytest.raises(outbound.TransportError, match="refused"):
        outbound.request("POST", "https://hooks.corp.local/x", body=b"{}")
    assert seen == [("10.1.1.1", 443)]


@pytest.fixture()
def tls(tmp_path, monkeypatch):
    pki = make_pki(tmp_path / "pki", ["hooks.wp11.test"])
    # transport tests: the guard is proven above; here "hooks.wp11.test" is pinned to a local test server
    monkeypatch.setattr(outbound, "resolve", lambda host, port, **k: "127.0.0.1")
    return pki


def test_tls_is_verified_against_the_destination_ca_and_redirects_are_not_followed(tls):
    def reply(handler, body):
        if handler.path == "/redirect":
            return 302, {"Location": "https://169.254.169.254/latest/meta-data/"}, b""
        return 200, {"Content-Type": "application/json"}, b'{"ok":true,"secret":"server-side-detail"}'

    srv, port = https_server(tls, reply)
    try:
        with pytest.raises(outbound.TransportError, match="not trusted"):
            outbound.request("GET", f"https://hooks.wp11.test:{port}/")  # system store only: refused
        resp = outbound.request("GET", f"https://hooks.wp11.test:{port}/", ca_pem=tls["ca_pem"])
        assert resp.status == 200 and resp.body.startswith(b'{"ok"')
        resp = outbound.request("GET", f"https://hooks.wp11.test:{port}/redirect", ca_pem=tls["ca_pem"])
        assert resp.status == 302  # returned as is
        assert [r["path"] for r in srv.requests] == ["/", "/redirect"]  # the Location was never requested
        with pytest.raises(outbound.TransportError, match="TLS"):  # wrong name on the certificate
            outbound.request("GET", f"https://other.wp11.test:{port}/", ca_pem=tls["ca_pem"])
    finally:
        srv.shutdown()


def test_a_large_response_is_capped(tls):
    srv, port = https_server(tls, lambda h, b: (200, {}, b"x" * (outbound.MAX_RESPONSE * 3)))
    try:
        resp = outbound.request("GET", f"https://hooks.wp11.test:{port}/", ca_pem=tls["ca_pem"])
        assert len(resp.body) == outbound.MAX_RESPONSE
    finally:
        srv.shutdown()


def test_a_silent_server_times_out_within_the_total_budget(monkeypatch):
    monkeypatch.setattr(outbound, "resolve", lambda host, port, **k: "127.0.0.1")
    sock, port = silent_server()
    try:
        start = time.monotonic()
        with pytest.raises(outbound.TransportError):
            outbound.request("GET", f"https://hooks.wp11.test:{port}/", total=2.0)
        assert time.monotonic() - start < 6
        start = time.monotonic()
        with pytest.raises(outbound.TransportError):
            outbound.send_stream("hooks.wp11.test", port, [b"x"], tls=True, total=2.0)
        assert time.monotonic() - start < 6
    finally:
        sock.close()


def _stream_receiver(mode: str, pki: dict[str, str] | None = None) -> tuple[int, dict]:
    """A one-connection syslog receiver. ``reset``: reads nothing, then aborts (RST: unread data is discarded);
    ``clean``: reads to the end, answers close_notify (TLS) and closes; ``ragged``: reads to the end (our close_notify
    included) and closes TCP without answering it."""
    import ssl
    import struct
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got: dict = {"data": b""}

    def run() -> None:
        conn, _ = srv.accept()
        srv.close()
        if pki is not None:
            conn = server_context(pki).wrap_socket(conn, server_side=True)
        if mode == "reset":
            time.sleep(0.3)  # the client has written everything and started closing
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            conn.close()
            return
        while True:
            try:
                chunk = conn.recv(4096)
            except ssl.SSLZeroReturnError:
                break
            if not chunk:
                break
            got["data"] += chunk
        if mode == "clean" and pki is not None:
            conn.unwrap().close()
        else:
            conn.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1], got


@pytest.mark.parametrize("tls_on", [False, True], ids=["tcp", "tls"])
def test_a_receiver_that_resets_while_closing_is_not_a_delivery(tls, tls_on):
    """rev4 M1: the reset was swallowed around unwrap / shutdown / recv, so a receiver that discarded the batch was
    recorded "delivered". A reset while closing now raises (the queue retries)."""
    port, _got = _stream_receiver("reset", tls if tls_on else None)
    with pytest.raises(outbound.TransportError, match="reset the connection before the batch was confirmed"):
        outbound.send_stream("hooks.wp11.test", port, [b"5 hello", b"5 world"], tls=tls_on, ca_pem=tls["ca_pem"])


@pytest.mark.parametrize("mode,tls_on", [("clean", False), ("clean", True), ("ragged", True)])
def test_a_receiver_that_read_everything_confirms_the_batch(tls, mode, tls_on):
    """A clean close confirms the batch; so does a TLS receiver that read up to our close_notify and closed TCP
    without answering it (RFC 5425 asks for an answer, but it consumed every frame)."""
    port, got = _stream_receiver(mode, tls if tls_on else None)
    assert outbound.send_stream("hooks.wp11.test", port, [b"5 hello", b"5 world"], tls=tls_on,
                                ca_pem=tls["ca_pem"]) == 2
    deadline = time.monotonic() + 5
    while got["data"] != b"5 hello5 world" and time.monotonic() < deadline:
        time.sleep(0.05)
    assert got["data"] == b"5 hello5 world"


def test_stream_and_datagrams_use_the_same_guard(monkeypatch):
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    with pytest.raises(outbound.Refused):
        outbound.send_stream("127.0.0.1", 514, [b"x"], tls=False)
    with pytest.raises(outbound.Refused):
        outbound.send_datagrams("169.254.169.254", 514, [b"x"])
    with pytest.raises(outbound.Refused, match="INTEGRATION_ALLOWED_PRIVATE"):
        outbound.send_datagrams("10.1.2.3", 514, [b"x"])
