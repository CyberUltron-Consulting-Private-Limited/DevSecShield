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
    assert outbound.resolve("public.example", 443) == ["93.184.216.34"]
    with pytest.raises(outbound.Refused):  # one bad address is enough: DNS may pick it later
        outbound.resolve("mixed.example", 443)
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "10.20.0.0/16, splunk.corp.local")
    assert outbound.resolve("siem.corp.local", 6514) == ["10.20.30.40"]  # CIDR rule
    assert outbound.resolve("splunk.corp.local", 8088) == ["192.168.7.9"]  # host-name rule
    with pytest.raises(outbound.Refused):
        outbound.resolve("10.99.0.1", 514)  # outside the listed range
    with pytest.raises(outbound.TransportError, match="does not resolve"):
        outbound.resolve("unknown.example", 443)
    with pytest.raises(outbound.Refused):
        outbound.resolve("siem.corp.local", 0)


def test_site_local_ipv6_is_private_not_public(monkeypatch):
    """rev5 #7: fec0::/10 (deprecated site-local, RFC 3879) is_global in Python, so it was treated as a public
    address. It is private now: refused unless the operator lists it, in the integrations guard and in safe_fetch."""
    from backend.utilities.cbom_sources import safe_fetch

    for address in ("fec0::1", "fec0:0:0:ffff::1", "feff:ffff::1"):
        assert not safe_fetch.public_address(address)
    assert safe_fetch.public_address("2001:4860:4860::8888")  # a global unicast address stays public
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    _fake_dns(monkeypatch, {"siem.corp.example": ["fec0::10"]})
    with pytest.raises(outbound.Refused, match="INTEGRATION_ALLOWED_PRIVATE"):
        outbound.resolve("siem.corp.example", 6514)
    with pytest.raises(outbound.Refused, match="INTEGRATION_ALLOWED_PRIVATE"):
        outbound.resolve("fec0::10", 6514)
    with pytest.raises(safe_fetch.FetchError, match="private or reserved"):
        safe_fetch._resolve("siem.corp.example", 443, False)
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "fec0::/10")
    assert outbound.resolve("siem.corp.example", 6514) == ["fec0::10"]


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


DUAL_STACK = ["2600:1f18:1234::1", "52.10.1.1"]  # 2600:... sorts before 52....: the old pin chose IPv6


def _ipv4_only_host(monkeypatch, port_for_v4: int) -> list[tuple[str, int]]:
    """This host cannot reach IPv6 (the compose files enable none): an IPv6 connect fails at once with ENETUNREACH;
    the IPv4 address lands on a local test server. Returns the connect attempts."""
    import errno

    from backend.utilities.cbom_sources import safe_fetch

    attempts: list[tuple[str, int]] = []

    def create_connection(address, timeout=None, *a, **k):
        attempts.append(address)
        if ":" in address[0]:
            raise OSError(errno.ENETUNREACH, "Network is unreachable")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # no name lookup: getaddrinfo is faked
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", port_for_v4))
        return sock

    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(safe_fetch, "_routable", lambda address, port: ":" not in address)
    return attempts


def test_a_dual_stack_destination_is_reached_over_the_family_this_host_can_route(tmp_path, monkeypatch):
    """rev5 #6: the pin was the lexically first checked address, so a dual-stack name always got its IPv6 address and
    failed in an IPv4-only container. Every address is still checked; they are tried in turn, routable first."""
    from backend.utilities.cbom_sources import safe_fetch

    _fake_dns(monkeypatch, {"hec.example.com": DUAL_STACK})
    monkeypatch.setattr(safe_fetch, "_routable", lambda address, port: True)
    assert outbound.resolve("hec.example.com", 443) == DUAL_STACK  # all routable: the resolver's order
    monkeypatch.setattr(safe_fetch, "_routable", lambda address, port: ":" not in address)
    assert outbound.resolve("hec.example.com", 443) == ["52.10.1.1", "2600:1f18:1234::1"]
    _fake_dns(monkeypatch, {"hec.example.com": [*DUAL_STACK, "10.0.0.9"]})
    with pytest.raises(outbound.Refused):  # each address is checked: one private address refuses the host
        outbound.resolve("hec.example.com", 443)

    pki = make_pki(tmp_path / "pki", ["hec.example.com"])
    srv, port = https_server(pki, lambda h, b: (200, {}, b'{"code":0}'))
    try:
        _fake_dns(monkeypatch, {"hec.example.com": DUAL_STACK})
        attempts = _ipv4_only_host(monkeypatch, port)
        resp = outbound.request("POST", f"https://hec.example.com:{port}/services/collector/event", body=b"{}",
                                ca_pem=pki["ca_pem"])
        assert resp.status == 200 and attempts == [("52.10.1.1", port)]
        # even when the resolver's order puts the unreachable family first, the connection falls back to the next
        monkeypatch.setattr(safe_fetch, "_routable", lambda address, port: True)
        attempts.clear()
        assert outbound.request("GET", f"https://hec.example.com:{port}/", ca_pem=pki["ca_pem"]).status == 200
        assert attempts == [("2600:1f18:1234::1", port), ("52.10.1.1", port)]
    finally:
        srv.shutdown()


def test_safe_fetch_reaches_a_dual_stack_host_over_ipv4(tmp_path, monkeypatch):
    """The same address choice in safe_fetch (IdP metadata, URL sources)."""
    from backend.utilities.cbom_sources import safe_fetch

    pki = make_pki(tmp_path / "pki", ["idp.example.com"])
    monkeypatch.setenv("CBOM_EXTRA_CA_FILE", pki["ca"])
    monkeypatch.delenv("CBOM_LAB_CA_FILE", raising=False)
    srv, port = https_server(pki, lambda h, b: (200, {"Content-Type": "application/json"}, b'{"issuer":"x"}'))
    try:
        monkeypatch.setattr(safe_fetch.socket, "getaddrinfo",
                            lambda host, p, *a, **k: [(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                                                       socket.SOCK_STREAM, 6, "", (ip, p)) for ip in DUAL_STACK])
        attempts = _ipv4_only_host(monkeypatch, port)
        got = safe_fetch.fetch(f"https://idp.example.com:{port}/.well-known/openid-configuration")
        assert got.status == 200 and got.body == b'{"issuer":"x"}' and attempts == [("52.10.1.1", port)]
    finally:
        srv.shutdown()


@pytest.fixture()
def tls(tmp_path, monkeypatch):
    pki = make_pki(tmp_path / "pki", ["hooks.wp11.test"])
    # transport tests: the guard is proven above; here "hooks.wp11.test" is pinned to a local test server
    monkeypatch.setattr(outbound, "resolve", lambda host, port, **k: ["127.0.0.1"])
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
    monkeypatch.setattr(outbound, "resolve", lambda host, port, **k: ["127.0.0.1"])
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
