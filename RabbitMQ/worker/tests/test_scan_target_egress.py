"""Issue #53, worker side: an MCP or LLM scan connects only to checked public addresses, redirects included.

The API checks an MCP server URL and a custom model URI before it queues a scan (backend tests
test_mcp_llm_target_ssrf.py), but DNS can answer differently when the worker connects (DNS rebinding) and a server can
redirect. So the worker applies the same rule (helpers/net/address_rule.py, the CBOM SSRF guard's code) at connect time:
every address of a host's DNS answer must be public before the answer is used, and every connection of the scan goes to
a checked address. MCP: every request of the MCP client (helpers/net/egress.py PinnedTransport). LLM: every connection
garak's REST generator makes goes through a local SOCKS5 proxy that applies the rule (GuardedSocksProxy).

Run: cd RabbitMQ/worker && uv run --frozen --with pytest==9.2.0 python -m pytest -q tests/test_scan_target_egress.py
"""
from __future__ import annotations

import ast
import asyncio
import http.server
import ipaddress
import json
import os
import socket
import sys
import threading
from pathlib import Path

import httpx
import pytest
import requests

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKER not in sys.path:
    sys.path.insert(0, WORKER)

from helpers.net import address_rule, egress  # noqa: E402
from helpers.net.address_rule import TargetGuard, TargetRefused  # noqa: E402
from helpers.tools.llm_agent import llm_runner  # noqa: E402
from helpers.tools.mcp_agent import main as mcp_main  # noqa: E402
from helpers.tools.mcp_agent.context import MCPContext  # noqa: E402
from helpers.tools.mcp_agent.mcp_client import mcp_connection_failure  # noqa: E402

PUBLIC = "93.184.216.34"
DNS = {
    "mcp.example.com": [PUBLIC],
    "llm.example.com": [PUBLIC],
    "other.example.com": ["8.8.8.8"],
    "metadata.example": ["169.254.169.254"],
    "internal.example": ["10.1.2.3"],
    "ula.example": ["fd00:1234::7"],
    "localhost": ["127.0.0.1", "::1"],
    "rebind.example": [PUBLIC, "192.168.1.20"],
    "api.openai.com": ["162.159.140.245"],
}


def _answers(host: str) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host.strip("[]")))]
    except ValueError:
        answers = DNS.get(host.lower().rstrip("."), [])
    if not answers:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    return list(answers)


@pytest.fixture()
def fake_dns(monkeypatch):
    """The system resolver answers from DNS (an IP literal answers itself, as getaddrinfo does)."""
    def getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port or 0))
                for a in _answers(str(host))]
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


REFUSED = [
    "http://127.0.0.1:8000/mcp", "http://localhost:3000/", "http://169.254.169.254/latest/meta-data/",
    "http://metadata.example/", "http://10.0.0.5/", "http://172.16.4.2:8080/", "https://192.168.1.1/",
    "https://internal.example/v1", "http://[::1]:8000/", "http://[fc00::1]/", "http://[fd12:3456:789a::1]/",
    "https://ula.example/", "http://[fe80::1]/", "http://[::ffff:10.0.0.1]/", "http://100.64.0.1/",
    "http://0.0.0.0/", "http://rebind.example/",
]


@pytest.mark.parametrize("url", REFUSED)
def test_the_guard_refuses_private_and_reserved_addresses(fake_dns, url):
    with pytest.raises(TargetRefused, match="private or reserved address"):
        TargetGuard().check_url(url)


def test_the_guard_passes_public_addresses(fake_dns):
    assert TargetGuard().check_url("https://mcp.example.com/mcp") == (PUBLIC,)
    assert TargetGuard().check_url(f"http://{PUBLIC}:8080/sse") == (PUBLIC,)


def test_a_name_that_does_not_resolve_is_unreachable_not_refused(fake_dns):
    with pytest.raises(OSError) as err:
        TargetGuard().check_url("https://nowhere.example/mcp")
    assert not isinstance(err.value, TargetRefused)
    assert mcp_connection_failure(err.value) == "MCP connection failed: unreachable"


def test_a_checked_answer_is_pinned_and_every_new_answer_is_checked():
    """DNS rebinding: the checked (public) answer is used for its pin window, never a second (private) one unchecked;
    once the window ends the host is resolved again and that answer is checked before any use."""
    answers = iter([[PUBLIC], ["169.254.169.254"]])
    calls, now = [], [100.0]

    def resolve(host, port):
        calls.append(host)
        return next(answers)
    guard = TargetGuard(resolve=resolve, clock=lambda: now[0])
    assert guard.check_url("https://mcp.example.com/mcp") == (PUBLIC,)
    now[0] += address_rule.PIN_SECONDS - 1
    assert guard.addresses("mcp.example.com", 443) == (PUBLIC,)
    assert guard.addresses("MCP.Example.com", 8443) == (PUBLIC,)
    assert calls == ["mcp.example.com"]
    now[0] += 1
    with pytest.raises(TargetRefused, match="private or reserved address"):
        guard.addresses("mcp.example.com", 443)
    assert calls == ["mcp.example.com", "mcp.example.com"]


SAFE_FETCH = Path(WORKER).parents[1] / "backend" / "utilities" / "cbom_sources" / "safe_fetch.py"
RULE_NAMES = {"_CGNAT", "_V4_IN_V6", "public_address", "_routable", "connection_order"}


def _definitions(path: Path) -> dict[str, str]:
    """The source of the module-level functions and assignments named in RULE_NAMES (read, not imported)."""
    source = path.read_text(encoding="utf-8")
    found = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name in RULE_NAMES:
            found[node.name] = ast.get_source_segment(source, node)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and getattr(node.targets[0], "id", "") in RULE_NAMES:
            found[node.targets[0].id] = ast.get_source_segment(source, node)
    return found


@pytest.mark.skipif(not SAFE_FETCH.is_file(), reason="the backend is not in this checkout")
def test_the_rule_is_the_cbom_ssrf_guards_code():
    """The worker cannot import the backend: its rule is safe_fetch's code, copied. A change to either copy fails here
    (worker suite) and in backend tests/test_mcp_llm_target_ssrf.py (backend suite): change both."""
    ours = _definitions(Path(address_rule.__file__))
    assert set(ours) == RULE_NAMES
    assert ours == _definitions(SAFE_FETCH)


def test_a_refused_redirect_says_address_not_allowed():
    leaf = TargetRefused("169.254.169.254 resolves to a private or reserved address")
    assert mcp_connection_failure(ExceptionGroup("unhandled errors in a TaskGroup", [leaf])) == (
        "MCP connection failed: address not allowed")


# ---------------------------------------------------------------------------------------------------- MCP (httpx)
class _Server:
    """What the inner (pinned) transport was asked to send, answered by ``route(request)``."""

    def __init__(self, route):
        self.route = route
        self.seen: list[httpx.Request] = []

    def __call__(self):
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        return self.route(request)


def _client(server: _Server, monkeypatch, guard: TargetGuard | None = None) -> httpx.AsyncClient:
    monkeypatch.setattr(egress, "_inner_transport", server)
    return egress.guarded_http_client_factory(guard or TargetGuard())(headers={"X-Probe": "1"})


async def _get(client: httpx.AsyncClient, url: str) -> httpx.Response:
    async with client:
        return await client.get(url)


def test_mcp_requests_go_to_the_checked_address_with_the_name_for_tls(fake_dns, monkeypatch):
    server = _Server(lambda request: httpx.Response(200, text="ok"))
    response = asyncio.run(_get(_client(server, monkeypatch), "https://mcp.example.com/mcp"))
    assert response.status_code == 200 and str(response.request.url) == "https://mcp.example.com/mcp"
    (sent,) = server.seen
    assert sent.url.host == PUBLIC  # pinned: the connection goes to the address that was checked
    assert sent.extensions["sni_hostname"] == "mcp.example.com"  # TLS: SNI and the certificate are for the name
    assert sent.headers["host"] == "mcp.example.com" and sent.headers["x-probe"] == "1"


@pytest.mark.parametrize("location", ["http://169.254.169.254/latest/meta-data/", "http://metadata.example/",
                                      "http://internal.example:8080/admin", "http://[::1]:8000/",
                                      "http://[fd00:1234::7]/", "https://ula.example/"])
def test_an_mcp_redirect_to_a_private_address_is_refused(fake_dns, monkeypatch, location):
    server = _Server(lambda request: httpx.Response(307, headers={"Location": location}))
    with pytest.raises(TargetRefused):
        asyncio.run(_get(_client(server, monkeypatch), "https://mcp.example.com/mcp"))
    assert [str(r.url) for r in server.seen] == [f"https://{PUBLIC}/mcp"]  # the private hop was never sent


def test_an_mcp_redirect_to_a_public_host_is_followed_and_pinned(fake_dns, monkeypatch):
    def route(request):
        if request.extensions["sni_hostname"] == "mcp.example.com":
            return httpx.Response(302, headers={"Location": "https://other.example.com/mcp"})
        return httpx.Response(200, text="ok")
    server = _Server(route)
    assert asyncio.run(_get(_client(server, monkeypatch), "https://mcp.example.com/mcp")).status_code == 200
    assert [r.url.host for r in server.seen] == [PUBLIC, "8.8.8.8"]


def test_an_environment_proxy_is_not_used(fake_dns, monkeypatch):
    """A proxy would resolve the name itself, after the check: the MCP client ignores HTTP(S)_PROXY / ALL_PROXY."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "http://10.9.9.9:3128")
    server = _Server(lambda request: httpx.Response(200))
    asyncio.run(_get(_client(server, monkeypatch), "https://mcp.example.com/mcp"))
    assert [r.url.host for r in server.seen] == [PUBLIC]


def _recon(url: str, mode: str):
    return mcp_main.MCPAgent(mcp_context=MCPContext(server_url=url, server_mode=mode)).estimate_credits_required()


@pytest.mark.parametrize("mode", ["httpstreamable", "sse"])
@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://internal.example:8000/mcp",
                                 "http://[::1]:8000/mcp", "http://rebind.example/sse"])
def test_the_mcp_client_never_connects_to_a_private_server(fake_dns, monkeypatch, url, mode):
    server = _Server(lambda request: httpx.Response(200))
    monkeypatch.setattr(egress, "_inner_transport", server)
    with pytest.raises(RuntimeError) as err:
        _recon(url, mode)
    assert str(err.value) == "MCP connection failed: address not allowed"
    assert server.seen == []


@pytest.mark.parametrize("mode", ["httpstreamable", "sse"])
def test_the_mcp_client_refuses_a_redirect_to_the_metadata_service(fake_dns, monkeypatch, mode):
    server = _Server(lambda request: httpx.Response(307, headers={"Location": "http://169.254.169.254/latest/"}))
    monkeypatch.setattr(egress, "_inner_transport", server)
    with pytest.raises(RuntimeError) as err:
        _recon("https://mcp.example.com/mcp", mode)
    assert str(err.value) == "MCP connection failed: address not allowed"
    assert [r.url.host for r in server.seen] == [PUBLIC]


# ------------------------------------------------------------------------------------------- LLM (garak, SOCKS5)
class _Redirector(http.server.BaseHTTPRequestHandler):
    location = ""
    hits: list[str] = []

    def _answer(self):
        type(self).hits.append(self.path)
        if type(self).location:
            self.send_response(307)
            self.send_header("Location", type(self).location)
        else:
            self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = _answer

    def log_message(self, *args):
        pass


@pytest.fixture()
def lab_server():
    """A real HTTP server on 127.0.0.1 standing in for a public model endpoint (the test guard maps a name to it)."""
    _Redirector.location, _Redirector.hits = "", []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Redirector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


class _LabGuard(TargetGuard):
    """The real rule, except that ``public.example`` (the test's stand-in for a public endpoint) is 127.0.0.1."""

    def addresses(self, host, port):
        if host == "public.example":
            return ("127.0.0.1",)
        return super().addresses(host, port)


@pytest.fixture()
def connections(monkeypatch):
    """Every TCP connection the proxy opens upstream."""
    made: list[tuple] = []
    real = socket.create_connection

    def create_connection(address, *args, **kwargs):
        made.append(address)
        return real(address, *args, **kwargs)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    return made


def _via(proxy, url: str):
    return requests.post(url, data=b"{}", timeout=10, proxies={"http": proxy.url, "https": proxy.url})


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://metadata.example/",
                                 "http://internal.example/v1", "http://[::1]:8000/v1", "http://[fc00::1]/v1",
                                 "https://ula.example/v1", "http://localhost:11434/api/generate"])
def test_garaks_connection_to_a_private_address_is_refused(fake_dns, connections, url):
    with egress.GuardedSocksProxy(_LabGuard()) as proxy:
        with pytest.raises(requests.exceptions.ConnectionError):
            _via(proxy, url)
    assert connections == []


@pytest.mark.parametrize("location", ["http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                                      "http://internal.example:8080/", "http://[::1]:9000/"])
def test_garaks_redirect_to_a_private_address_is_refused(fake_dns, connections, lab_server, location):
    _Redirector.location = location
    with egress.GuardedSocksProxy(_LabGuard()) as proxy:
        with pytest.raises(requests.exceptions.ConnectionError):
            _via(proxy, f"http://public.example:{lab_server.server_address[1]}/v1")
    assert _Redirector.hits == ["/v1"]  # the endpoint answered once; the redirect's private target never
    assert connections == [("127.0.0.1", lab_server.server_address[1])]


def test_garaks_connection_to_a_checked_address_is_relayed(fake_dns, connections, lab_server):
    with egress.GuardedSocksProxy(_LabGuard()) as proxy:
        response = _via(proxy, f"http://public.example:{lab_server.server_address[1]}/v1")
    assert response.status_code == 200 and response.text == "ok"
    assert connections == [("127.0.0.1", lab_server.server_address[1])]


def _run_garak(monkeypatch, **kwargs):
    """run_garak_scan with garak itself replaced: returns the generator config garak was given (None: not run)."""
    seen: dict = {}

    def run(cmd, check):
        config_path = cmd[cmd.index("-G") + 1]
        with open(config_path, encoding="utf-8") as f:
            seen["config"] = json.load(f)
        os.unlink(config_path)  # run_garak_scan leaves it (it only closes it); a test must not
        proxy = seen["config"]["rest"]["RestGenerator"]["proxies"]["https"]
        host, port = proxy.removeprefix("socks5h://").split(":")
        with socket.socket() as probe:  # the proxy is listening while garak runs
            probe.connect((host, int(port)))
        seen["proxy"] = (host, int(port))
    monkeypatch.setattr(llm_runner.subprocess, "run", run)
    llm_runner.run_garak_scan(probes="dan.Dan_11_0", **kwargs)
    return seen


def test_a_custom_model_on_a_private_address_is_refused_before_garak_runs(fake_dns, monkeypatch):
    with pytest.raises(TargetRefused):
        _run_garak(monkeypatch, model_type="custom", model_name="m", model_uri="http://internal.example/v1",
                   headers={"Content-Type": "application/json"}, request_template={"input": "$INPUT"},
                   response_json_field="$.text")


def test_every_garak_rest_connection_goes_through_the_guard(fake_dns, monkeypatch):
    seen = _run_garak(monkeypatch, model_type="custom", model_name="m", model_uri="https://llm.example.com/v1",
                      headers={"Content-Type": "application/json"}, request_template={"input": "$INPUT"},
                      response_json_field="$.text")
    generator = seen["config"]["rest"]["RestGenerator"]
    assert generator["uri"] == "https://llm.example.com/v1"
    assert generator["proxies"]["http"] == generator["proxies"]["https"] == "socks5h://%s:%d" % seen["proxy"]
    assert seen["proxy"][0] == "127.0.0.1"
    with pytest.raises(OSError):  # stopped once garak has finished
        socket.create_connection(seen["proxy"], timeout=2).close()


def test_a_vendor_model_is_checked_the_same_way(fake_dns, monkeypatch):
    """The URI garak connects to is checked whatever the model type (here: OpenAI's, answered by a hijacked DNS)."""
    seen = _run_garak(monkeypatch, model_type="openai", model_name="gpt-4o", api_key="sk-test")
    assert seen["config"]["rest"]["RestGenerator"]["uri"] == "https://api.openai.com/v1/responses"
    DNS["api.openai.com"] = ["10.0.0.1"]
    try:
        with pytest.raises(TargetRefused):
            _run_garak(monkeypatch, model_type="openai", model_name="gpt-4o", api_key="sk-test")
    finally:
        DNS["api.openai.com"] = ["162.159.140.245"]
