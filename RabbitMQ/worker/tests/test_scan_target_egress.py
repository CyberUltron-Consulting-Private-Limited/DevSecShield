"""Issue #53, worker side: an MCP or LLM scan connects only to checked public addresses, redirects included.

The API checks an MCP server URL and a custom model URI before it queues a scan (backend tests
test_mcp_llm_target_ssrf.py), but DNS can answer differently when the worker connects (DNS rebinding) and a server can
redirect. So the worker applies the same rule at connect time: helpers/net/guard.py runs the CBOM SSRF guard's own file
(backend/utilities/cbom_sources/address_rule.py, which safe_fetch.py runs), so every address of a host's DNS answer
must be public before the answer is used, and every connection of the scan goes to a checked address. MCP: every
request of the MCP client (helpers/net/egress.py PinnedTransport). LLM: every connection garak's REST generator makes
goes through a local SOCKS5 proxy that applies the rule (GuardedSocksProxy).

Run: cd RabbitMQ/worker && uv run --frozen --with pytest==9.2.0 python -m pytest -q tests/test_scan_target_egress.py
"""
from __future__ import annotations

import asyncio
import http.server
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import requests

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKER not in sys.path:
    sys.path.insert(0, WORKER)

from helpers.net import egress, guard  # noqa: E402
from helpers.net.guard import TargetGuard, TargetRefused  # noqa: E402
from helpers.tools.llm_agent import llm_runner  # noqa: E402
from helpers.tools.mcp_agent import main as mcp_main  # noqa: E402
from helpers.tools.mcp_agent.context import MCPContext  # noqa: E402
from helpers.tools.mcp_agent.mcp_client import MCPClient, mcp_connection_failure  # noqa: E402

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


def test_a_checked_answer_is_pinned_and_every_new_answer_is_checked(monkeypatch):
    """DNS rebinding: the checked (public) answer is used for its pin window, never a second (private) one unchecked;
    once the window ends the host is resolved again and that answer is checked before any use."""
    answers = iter([[PUBLIC], ["169.254.169.254"]])
    calls, now = [], [100.0]

    def getaddrinfo(host, port, *args, **kwargs):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in next(answers)]
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    target = TargetGuard(clock=lambda: now[0])
    assert target.check_url("https://mcp.example.com/mcp") == (PUBLIC,)
    now[0] += guard.PIN_SECONDS - 1
    assert target.addresses("mcp.example.com", 443) == (PUBLIC,)
    assert target.addresses("MCP.Example.com", 8443) == (PUBLIC,)
    assert calls == ["mcp.example.com"]
    now[0] += 1
    with pytest.raises(TargetRefused, match="private or reserved address"):
        target.addresses("mcp.example.com", 443)
    assert calls == ["mcp.example.com", "mcp.example.com"]
    assert target.refused == [
        "mcp.example.com resolves to a private or reserved address; only public addresses can be scanned"]


SHARED_RULE = Path(WORKER).parents[1] / "backend" / "utilities" / "cbom_sources" / "address_rule.py"


def test_the_guard_runs_the_cbom_ssrf_guards_own_rule_file(fake_dns, monkeypatch):
    """The worker holds no copy of the rule: guard.RULE is the file safe_fetch.py runs (the worker image carries it at
    the same path), and every answer of the guard is that module's: change the rule and the worker's answer changes."""
    assert Path(guard.RULE.__file__).resolve() == SHARED_RULE.resolve()
    assert not (Path(WORKER) / "helpers" / "net" / "address_rule.py").exists()
    with pytest.raises(TargetRefused):
        TargetGuard().check_url("http://169.254.169.254/latest/meta-data/")
    monkeypatch.setattr(guard.RULE, "public_address", lambda text: True)  # the shared rule, changed for this test
    assert TargetGuard().check_url("http://169.254.169.254/latest/meta-data/") == ("169.254.169.254",)
    monkeypatch.setattr(guard.RULE, "scan_target", lambda url: ("mcp.example.com", 443))
    assert TargetGuard().check_url("gopher://anything/") == (PUBLIC,)
    made = []
    monkeypatch.setattr(guard.RULE, "connect_first", lambda addresses, port, timeout: made.append((addresses, port)))
    TargetGuard().connect("mcp.example.com", 443)
    assert made == [([PUBLIC], 443)]


def test_the_worker_image_carries_the_rule_where_the_guard_loads_it():
    """guard.py loads the rule from backend/ next to RabbitMQ/worker in a checkout; the image keeps the worker at
    /build/RabbitMQ/worker, so its Dockerfile copies the rule to /build/backend/... and its ignore file lets it in."""
    worker = Path(WORKER).resolve()
    rule = guard.RULE_FILE.relative_to(worker.parents[1]).as_posix()
    assert rule == "backend/utilities/cbom_sources/address_rule.py"
    dockerfile = (worker / "Dockerfile").read_text(encoding="utf-8").splitlines()
    assert "COPY --from=builder /build/RabbitMQ/worker /build/RabbitMQ/worker" in dockerfile
    assert f"COPY {rule} /build/{rule}" in dockerfile
    assert f"!{rule}" in (worker / "Dockerfile.dockerignore").read_text(encoding="utf-8").splitlines()


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


CUSTOM = {"model_type": "custom", "model_name": "m", "model_uri": "https://llm.example.com/v1",
          "headers": {"Content-Type": "application/json"}, "request_template": {"input": "$INPUT"},
          "response_json_field": "$.text"}


def test_a_connection_refused_while_garak_runs_is_reported_as_the_refusal(fake_dns, monkeypatch):
    """garak exits 1 when the proxy refuses a connection during the run (a redirect hop, a changed DNS answer): the
    scan reports the refusal, not garak's command line."""
    def run(cmd, check):
        config_path = cmd[cmd.index("-G") + 1]
        with open(config_path, encoding="utf-8") as f:
            proxies = json.load(f)["rest"]["RestGenerator"]["proxies"]
        os.unlink(config_path)
        with pytest.raises(requests.exceptions.ConnectionError):  # what garak's REST generator meets
            requests.post("http://169.254.169.254/latest/meta-data/", data=b"{}", timeout=10, proxies=proxies)
        raise subprocess.CalledProcessError(1, cmd)
    monkeypatch.setattr(llm_runner.subprocess, "run", run)
    with pytest.raises(TargetRefused, match="^169.254.169.254 resolves to a private or reserved address; only public"):
        llm_runner.run_garak_scan(probes="dan.Dan_11_0", **CUSTOM)


def test_garak_failing_for_another_reason_still_reports_garaks_error(fake_dns, monkeypatch):
    def run(cmd, check):
        os.unlink(cmd[cmd.index("-G") + 1])
        raise subprocess.CalledProcessError(2, cmd)
    monkeypatch.setattr(llm_runner.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        llm_runner.run_garak_scan(probes="dan.Dan_11_0", **CUSTOM)


class _SseEndpoint(http.server.BaseHTTPRequestHandler):
    """An MCP server over SSE whose message endpoint redirects every POST to the metadata service. Its event stream
    stays open (a ping every 0.2 s, for up to 2 minutes) until the client goes."""
    posts: list[str] = []

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        try:
            self.wfile.write(b"event: endpoint\ndata: /messages/?session_id=1\n\n")
            self.wfile.flush()
            for _ in range(600):
                time.sleep(0.2)
                self.wfile.write(b": ping\n\n")
                self.wfile.flush()
        except OSError:  # the client went
            pass

    def do_POST(self):
        type(self).posts.append(self.path)
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(307)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def test_a_refusal_the_listing_swallowed_fails_the_recon(fake_dns, monkeypatch):
    """The listing logs a failed request and returns; when the guard refused one of its hops, the recon fails and says
    why instead of estimating from a partial listing."""
    client = MCPClient(server_url="https://mcp.example.com/mcp", server_mode="httpstreamable")
    refusal = "169.254.169.254 resolves to a private or reserved address; only public addresses can be scanned"

    async def connect():
        pass

    async def listing():
        client.guard.refused.append(refusal)
    monkeypatch.setattr(client, "connect_httpstreamable", connect)
    monkeypatch.setattr(client, "list_tools_prompts_resources", listing)
    with pytest.raises(TargetRefused) as err:
        asyncio.run(client.connect_and_get_recon_context())
    assert str(err.value) == refusal


def test_an_sse_server_that_redirects_its_post_endpoint_fails_at_once(fake_dns):
    """mcp's SSE client only logs a failed POST, so the session waited on the open event stream (a pinging server held
    it for ever). The refused hop closes the client's connections: the listing fails at once and says why."""
    _SseEndpoint.posts = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SseEndpoint)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = MCPClient(server_url=f"http://public.example:{server.server_address[1]}/sse", server_mode="sse")
    client.guard = _LabGuard()
    try:
        started = time.monotonic()
        with pytest.raises(TargetRefused, match="^169.254.169.254 resolves to a private or reserved address"):
            asyncio.run(asyncio.wait_for(client.connect_and_get_recon_context(), 30))
        assert time.monotonic() - started < 20
        assert _SseEndpoint.posts == ["/messages/?session_id=1"]  # the endpoint answered; the redirect's target never
        assert mcp_connection_failure(TargetRefused(client.guard.refused[0])) == (
            "MCP connection failed: address not allowed")
    finally:
        server.shutdown()
        server.server_close()
