"""Issue #53: an MCP scan's server URL and a custom LLM scan's model URI follow the CBOM SSRF guard's address rule.

Found by the T2 builder (#33 audit): ``format_input_for_scan`` copied ``mcp.server_url`` and ``llm.model_uri`` into the
worker's kwargs with no address check, so an estimate or start with ``http://169.254.169.254/latest/meta-data/`` or a
compose service name (``http://backend:8000/``) made the scan worker connect there. The API now refuses with 400 before
it sends an estimate or scan task (estimate, start and reinitialize all assemble the kwargs there), using
the CBOM SSRF guard's rule (``cbom_sources/address_rule.py``, which ``safe_fetch.py`` runs): every address the host
resolves to must be public. The worker checks again when it connects, with the same file
(RabbitMQ/worker/tests/test_scan_target_egress.py).

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_mcp_llm_target_ssrf.py -q -p no:cacheprovider
"""
from __future__ import annotations

import asyncio
import importlib.util
import ipaddress
import socket
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from backend.utilities.cbom_sources import safe_fetch  # noqa: E402
from backend.utilities.db.schemas import StartScanPayload  # noqa: E402
from backend.utilities.scan import estimate_scan, start_scan  # noqa: E402
from backend.utilities.scan.format_input import format_input_for_scan  # noqa: E402

WORKER_GUARD = REPO / "RabbitMQ" / "worker" / "helpers" / "net" / "guard.py"
PUBLIC = "93.184.216.34"
DNS = {
    "mcp.example.com": [PUBLIC],
    "llm.example.com": [PUBLIC, "2606:2800:220:1:248:1893:25c8:1946"],
    "backend": ["172.20.0.5"],  # a compose service name on the stack's network
    "localhost": ["127.0.0.1", "::1"],
    "metadata.example": ["169.254.169.254"],
    "internal.example": ["10.1.2.3"],
    "ula.example": ["fd12:3456:789a::1"],
    "rebind.example": [PUBLIC, "192.168.1.20"],  # one public and one private answer
}


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """The system resolver, answering from DNS (an IP literal answers itself, as getaddrinfo does; like CPython's,
    a str host is IDNA-encoded first, which raises UnicodeError for a label over 63 characters)."""
    def getaddrinfo(host, port, *args, **kwargs):
        str(host).encode("idna")
        try:
            answers = [str(ipaddress.ip_address(str(host)))]
        except ValueError:
            answers = DNS.get(str(host).lower().rstrip("."), [])
        if not answers:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port or 0))
                for a in answers]
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


REFUSED = [
    "http://127.0.0.1:8000/mcp",  # loopback
    "http://localhost:3000/mcp",  # a name for loopback
    "http://169.254.169.254/latest/meta-data/",  # link-local: the cloud metadata service
    "http://metadata.example/latest/meta-data/",  # a name resolving to it
    "http://10.0.0.5/mcp",  # RFC 1918 10/8
    "http://172.16.4.2:8080/mcp",  # RFC 1918 172.16/12
    "https://192.168.1.1/mcp",  # RFC 1918 192.168/16
    "http://backend:8000/",  # a compose service name (private)
    "https://internal.example/v1/chat",  # a name resolving to RFC 1918
    "http://[::1]:8000/mcp",  # IPv6 loopback
    "http://[fc00::1]/mcp",  # IPv6 unique-local fc00::/7
    "http://[fd12:3456:789a::1]/mcp",  # ... its fd00::/8 half
    "https://ula.example/mcp",  # a name resolving to fc00::/7
    "http://[fe80::1]/mcp",  # IPv6 link-local
    "http://[::ffff:169.254.169.254]/",  # IPv4-mapped metadata
    "http://[64:ff9b::a9fe:a9fe]/",  # NAT64 form of 169.254.169.254
    "http://100.64.0.1/",  # CGNAT
    "http://0.0.0.0:8000/",  # unspecified
    "http://rebind.example/mcp",  # one private answer refuses the host (DNS may hand it out later)
]


@pytest.mark.parametrize("url", REFUSED)
def test_the_rule_refuses_private_and_reserved_addresses(url):
    from backend.utilities.scan.target_address import TargetAddressRefused, check_scan_target

    with pytest.raises(TargetAddressRefused, match="private or reserved address; only public addresses can be scanned"):
        check_scan_target(url, "MCP server URL")


def test_a_public_url_passes_with_its_checked_addresses():
    from backend.utilities.scan.target_address import check_scan_target

    assert check_scan_target("https://mcp.example.com/mcp", "MCP server URL") == [PUBLIC]
    assert sorted(check_scan_target("http://llm.example.com:8443/v1", "Model URI")) == sorted(DNS["llm.example.com"])
    assert check_scan_target(f"http://{PUBLIC}:8000/sse", "MCP server URL") == [PUBLIC]


@pytest.mark.parametrize("url, says", [
    ("", "is required"),
    (None, "is required"),
    ("ftp://mcp.example.com/", "http:// or https://"),
    ("file:///etc/passwd", "http:// or https://"),
    ("gopher://mcp.example.com:70/", "http:// or https://"),
    ("mcp.example.com/mcp", "http:// or https://"),  # no scheme: no host either
    ("http://[::1/", "not a valid URL"),
    ("http://mcp.example.com:99999/", "invalid port"),
    ("https://nowhere.example/mcp", "does not resolve"),
    ("https://" + "a" * 70 + ".example/", "not a valid host name"),
])
def test_what_is_not_a_checkable_url_is_refused(url, says):
    from backend.utilities.scan.target_address import TargetAddressRefused, check_scan_target

    with pytest.raises(TargetAddressRefused, match=says):
        check_scan_target(url, "MCP server URL")


def _mcp(url: str) -> StartScanPayload:
    return StartScanPayload.model_validate({"mcp": {"server_url": url, "server_mode": "httpstreamable"}})


def _llm(model_type: str, model_uri: str | None) -> StartScanPayload:
    return StartScanPayload.model_validate({"llm": {
        "model_type": model_type, "model_name": "m", "model_uri": model_uri, "probes": ["dan"],
        "request_template": {"input": "$INPUT"}, "response_json_field": "$.text"}})


def _format(scan_type: str, payload: StartScanPayload) -> dict:
    return asyncio.run(format_input_for_scan(scan_type=scan_type, start_scan_payload=payload, uploaded_file=None))


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://backend:8000/",
                                 "http://[::1]:8000/mcp", "https://ula.example/mcp", "http://rebind.example/mcp"])
def test_an_mcp_scan_to_a_private_server_is_a_400(url):
    with pytest.raises(HTTPException) as err:
        _format("mcp", _mcp(url))
    assert err.value.status_code == 400
    assert err.value.detail.startswith("MCP server URL: ") and "only public addresses can be scanned" in err.value.detail


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                                 "http://internal.example/v1", "http://[fc00::1]/v1", "http://localhost:11434/api"])
def test_a_custom_llm_scan_to_a_private_model_is_a_400(url):
    with pytest.raises(HTTPException) as err:
        _format("llm", _llm("custom", url))
    assert err.value.status_code == 400
    assert err.value.detail.startswith("Model URI: ") and "only public addresses can be scanned" in err.value.detail


def test_a_custom_llm_scan_without_a_model_uri_is_a_400():
    with pytest.raises(HTTPException) as err:
        _format("llm", _llm("custom", None))
    assert err.value.status_code == 400 and err.value.detail == "Model URI is required"


def test_public_targets_still_reach_the_worker_unchanged():
    mcp = _format("mcp", _mcp("https://mcp.example.com/mcp"))
    assert mcp["mcp_dict_context"]["server_url"] == "https://mcp.example.com/mcp"
    llm = _format("llm", _llm("custom", "https://llm.example.com/v1/chat"))
    assert llm["llm_benchmark_dict_context"]["model_uri"] == "https://llm.example.com/v1/chat"
    # a vendor model's URI comes from the worker's template; a model_uri sent with it is not used, so not checked
    vendor = _format("llm", _llm("openai", "http://169.254.169.254/"))
    assert vendor["llm_benchmark_dict_context"]["model_type"] == "openai"


class _Celery:
    """Records what would be sent to the workers; an estimate it ran says 0.01 credits."""

    def __init__(self):
        self.sent: list[str] = []

    def send_task(self, name, **_kwargs):
        self.sent.append(name)
        return type("Task", (), {"id": "t-1"})()

    def AsyncResult(self, _task_id):  # noqa: N802 - Celery's name
        return type("Result", (), {"state": "SUCCESS", "result": 0.01})()


@pytest.mark.parametrize("scan_type, payload", [("mcp", _mcp("http://169.254.169.254/latest/meta-data/")),
                                                ("llm", _llm("custom", "http://backend:8000/v1"))])
def test_estimate_refuses_before_any_task_is_sent(monkeypatch, scan_type, payload):
    app = _Celery()
    monkeypatch.setattr(estimate_scan, "get_celery_app", lambda: app)
    with pytest.raises(HTTPException) as err:
        asyncio.run(estimate_scan.estimate_credits(scan_type=scan_type, engine=None, start_scan_payload=payload))
    assert err.value.status_code == 400 and app.sent == []


@pytest.mark.parametrize("scan_type, payload", [("mcp", _mcp("http://10.0.0.5/mcp")),
                                                ("llm", _llm("custom", "http://[::1]:8000/v1"))])
def test_start_and_reinitialize_refuse_before_any_task_is_sent(monkeypatch, scan_type, payload):
    """Both routes dispatch through start_scan_and_update_db; a refusal there is a 400 the start route refunds."""
    app = _Celery()
    monkeypatch.setattr(start_scan, "get_celery_app", lambda: app)
    with pytest.raises(HTTPException) as err:
        asyncio.run(start_scan.start_scan_and_update_db(scan_type=scan_type, engine=None, scan_id=1, team_id=1,
                                                        start_scan_payload=payload))
    assert err.value.status_code == 400 and app.sent == []


@pytest.fixture()
def start_route(monkeypatch):
    """/start over SQLite with a fake dispatch. Scan 1 holds an estimate for a private server URL (made before this
    check, or before its name started resolving to a private address), scan 2 one for a public URL: a stored estimate
    that matches the input is charged at once, before dispatch, so /start must check the target before it charges."""
    import datetime as dt
    import types

    from fastapi.testclient import TestClient
    from sqlalchemy.pool import StaticPool
    from sqlmodel import Session, SQLModel, create_engine

    from backend.new_models import Scan, Team, TeamMembership, User
    from backend.routers import scans
    from backend.utilities.scan import credit_estimate
    from backend.utilities.team import credits

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    payloads = {1: _mcp("http://backend:8000/mcp"), 2: _mcp("https://mcp.example.com/mcp")}
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=100.0))
        s.add(User(id=1, email="u@example.test", password="x", first_name="u", last_name="t", default_team_id=1))
        s.add(TeamMembership(team_id=1, user_id=1, role="admin"))
        for scan_id, payload in payloads.items():
            measured = credit_estimate.input_digest("mcp", scans._payload_section(payload, "mcp"), None)
            s.add(Scan(id=scan_id, team_id=1, owner_user_id=1, scan_type="mcp", scan_status="NOT_STARTED",
                       created_at=dt.datetime.now(dt.timezone.utc), credit_consumed=0.01,
                       credit_estimate={**measured, "minimum": 0.0, "credits": 0.01}))
        s.commit()
    dispatched: list[int] = []

    async def dispatch(**kwargs):
        dispatched.append(kwargs["scan_id"])
        with Session(engine) as s:
            scan = s.get(Scan, kwargs["scan_id"])
            scan.task_id = "task"
            s.add(scan)
            s.commit()

    async def estimate(**_kwargs):
        raise AssertionError("the stored estimate matches the input: no re-estimate")

    async def user(*_a, **_k):
        return types.SimpleNamespace(id=1, email="u@example.test")

    monkeypatch.setattr(scans, "get_db", lambda: engine)
    monkeypatch.setattr(scans, "get_mongo_client_db", lambda: None)
    monkeypatch.setattr(scans, "get_user_from_header_or_raise_exception", user)
    monkeypatch.setattr(scans, "check_if_user_is_in_team", lambda *_a, **_k: None)
    monkeypatch.setattr(scans, "start_scan_and_update_db", dispatch)
    monkeypatch.setattr(scans, "estimate_credits", estimate)
    monkeypatch.setattr(credits, "get_db", lambda: engine)
    from backend.main import app

    def start(scan_id: int):
        return TestClient(app).post(f"/1/mcp/scan/{scan_id}/start", headers={"Authorization": "Bearer t"},
                                    data={"start_scan_payload_string": payloads[scan_id].model_dump_json()})

    def row(scan_id: int):
        with Session(engine) as s:
            scan = s.get(Scan, scan_id)
            return scan.scan_status, scan.credit_charged, s.get(Team, 1).credit_balance

    return start, row, dispatched


def test_start_refuses_a_private_target_before_any_credit_moves(start_route):
    start, row, dispatched = start_route
    refused = start(1)
    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"].startswith("MCP server URL: backend resolves to a private or reserved address")
    assert row(1) == ("NOT_STARTED", None, 100.0) and dispatched == []  # nothing charged, claim given back
    started = start(2)  # the same route charges and dispatches a public target
    assert started.status_code == 200, started.text
    assert row(2) == ("pending", 0.01, 99.99) and dispatched == [2]


def test_the_workers_connect_time_refusal_is_a_400_that_says_why():
    """The worker refuses at connect time when DNS changed after the API's check or the server redirected."""
    exc = estimate_scan._estimation_failure(
        type("Result", (), {"result": RuntimeError("MCP connection failed: address not allowed")})(), "mcp")
    assert exc.status_code == 400
    assert "private or reserved address" in exc.detail and "public addresses" in exc.detail


def test_safe_fetch_the_scan_api_and_the_worker_run_one_address_rule(monkeypatch):
    """#53 review: the worker had a copy of safe_fetch's rule. There is one file now, cbom_sources/address_rule.py:
    safe_fetch re-exports its functions (the same objects), the scan API calls it, and the worker loads this file."""
    from backend.utilities.cbom_sources import address_rule
    from backend.utilities.scan.target_address import check_scan_target

    for name in ("public_address", "connection_order", "connect_first", "_CGNAT", "_V4_IN_V6"):
        assert getattr(safe_fetch, name) is getattr(address_rule, name), name
    assert not hasattr(safe_fetch, "_routable")  # patch address_rule._routable: a patch here would change nothing
    spec = importlib.util.spec_from_file_location("_worker_net_guard", WORKER_GUARD)
    worker_guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker_guard)
    assert Path(worker_guard.RULE.__file__).resolve() == Path(address_rule.__file__).resolve()
    assert not (WORKER_GUARD.parent / "address_rule.py").exists()  # no copy left in the worker
    # safe_fetch and the scan API decide through the shared module: change it, and both answers change
    monkeypatch.setattr(address_rule, "public_address", lambda text: True)
    assert safe_fetch._resolve("169.254.169.254", 443, False) == ["169.254.169.254"]
    assert check_scan_target("http://169.254.169.254/latest/meta-data/", "MCP server URL") == ["169.254.169.254"]
