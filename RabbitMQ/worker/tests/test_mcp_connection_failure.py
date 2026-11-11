"""X1 (Nov 11): an MCP estimate against a server URL answering 404 gave the customer a 500 "Credit estimation failed,
please try again later". The MCP client raised ExceptionGroup('unhandled errors in a TaskGroup', [HTTPStatusError(404)])
which Celery could not serialise (UnpickleableExceptionWrapper), so the API never learned why. run_recon now raises one
plain sentence ("MCP connection failed: the MCP server answered HTTP 404" / timeout / unreachable / not an MCP
endpoint) that the API turns into a 400 (backend tests/test_mcp_estimate_failure.py). The context never prints headers.

Run: /tmp/claude-0/wvenv/bin/python -m pytest -q RabbitMQ/worker/tests/test_mcp_connection_failure.py"""
from __future__ import annotations

import os
import pickle
import sys

import httpx
import pytest

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKER not in sys.path:
    sys.path.insert(0, WORKER)

from helpers.tools.mcp_agent import main as mcp_main  # noqa: E402
from helpers.tools.mcp_agent.context import MCPContext  # noqa: E402
from helpers.tools.mcp_agent.mcp_client import mcp_connection_failure  # noqa: E402

URL = "https://example.com/sse"


def _status(code: int) -> httpx.HTTPStatusError:
    req = httpx.Request("GET", URL)
    return httpx.HTTPStatusError(f"Client error '{code}'", request=req, response=httpx.Response(code, request=req))


@pytest.mark.parametrize("exc, reason", [
    (ExceptionGroup("unhandled errors in a TaskGroup", [_status(404)]), "the MCP server answered HTTP 404"),
    (ExceptionGroup("g", [ExceptionGroup("inner", [_status(502)])]), "the MCP server answered HTTP 502"),
    (ExceptionGroup("unhandled errors in a TaskGroup", [httpx.ConnectTimeout("")]), "timeout"),
    (ExceptionGroup("g", [httpx.ConnectError("[Errno 111] Connection refused")]), "unreachable"),
    (RuntimeError("Expected response header Content-Type to contain 'text/event-stream'"), "not an MCP endpoint"),
])
def test_each_failure_has_one_plain_reason(exc, reason):
    assert mcp_connection_failure(exc) == f"MCP connection failed: {reason}"


def test_run_recon_raises_a_serialisable_sentence(monkeypatch):
    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def connect_and_get_recon_context(self):
            raise ExceptionGroup("unhandled errors in a TaskGroup", [_status(404)])

    monkeypatch.setattr(mcp_main, "MCPClient", _Client)
    agent = mcp_main.MCPAgent(mcp_context=MCPContext(server_url=URL, server_mode="sse"))
    with pytest.raises(RuntimeError) as info:
        agent.estimate_credits_required()
    assert str(info.value) == "MCP connection failed: the MCP server answered HTTP 404"
    assert isinstance(info.value.__cause__, type(None))  # no ExceptionGroup travels with it
    assert str(pickle.loads(pickle.dumps(info.value))) == str(info.value)  # Celery can carry it


def test_headers_are_never_printed():
    ctx = MCPContext(server_url=URL, server_mode="sse", headers={"Authorization": "Bearer Canary-x1-mcp"})
    assert "Canary-x1-mcp" not in repr(ctx) and "Canary-x1-mcp" not in str(ctx)
