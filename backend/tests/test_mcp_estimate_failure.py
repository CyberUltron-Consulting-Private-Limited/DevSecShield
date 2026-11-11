"""X1 (Nov 11): "Estimate credits" on an MCP scan whose server URL answers 404 gave a 500 "Credit estimation failed,
please try again later" although the worker saw 404 Not Found. An MCP connection failure is the customer's input, not
an outage: the API answers 400 and says why (HTTP status from the MCP server, timeout, unreachable, not an MCP
endpoint), from the worker's "MCP connection failed: <reason>" (RabbitMQ/worker tests/test_mcp_connection_failure.py)
or an older worker's ExceptionGroup text, exactly as the stack's scan-worker logged it.  Other failures stay 500.

Browser check after a rebuild: MCP scan > server URL https://example.com/sse > Estimate: the reason is shown under the
button, the form keeps its values."""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from backend.utilities.scan.estimate_scan import _estimation_failure, poll_for_estimated_credits

# what the running scan-worker (288fba9) raised for X1's four attempts (docker logs dss-staging-scan-worker-1)
LEGACY_404 = ("ExceptionGroup('unhandled errors in a TaskGroup', [HTTPStatusError(\"Client error '404 Not Found' for "
              "url 'https://example.com/sse'\\nFor more information check: "
              "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/404\")])")
LEGACY_TIMEOUT = "ExceptionGroup('unhandled errors in a TaskGroup', [ConnectTimeout('')])"


class _Result:
    def __init__(self, result, state="FAILURE"):
        self.result, self.state = result, state


class _App:
    def __init__(self, result):
        self._result = result

    def AsyncResult(self, _task_id):  # noqa: N802 - Celery's name
        return self._result


def _poll(err) -> HTTPException:
    with pytest.raises(HTTPException) as info:
        asyncio.run(poll_for_estimated_credits("t", _App(_Result(err)), scan_type="mcp"))
    return info.value


@pytest.mark.parametrize("err, says", [
    (RuntimeError("MCP connection failed: the MCP server answered HTTP 404"), "answered HTTP 404"),
    (Exception(LEGACY_404), "answered HTTP 404"),
    (RuntimeError("MCP connection failed: timeout"), "timeout"),
    (Exception(LEGACY_TIMEOUT), "timeout"),
    (RuntimeError("MCP connection failed: unreachable"), "could not be reached"),
    (RuntimeError("MCP connection failed: not an MCP endpoint"), "not as an MCP server"),
])
def test_an_mcp_connection_failure_is_a_400_that_says_why(err, says):
    exc = _poll(err)
    assert exc.status_code == 400  # before: 500 "Credit estimation failed, please try again later"
    assert says in exc.detail
    assert "developer.mozilla" not in exc.detail and "example.com" not in exc.detail  # fixed sentences only


def test_other_mcp_failures_stay_500():
    assert _poll(RuntimeError("broker connection lost")).status_code == 500


def test_other_scan_types_are_unchanged():
    assert _estimation_failure(_Result(Exception(LEGACY_404))).status_code == 500
