"""Issue #88: assembling a scan's worker kwargs must never print a credential.

``format_input_for_scan`` printed the whole kwargs for every scan type: an LLM scan's ``api_key`` and headers, an
MCP scan's request headers (``Authorization: Bearer ...``), and a repository scan's ``PAT`` (``model_dump()`` ignores
the fields' ``repr=False``). the credit estimate printed the whole payload too (the MCP / LLM headers). Every such line now
goes through one helper (``log_redaction.safe_repr``), and these tests fabricate credentials at run time and assert
none of them reaches the console.

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \\
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \\
      python -m pytest tests/test_secret_logging_88.py -q -p no:cacheprovider
"""
from __future__ import annotations

import asyncio
import io
import json
import re
import secrets
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities import log_redaction as LR  # noqa: E402
from backend.utilities.db.schemas import StartScanPayload  # noqa: E402
from backend.utilities.scan import format_input as FI  # noqa: E402

BACKEND = _REPO_ROOT / "backend"


def _fresh() -> dict[str, str]:
    """Credentials in their real shapes, generated per test run (never a real value)."""
    return {
        "llm_key": "sk-" + secrets.token_urlsafe(24),
        "llm_header": "hdr-" + secrets.token_hex(12),
        "mcp_bearer": secrets.token_urlsafe(20),
        "mcp_cookie": "sess=" + secrets.token_hex(10),
        "mcp_custom": "cust-" + secrets.token_hex(10),
        "pat": "ghp_" + secrets.token_hex(18),
        "dast_password": "Pw!" + secrets.token_hex(6),
    }


@pytest.fixture()
def console(monkeypatch):
    """Everything format_input prints (its rich Console), as plain text."""
    out = io.StringIO()
    from rich.console import Console

    monkeypatch.setattr(FI, "console", Console(file=out, width=400, color_system=None))
    return out


def _format(scan_type: str, payload: dict) -> dict:
    model = StartScanPayload.model_validate({scan_type: payload})
    return asyncio.run(FI.format_input_for_scan(scan_type, model))


def test_llm_and_mcp_kwargs_never_print_the_api_key_or_header_values(console, monkeypatch):
    # #53: the MCP server and model hosts must resolve to public addresses; .test names never resolve (RFC 6761)
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))])
    s = _fresh()
    llm = _format("llm", {"model_type": "custom", "model_name": "m", "api_key": s["llm_key"],
                          "headers": {"X-Api-Key": s["llm_header"]}, "model_uri": "https://llm.example.test/v1"})
    mcp = _format("mcp", {"server_url": "https://mcp.example.test/mcp", "server_mode": "httpstreamable",
                          "headers": {"Authorization": f"Bearer {s['mcp_bearer']}", "Cookie": s["mcp_cookie"],
                                      "X-Custom": s["mcp_custom"]}})
    # the worker still gets the real values
    assert llm["llm_benchmark_dict_context"]["api_key"] == s["llm_key"]
    assert mcp["mcp_dict_context"]["headers"]["X-Custom"] == s["mcp_custom"]
    text = console.getvalue()
    assert "LLM kwargs" in text and "MCP kwargs" in text
    for name in ("llm_key", "llm_header", "mcp_bearer", "mcp_cookie", "mcp_custom"):
        assert s[name] not in text, name
    # still useful for debugging: the header NAMES and the non-secret fields are there
    assert "X-Custom" in text and "Authorization" in text and "https://mcp.example.test/mcp" in text


@pytest.mark.parametrize("scan_type, extra", [
    ("sast", {"app_lang": "python"}),
    ("iac", {"iac_contexts": [{"mode": "terraform"}]}),
    ("sbom_sca", {}),
    ("cbom", {}),
    ("ai_bom", {}),
])
def test_repository_scan_kwargs_never_print_the_pat(console, scan_type, extra):
    s = _fresh()
    out = _format(scan_type, {"repo_context": {"mode": "github", "repo_url": "https://github.com/acme/app",
                                               "PAT": s["pat"], "branch": "main"}, **extra})
    assert out["repo_dict_context"]["PAT"] == s["pat"]
    text = console.getvalue()
    assert "kwargs" in text and "https://github.com/acme/app" in text
    assert s["pat"] not in text


def test_safe_repr_redacts_nested_secrets_urls_and_header_values():
    s = _fresh()
    value = {
        "dast_dict_context": {"target_url": "https://app.example.test/",
                              "auth": {"login_url": "https://app.example.test/login", "username": "qa",
                                       "password": s["dast_password"]}},
        "repo": {"repo_url": f"https://x-access-token:{s['pat']}@github.com/acme/app.git"},
        "model_uri": f"https://llm.example.test/v1?api_key={s['llm_key']}&model=m",
        "headers": [("Authorization", f"Bearer {s['mcp_bearer']}")],
        "Set-Cookie": s["mcp_cookie"], "client_secret": s["mcp_custom"], "jira_api_token": s["llm_header"],
        "count": 3,
    }
    text = LR.safe_repr(value)
    for secret in s.values():
        assert secret not in text, secret
    assert "https://app.example.test/login" in text and "'username': 'qa'" in text and "'count': 3" in text
    assert "model=m" in text and "github.com/acme/app.git" in text
    # the input is not modified
    assert value["dast_dict_context"]["auth"]["password"] == s["dast_password"]
    # pydantic models: model_dump() (which includes repr=False fields) and then the same redaction
    model = StartScanPayload.model_validate({"llm": {"model_type": "openai", "model_name": "gpt",
                                                     "api_key": s["llm_key"], "headers": {"X-K": s["llm_header"]}}})
    text = LR.safe_repr(model)
    assert s["llm_key"] not in text and s["llm_header"] not in text and "gpt" in text


def test_safe_repr_never_raises():
    class Hostile:
        def __repr__(self):
            raise RuntimeError("no")

    assert LR.safe_repr({"x": Hostile()}) == LR.UNREDACTABLE


def test_estimate_never_prints_the_payload_headers(monkeypatch):
    """routers/scans.py estimate_credits printed the whole StartScanPayload (MCP / LLM headers included)."""
    s = _fresh()
    from fastapi import HTTPException
    from fastapi.testclient import TestClient
    from rich.console import Console

    from backend.main import app
    from backend.routers import scans

    out = io.StringIO()
    monkeypatch.setattr(scans, "console", Console(file=out, width=400, color_system=None))
    monkeypatch.setattr(scans, "get_db", lambda: None)

    async def user(*_a, **_k):
        import types
        return types.SimpleNamespace(id=1, email="u@example.test")

    def not_in_team(*_a, **_k):
        raise HTTPException(status_code=403, detail="stop here")

    monkeypatch.setattr(scans, "get_user_from_header_or_raise_exception", user)
    monkeypatch.setattr(scans, "check_if_user_is_in_team", not_in_team)
    from backend.tests.support.rbac import stand_in_principal
    stand_in_principal(monkeypatch, user_id=1, email="u@example.test", role="member")  # F4 route policy
    from backend.utilities import ratelimit
    ratelimit.reset_all()
    payload = {"mcp": {"server_url": "https://mcp.example.test/mcp", "server_mode": "sse",
                       "headers": {"Authorization": f"Bearer {s['mcp_bearer']}", "X-Custom": s["mcp_custom"]}}}
    r = TestClient(app).post("/1/mcp/scan/5/estimate_credits", data={"start_scan_payload_string": json.dumps(payload)},
                             headers={"Authorization": "Bearer t"})
    ratelimit.reset_all()
    assert r.status_code == 403, r.text
    text = out.getvalue()
    assert "Start scan payload" in text
    assert s["mcp_bearer"] not in text and s["mcp_custom"] not in text


def test_no_print_of_raw_kwargs_payloads_or_headers_in_the_backend():
    """The grep guard: a print / log of a kwargs dict, a payload model or request headers goes through safe_repr."""
    pattern = re.compile(r"(console\.print|print|log(?:ger)?\.(?:debug|info|warning|error|exception))\(\s*f?[\"']"
                         r"[^\n]*\{(?!safe_repr\()[^}\n]*\b(scan_kwargs|cicd_kwargs|integration_kwargs|kwargs|"
                         r"start_scan_payload|headers|api_key|PAT|password)\b[^}\n]*\}")
    offenders = []
    for path in BACKEND.rglob("*.py"):
        rel = path.relative_to(BACKEND).as_posix()
        if rel.startswith(("tests/", ".venv/")) or "/site-packages/" in rel:
            continue
        for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{rel}:{n}: {line.strip()}")
    assert offenders == []
