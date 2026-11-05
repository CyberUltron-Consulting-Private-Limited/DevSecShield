"""Regression: both public guardrails routes held the Celery task state in a local variable named `status`, which
shadowed `fastapi.status` for the whole function body, so every `status.HTTP_...` reference raised
UnboundLocalError/AttributeError and a missing API key came back as a generic 500 instead of 401 (found by
`make lint`, ruff F823)."""
import os
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "guardrails-test-secret-0123456789abcdef")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "guardrails-test-refresh-0123456789abcdef")

from backend.routers import guardrails_public as gp  # noqa: E402


def _client(monkeypatch):
    monkeypatch.setattr(gp, "get_db", lambda: None)
    monkeypatch.setattr(gp, "get_mongo_client_db", lambda: None)
    app = FastAPI()
    app.include_router(gp.router)
    app.dependency_overrides[gp.get_user_and_integration_id] = lambda: {"user_id": None, "integration_id": None}
    gp.limiter.requests.clear() if hasattr(gp.limiter, "requests") else None
    return TestClient(app, raise_server_exceptions=False)


def test_get_scan_status_without_a_key_is_401_not_a_crash(monkeypatch):
    r = _client(monkeypatch).get("/public/guardrails/0123456789abcdef01234567")
    assert r.status_code == 401, r.text


def test_the_routes_no_longer_shadow_fastapi_status():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(gp))
    assigned = {n.id for f in ast.walk(tree) if isinstance(f, ast.AsyncFunctionDef)
                for n in ast.walk(f) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    assert "status" not in assigned
