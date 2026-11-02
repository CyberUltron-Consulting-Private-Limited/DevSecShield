"""Live end-to-end tests against a running backend skip cleanly unless that backend can really be exercised.

The JWT secret comes from the environment only (export JWT_SECRET_KEY, the running backend's access-token secret);
a test never reads backend/.env. A live test SKIPS (never fails) when:
  * the backend at its base URL does not answer GET /health with 200;
  * JWT_SECRET_KEY is not exported;
  * the backend rejects a token signed with that secret (it runs with another secret, or the user is not seeded);
  * a database the test opens directly is unreachable.
Everything after those checks is a real assertion.
"""
from __future__ import annotations

import datetime
import os
import urllib.error
import urllib.request

import pytest


def jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET_KEY", "")
    if not secret:
        pytest.skip("live test: export JWT_SECRET_KEY (the running backend's access-token secret) to run it")
    return secret


def mint_token(sub: str, hours: int = 2) -> str:
    import jwt

    now = datetime.datetime.now(datetime.timezone.utc)
    claims = {"sub": sub, "iat": now, "exp": now + datetime.timedelta(hours=hours), "typ": "access"}
    return jwt.encode(claims, jwt_secret(), algorithm="HS256")


def _status(base: str, path: str, token: str | None = None, timeout: float = 10) -> int | None:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers), timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def require_live_backend(base: str, sub: str, team: int) -> str:
    """Skip unless ``base`` is up and accepts a token for ``sub``; return such a token."""
    health = _status(base, "/health")
    if health != 200:
        pytest.skip(f"live test: no backend on {base} (GET /health -> {health})")
    token = mint_token(sub)
    if _status(base, f"/{team}/cbom/scans", token) == 401:
        pytest.skip(f"live test: {base} rejects a token signed with the exported JWT_SECRET_KEY "
                    f"(it runs with another secret, or {sub} is not seeded)")
    return token


def require_database() -> None:
    """Skip unless the database ``backend.get_db`` points at answers a query."""
    from sqlalchemy import text

    from backend.get_db import get_db

    try:
        with get_db().connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # OperationalError, a missing PG_* variable, ...
        pytest.skip(f"live test: database not reachable ({type(exc).__name__})")
