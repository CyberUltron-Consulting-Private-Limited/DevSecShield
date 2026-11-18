"""Follow-up to #374 (#87, #88; review 5909551771): secrets in validation errors and safe_repr's gaps.

* A ``repo_url`` that fails validation made ``StartScanPayload.model_validate_json`` raise a ``ValidationError`` whose
  ``errors()`` carry the whole ``repo_context`` input, PAT included: the start / reinitialize / estimate routes put
  that in the 422 ``detail`` and then printed it. Now ``errors(include_input=False, include_url=False)`` and the
  prints go through ``redact``.
* FastAPI's own 422 for a JSON body echoes each error's ``input`` (for a missing field: the whole object, secrets
  included): the app-wide handler drops ``input`` and ``url``.
* ``safe_repr`` gaps: ``ssh_key`` / ``github_pat`` / ``*_token`` / ``*_secret`` / ``bearer`` names, Basic and Bearer
  credentials inside free text, URL fragments, ``bytes`` values, pydantic's ``input_value=`` text.

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \\
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \\
      python -m pytest tests/test_secret_leaks_followup.py -q -p no:cacheprovider
"""
from __future__ import annotations

import base64
import io
import json
import secrets
import sys
import types
from pathlib import Path

import pytest
from pydantic import BaseModel

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities import log_redaction as LR  # noqa: E402


def _pat() -> str:
    return "ghp_" + secrets.token_hex(18)


@pytest.fixture()
def scans_app(monkeypatch):
    """Real access token against SQLite.
    Validation still fails before a scan row is read."""
    from fastapi.testclient import TestClient
    from rich.console import Console
    from sqlalchemy.pool import StaticPool
    from sqlmodel import Session, SQLModel, create_engine

    from backend.main import app
    from backend.new_models import Team, TeamMembership, User
    from backend.routers import scans
    from backend.utilities import ratelimit
    from backend.utilities.auth.auth_utils import create_access_token

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="t"))
        s.add(User(
            id=1, email="u@example.test", password="x", first_name="u", last_name="t",
            profile_photo=None, default_team_id=1, session_active=True))
        s.add(TeamMembership(team_id=1, user_id=1, role="member"))  # scan.run
        s.commit()

    out = io.StringIO()
    monkeypatch.setattr(scans, "console", Console(file=out, width=400, color_system=None))
    monkeypatch.setattr(scans, "get_db", lambda: engine)
    monkeypatch.setattr(scans, "get_mongo_client_db", lambda: {})

    async def user(*_a, **_k):
        return types.SimpleNamespace(id=1, email="u@example.test")

    monkeypatch.setattr(scans, "get_user_from_header_or_raise_exception", user)
    ratelimit.reset_all()
    token = create_access_token("u@example.test", version=0)
    headers = {"Authorization": f"Bearer {token}"}
    yield TestClient(app), out, headers
    ratelimit.reset_all()


@pytest.mark.parametrize("action", ["start", "reinitialize", "estimate_credits"])
def test_a_refused_repo_url_never_returns_or_prints_the_pat(scans_app, action):
    client, out, headers = scans_app
    pat = _pat()
    payload = {"sast": {"app_lang": "python",
                        "repo_context": {"mode": "github", "repo_url": "https://evil.example/x/y", "PAT": pat}}}
    r = client.post(f"/1/sast/scan/5/{action}", data={"start_scan_payload_string": json.dumps(payload)},
                    headers=headers)
    assert r.status_code == 422, r.text
    assert "repo_url host must be" in r.text  # the reason is still given
    assert pat not in r.text
    assert pat not in out.getvalue()


def test_validation_error_text_is_redacted_wherever_it_is_logged():
    """str(ValidationError) holds ``input_value=``: the text redaction (log filter, prints) removes it."""
    from pydantic import ValidationError

    from backend.utilities.db.schemas import StartScanPayload

    pat = _pat()
    try:
        StartScanPayload.model_validate({"sast": {"app_lang": "python", "repo_context": {
            "mode": "github", "repo_url": "https://evil.example/x/y", "PAT": pat}}})
    except ValidationError as exc:
        tail = pat[-16:]
        assert tail in str(exc)  # what pydantic prints (it shortens long inputs, keeping the end)
        assert tail not in LR.redact(str(exc)) and pat[:12] not in LR.redact(str(exc))
        assert "repo_url host must be" in LR.redact(str(exc))
    else:
        raise AssertionError("expected a ValidationError")


class ProbeBody(BaseModel):
    username: str
    password: str
    count: int


def test_fastapis_422_never_echoes_the_request_body():
    """For a missing field FastAPI's default 422 puts the whole object (a password here) in ``input``."""
    from fastapi import FastAPI
    from fastapi.exceptions import RequestValidationError
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.utilities import validation_errors as VE

    assert app.exception_handlers.get(RequestValidationError) is VE.request_validation_handler

    probe = FastAPI()
    probe.add_exception_handler(RequestValidationError, VE.request_validation_handler)

    @probe.post("/probe")
    def _probe(body: ProbeBody):
        return {}

    secret = "Pw!" + secrets.token_hex(8)
    r = TestClient(probe).post("/probe", json={"username": "ana", "password": secret})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail and detail[0]["loc"] == ["body", "count"] and detail[0]["msg"] == "Field required"
    assert secret not in r.text and all("input" not in e and "url" not in e for e in detail)


def test_safe_repr_gaps_from_the_review():
    s = {k: secrets.token_urlsafe(18) for k in ("ssh", "gh", "refresh", "client", "bearer", "basic", "frag",
                                                  "sess", "jwt", "raw", "priv")}
    basic = base64.b64encode(f"svc:{s['basic']}".encode()).decode()
    value = {
        "ssh_key": s["ssh"], "github_pat": s["gh"], "refresh_token": s["refresh"], "oauth_client_secret": s["client"],
        "bearer": s["bearer"], "private_key_pem": s["priv"],
        "note": f"curl -H 'Authorization: Basic {basic}' -H \"Authorization: Bearer {s['frag']}~x/y+z=\"",
        "callback": f"https://app.example.test/cb#access_token={s['frag']}&state=ok",
        "links": [f"https://app.example.test/?session={s['sess']}&jwt={s['jwt']}&page=2"],
        "blob": s["raw"].encode(),
        "bucket_name": "scans", "object_name": "zips/a.zip", "path": "src/app.py", "monkey": "banana",
    }
    text = LR.safe_repr(value)
    for name, secret in s.items():
        assert secret not in text, name
    assert basic not in text
    # nothing over-redacted: ordinary fields stay readable
    for kept in ("'bucket_name': 'scans'", "zips/a.zip", "src/app.py", "'monkey': 'banana'", "state=ok", "page=2",
                 "https://app.example.test/cb"):
        assert kept in text, kept
