"""Unit and API tests for DAST OTP form and Session Import authentication."""
from __future__ import annotations

import asyncio
import json
import os
import sys
import types

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("JWT_SECRET_KEY", "dast-otp-test-secret-not-for-prod")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "dast-otp-test-refresh-not-for-prod")

from backend.main import app  # noqa: E402
from backend.new_models import Team, TeamMembership, User  # noqa: E402
from backend.utilities.celery.task_reprs import redact_task_reprs  # noqa: E402
from backend.utilities.dashboard.scan_metadata import get_scan_metadata  # noqa: E402
from backend.utilities.dast import ssrf  # noqa: E402
from backend.utilities.dast.auth_crypto import (  # noqa: E402
    decrypt_auth,
    encrypt_auth,
    redact_auth,
)
from backend.utilities.db.metadata import get_scan_metadata_for_type  # noqa: E402
from backend.utilities.db.schemas import (  # noqa: E402
    AuthRequirements,
    StartDASTScanData,
    StartScanPayload,
)
from backend.utilities.log_redaction import safe_repr  # noqa: E402
from backend.utilities.scan.format_input import format_input_for_scan  # noqa: E402

CANARY_COOKIE = "sid=canary-cookie-val-991"
CANARY_BEARER = "Bearer canary-jwt-token-882"
CANARY_LS = json.dumps({"access_token": "canary-ls-tok-773"})
CANARY_SS = json.dumps({"session_key": "canary-ss-tok-664"})
CANARY_OTP = "918273"
CANARY_TOTP = "JBSWY3DPEHPK3PXP"
CANARY_MPIN = "456789"


def _session_auth(**overrides):
    base = {
        "auth_type": "session",
        "session_cookie": CANARY_COOKIE,
        "auth_header_name": "Authorization",
        "auth_header_value": CANARY_BEARER,
        "local_storage_json": CANARY_LS,
        "session_storage_json": CANARY_SS,
        "session_check_url": "https://portal.example/dashboard",
        "logged_in_indicator": "My Loans",
    }
    base.update(overrides)
    return base


def _otp_auth(**overrides):
    base = {
        "auth_type": "otp_form",
        "login_url": "https://portal.example/login",
        "username": "7011554991",
        "xpath_of_username_field": "//input[@name='mobile']",
        "xpath_of_send_otp_button": "//button[@id='send-otp']",
        "xpath_of_otp_field": "//input[@name='otp']",
        "xpath_of_submit_button": "//button[@id='verify']",
        "otp_source": "static",
        "otp_code": CANARY_OTP,
        "mpin": CANARY_MPIN,
        "xpath_of_mpin_field": "//input[@name='mpin']",
        "xpath_of_mpin_submit_button": "//button[@id='mpin-go']",
        "session_check_url": "https://portal.example/dashboard",
        "logged_in_indicator": "Dashboard",
    }
    base.update(overrides)
    return base


def test_session_and_otp_auth_validation_happy_paths() -> None:
    s = AuthRequirements.model_validate(_session_auth())
    assert s.auth_type == "session"
    assert CANARY_COOKIE not in repr(s)
    assert CANARY_BEARER not in repr(s)
    assert "canary-ls-tok-773" not in repr(s)

    o = AuthRequirements.model_validate(_otp_auth())
    assert o.auth_type == "otp_form"
    assert CANARY_OTP not in repr(o)
    assert CANARY_MPIN not in repr(o)

    t = AuthRequirements.model_validate(_otp_auth(otp_source="totp", otp_code=None, totp_secret=CANARY_TOTP))
    assert t.otp_source == "totp"
    assert CANARY_TOTP not in repr(t)


@pytest.mark.parametrize(
    "bad, match",
    [
        ({"auth_type": "session"}, "at least one"),
        (_session_auth(session_cookie="a=1\r\nX-Injected: 2"), "newline"),
        (_session_auth(auth_header_value="Bearer x\nEvil: 1"), "newline"),
        (_session_auth(auth_header_name="Host"), "Invalid auth_header_name"),
        (_session_auth(auth_header_name="Bad Header"), "Invalid auth_header_name"),
        (_session_auth(local_storage_json="not-json"), "valid JSON"),
        (_session_auth(local_storage_json='["list"]'), "JSON object"),
        (_otp_auth(otp_code=""), "otp_code is required"),
        (_otp_auth(otp_source="totp", otp_code=None, totp_secret="not!!base32"), "Base32"),
        (_otp_auth(xpath_of_mpin_field=None), "xpath_of_mpin_field"),
        (_otp_auth(xpath_of_otp_field=None), "xpath_of_otp_field"),
    ],
)
def test_invalid_session_and_otp_auth_rejected(bad: dict, match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        AuthRequirements.model_validate(bad)


def test_encrypt_decrypt_redact_for_session_and_otp() -> None:
    for plain, canaries in (
        (_session_auth(), (CANARY_COOKIE, CANARY_BEARER, "canary-ls-tok-773", "canary-ss-tok-664")),
        (_otp_auth(), (CANARY_OTP, CANARY_MPIN)),
        (_otp_auth(otp_source="totp", otp_code=None, totp_secret=CANARY_TOTP), (CANARY_TOTP, CANARY_MPIN)),
    ):
        stored = encrypt_auth(plain)
        blob = json.dumps(stored)
        for secret in canaries:
            assert secret not in blob
        restored = decrypt_auth(stored)
        for k, v in plain.items():
            assert restored.get(k) == v
        redacted = redact_auth(stored)
        redacted_blob = json.dumps(redacted)
        for secret in canaries:
            assert secret not in redacted_blob


def test_metadata_and_celery_task_reprs_never_leak_otp_or_session_secrets() -> None:
    for auth_dict, canaries in (
        (_session_auth(), (CANARY_COOKIE, CANARY_BEARER, "canary-ls-tok-773", "canary-ss-tok-664")),
        (_otp_auth(), (CANARY_OTP, CANARY_MPIN)),
        (_otp_auth(otp_source="totp", otp_code=None, totp_secret=CANARY_TOTP), (CANARY_TOTP, CANARY_MPIN)),
    ):
        payload = StartScanPayload(
            dast=StartDASTScanData(target_url="https://portal.example", auth=AuthRequirements.model_validate(auth_dict))
        )
        stored = get_scan_metadata_for_type("dast", payload)
        served = get_scan_metadata("dast", types.SimpleNamespace(scan_metadata=stored, scan_data={}))
        assert served["auth"]["auth_type"] == auth_dict["auth_type"]
        for blob in (json.dumps(stored), json.dumps(served), safe_repr(payload.dast.model_dump())):
            for secret in canaries:
                assert secret not in blob

        headers = {"argsrepr": "()", "kwargsrepr": "raw"}
        redact_task_reprs(headers=headers, body=((), {"dast_dict_context": payload.dast.model_dump()}, {}))
        for secret in canaries:
            assert secret not in headers["kwargsrepr"]


def test_session_check_url_is_ssrf_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DAST_ALLOWED_PRIVATE", raising=False)
    monkeypatch.setattr(ssrf, "_resolve_ips", lambda host: ["93.184.216.34"] if host == "portal.example" else ["10.0.0.5"])

    ok_payload = StartScanPayload(
        dast=StartDASTScanData(target_url="https://portal.example", auth=AuthRequirements.model_validate(_session_auth()))
    )
    out = asyncio.run(format_input_for_scan("dast", ok_payload))
    assert out["dast_dict_context"]["auth"]["auth_type"] == "session"

    bad_payload = StartScanPayload(
        dast=StartDASTScanData(
            target_url="https://portal.example",
            auth=AuthRequirements.model_validate(_session_auth(session_check_url="http://169.254.169.254/latest/meta-data/")),
        )
    )
    with pytest.raises(HTTPException) as err:
        asyncio.run(format_input_for_scan("dast", bad_payload))
    assert err.value.status_code == 400

    off_host = StartScanPayload(
        dast=StartDASTScanData(
            target_url="https://portal.example",
            auth=AuthRequirements.model_validate(_session_auth(session_check_url="https://evil.example/check")),
        )
    )
    with pytest.raises(HTTPException) as err2:
        asyncio.run(format_input_for_scan("dast", off_host))
    assert err2.value.status_code == 400 and "not in allowlist" in err2.value.detail


def test_dast_profiles_crud_with_otp_and_session(monkeypatch: pytest.MonkeyPatch) -> None:
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    monkeypatch.setattr("backend.get_db.get_db", lambda: eng)
    monkeypatch.setattr("backend.routers.dast_profiles.get_db", lambda: eng)
    monkeypatch.setattr("backend.routers.dast_profiles.check_if_user_is_in_team", lambda *_a, **_k: None)
    monkeypatch.setattr("backend.utilities.dast.ssrf._resolve_ips", lambda _host: ["93.184.216.34"])

    with Session(eng) as session:
        team = Team(name="otp-team", credit_balance=20.0)
        session.add(team)
        session.commit()
        session.refresh(team)
        user = User(email="otp@example.com", password="x", first_name="o", last_name="t", default_team_id=team.id, session_active=True)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(TeamMembership(team_id=team.id, user_id=user.id, role="admin"))
        session.commit()
        tid = team.id

    from backend.utilities.auth.auth_utils import create_access_token

    headers = {"Authorization": f"Bearer {create_access_token('otp@example.com', version=0)}"}
    client = TestClient(app)

    # Create OTP profile
    r = client.post(
        f"/{tid}/dast/profiles",
        headers=headers,
        json={
            "title": "Chola UAT OTP",
            "target_url": "https://portal.example",
            "auth": _otp_auth(),
            "scan_speed": "fast",
            "max_urls": 5,
            "consent_ok": True,
        },
    )
    assert r.status_code == 200, r.text
    prof = r.json()
    assert prof["auth"]["auth_type"] == "otp_form"
    assert prof["auth"]["username"] == "7011554991"
    assert CANARY_OTP not in r.text and CANARY_MPIN not in r.text

    # Update profile leaving secrets blank preserves stored encrypted OTP + MPIN
    pid = prof["id"]
    r2 = client.put(
        f"/{tid}/dast/profiles/{pid}",
        headers=headers,
        json={"auth": _otp_auth(otp_code="", mpin=""), "title": "Chola UAT OTP v2"},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["title"] == "Chola UAT OTP v2"

    # Switching to session mode with no secrets must fail 400
    r3 = client.put(
        f"/{tid}/dast/profiles/{pid}",
        headers=headers,
        json={"auth": {"auth_type": "session"}},
    )
    assert r3.status_code == 400

    # Switching to session mode with cookie succeeds and redacts cookie
    r4 = client.put(
        f"/{tid}/dast/profiles/{pid}",
        headers=headers,
        json={"auth": _session_auth()},
    )
    assert r4.status_code == 200, r4.text
    assert r4.json()["auth"]["auth_type"] == "session"
    assert CANARY_COOKIE not in r4.text and CANARY_BEARER not in r4.text
