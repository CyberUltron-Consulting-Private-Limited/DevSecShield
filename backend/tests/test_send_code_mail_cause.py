"""/send_code when the mail cannot be sent: a clear 503 for the user, the real cause in the server log.

Follow-up 3: the staging backend logged ``Error sending email: 'TENANT_ID'`` and answered 200. The answer is now a
503 ("We could not send the verification code right now ...") without configuration in it; this test also proves
the operator still learns WHY from the log (the missing setting's name, the relay's reply), with no secret and no
recipient address in that line.
"""
from __future__ import annotations

import logging
import pathlib
import smtplib
import sys

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.main import app  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402

ADDRESS = "mail.down@example.test"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'auth.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(auth_router, "get_db", lambda: engine)
    monkeypatch.delenv("DSS_DEV_MODE", raising=False)
    for name in ("SMTP_HOST", "TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)
    return TestClient(app)


def test_a_missing_graph_setting_is_a_503_and_the_log_names_the_setting(client, caplog):
    caplog.set_level(logging.ERROR)
    r = client.post("/send_code", json={"email": ADDRESS})  # the real mailer: no relay, no TENANT_ID
    assert r.status_code == 503
    assert r.json()["detail"] == ("We could not send the verification code right now. Please try again in a few "
                                  "minutes.")
    assert "TENANT_ID" not in r.text and "KeyError" not in r.text and "Graph" not in r.text
    lines = [rec.getMessage() for rec in caplog.records]
    assert any("Microsoft Graph: missing setting TENANT_ID" in line for line in lines), lines
    assert not any(ADDRESS in line for line in lines)


def test_the_relay_reply_is_logged_without_the_password_or_the_recipient(monkeypatch):
    monkeypatch.setenv("SMTP_PASSWORD", "relay-pass-9f3e")
    refused = smtplib.SMTPRecipientsRefused({ADDRESS: (550, b"5.1.1 mailbox unavailable")})
    cause = auth_utils.mail_failure_cause(refused, ADDRESS)
    assert cause.startswith("SMTPRecipientsRefused: ") and "550" in cause and "mailbox unavailable" in cause
    assert ADDRESS not in cause and "<recipient>" in cause
    login = smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials for relay-pass-9f3e")
    cause = auth_utils.mail_failure_cause(login, ADDRESS)
    assert "535" in cause and "relay-pass-9f3e" not in cause and "***" in cause
    assert auth_utils.mail_failure_cause(ConnectionRefusedError(111, "Connection refused")) == \
        "ConnectionRefusedError: [Errno 111] Connection refused"
    assert auth_utils.mail_failure_cause(KeyError("CLIENT_ID")) == "missing setting CLIENT_ID"
    assert len(auth_utils.mail_failure_cause(RuntimeError("x" * 900))) <= len("RuntimeError: ") + 200
