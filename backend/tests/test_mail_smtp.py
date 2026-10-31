"""Sign-in codes through the site's own SMTP relay (on-prem and air-gapped installs): no Microsoft Graph, no internet."""
import asyncio
import os
import socket
import socketserver
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
os.environ.setdefault("JWT_SECRET_KEY", "t")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "r")

from fastapi import HTTPException  # noqa: E402

from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.auth.html_email import create_verification_email_html  # noqa: E402


class _Sink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.messages: list[dict] = []


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        def w(s):
            self.wfile.write((s + "\r\n").encode())
        w("220 sink")
        msg = {"rcpt": []}
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode().strip()
            up = cmd.upper()
            if up.startswith(("EHLO", "HELO")):
                w("250 sink")
            elif up.startswith("MAIL FROM"):
                msg["from"] = cmd[10:]
                w("250 ok")
            elif up.startswith("RCPT TO"):
                msg["rcpt"].append(cmd[8:])
                w("250 ok")
            elif up == "DATA":
                w("354 go")
                buf = []
                while True:
                    data = self.rfile.readline()
                    if not data or data in (b".\r\n", b".\n"):
                        break
                    buf.append(data)
                msg["data"] = b"".join(buf).decode()
                self.server.messages.append(msg)
                msg = {"rcpt": []}
                w("250 queued")
            elif up == "QUIT":
                w("221 bye")
                return
            else:
                w("250 ok")


@pytest.fixture
def sink():
    server = _Sink()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def no_graph(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("Microsoft Graph must not be called when an SMTP relay is configured")
    monkeypatch.setattr(auth_utils.msal, "ConfidentialClientApplication", boom)
    monkeypatch.setattr(auth_utils.requests, "post", boom)


def _env(monkeypatch, **values):
    for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_USERNAME", "SMTP_PASSWORD", "MAIL_FROM", "SMTP_CA_FILE",
                "SMTP_TIMEOUT_S"):
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, str(value))


def test_relay_is_off_by_default(monkeypatch):
    _env(monkeypatch)
    assert auth_utils.smtp_settings() is None


def test_code_goes_through_the_relay_and_never_to_graph(monkeypatch, sink, no_graph):
    _env(monkeypatch, SMTP_HOST="127.0.0.1", SMTP_PORT=sink.server_address[1], SMTP_SECURITY="none", MAIL_FROM="cbom@bank.local")
    asyncio.run(auth_utils.send_outlook_email("analyst@bank.local", "Verification code",
                                              html_body=create_verification_email_html("482913")))
    assert len(sink.messages) == 1
    m = sink.messages[0]
    assert m["rcpt"] == ["<analyst@bank.local>"] and m["from"].startswith("<cbom@bank.local>")
    assert "Subject: Verification code" in m["data"] and "To: analyst@bank.local" in m["data"]
    assert "482913" in m["data"]


def test_plaintext_relay_with_a_password_is_refused(monkeypatch, no_graph):
    _env(monkeypatch, SMTP_HOST="127.0.0.1", SMTP_PORT=2525, SMTP_SECURITY="none", SMTP_USERNAME="u", SMTP_PASSWORD="p")
    with pytest.raises(HTTPException) as e:
        asyncio.run(auth_utils.send_outlook_email("a@bank.local", "Verification code", body="x"))
    assert e.value.detail == "The mail relay is not configured correctly"


def test_unknown_security_mode_is_refused(monkeypatch, no_graph):
    _env(monkeypatch, SMTP_HOST="127.0.0.1", SMTP_SECURITY="tls1.0")
    with pytest.raises(HTTPException):
        asyncio.run(auth_utils.send_outlook_email("a@bank.local", "Verification code", body="x"))


def test_header_injection_is_refused(monkeypatch, sink, no_graph):
    _env(monkeypatch, SMTP_HOST="127.0.0.1", SMTP_PORT=sink.server_address[1], SMTP_SECURITY="none")
    with pytest.raises(HTTPException) as e:
        asyncio.run(auth_utils.send_outlook_email("a@bank.local\r\nBcc: attacker@evil.test", "Verification code", body="x"))
    assert e.value.status_code == 400 and sink.messages == []


def test_internationalised_domain_is_sent_as_punycode(monkeypatch, sink, no_graph):
    _env(monkeypatch, SMTP_HOST="127.0.0.1", SMTP_PORT=sink.server_address[1], SMTP_SECURITY="none")
    asyncio.run(auth_utils.send_outlook_email("analyst@bücher.example", "Verification code", body="x"))
    assert sink.messages[0]["rcpt"] == ["<analyst@xn--bcher-kva.example>"]


@pytest.mark.parametrize("port,timeout", [("abc", "20"), ("0", "20"), ("70000", "20"), ("25", "0"), ("25", "nan")])
def test_bad_relay_settings_give_a_generic_error(monkeypatch, no_graph, port, timeout):
    _env(monkeypatch, SMTP_HOST="127.0.0.1", SMTP_PORT=port, SMTP_SECURITY="none", SMTP_TIMEOUT_S=timeout)
    with pytest.raises(HTTPException) as e:
        asyncio.run(auth_utils.send_outlook_email("a@bank.local", "Verification code", body="x"))
    assert e.value.detail == "The mail relay is not configured correctly"


def test_relay_down_gives_a_readable_error(monkeypatch, no_graph):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens there now
    _env(monkeypatch, SMTP_HOST="127.0.0.1", SMTP_PORT=port, SMTP_SECURITY="none")
    with pytest.raises(HTTPException) as e:
        asyncio.run(auth_utils.send_outlook_email("a@bank.local", "Verification code", body="x"))
    assert e.value.status_code == 500 and "mail relay" in e.value.detail


def test_starttls_is_required_by_default(monkeypatch, sink, no_graph):
    """The sink does not offer STARTTLS, so the default (starttls) must fail rather than fall back to clear text."""
    _env(monkeypatch, SMTP_HOST="127.0.0.1", SMTP_PORT=sink.server_address[1])
    with pytest.raises(HTTPException):
        asyncio.run(auth_utils.send_outlook_email("a@bank.local", "Verification code", body="x"))
    assert sink.messages == []
