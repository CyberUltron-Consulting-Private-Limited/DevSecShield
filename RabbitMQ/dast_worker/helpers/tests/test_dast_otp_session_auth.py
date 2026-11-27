"""Tests for DAST Session Import and 2-Step Mobile/OTP Form authentication."""
from __future__ import annotations

import http.server
import json
import socketserver
import threading
import urllib.parse

import pytest
import yaml

from helpers.agent.context import AuthRequirements, StartDASTScanData
from helpers.agent.main import DASTAgent
from helpers.agent.session_auth import (
    COOKIE_PLACEHOLDER,
    CapturedSession,
    DastAuthError,
    build_session_nuclei_template,
    establish_session,
    generate_totp,
    login_with_otp_form,
    materialize_session_template,
    session_from_import,
)
from helpers.agent.utils import get_auth_login_template
from helpers.checks.nuclei.yaml_validate import validate_nuclei_yaml
from helpers.checks.security_headers import fetch_http_headers
from helpers.crawler.crawler import Crawler
from helpers.net.egress import EgressProxy, ScanEgress


def _make_otp_server():
    """Local HTTP server implementing cookie+Bearer session auth AND a 2-step Mobile -> OTP -> MPIN login."""
    valid_cookie = "sid=valid-session-991"
    valid_bearer = "Bearer valid-jwt-882"
    state = {"otp_sent": 0, "headers_seen": []}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _is_authed(self) -> bool:
            cookie = self.headers.get("Cookie", "")
            auth = self.headers.get("Authorization", "")
            return valid_cookie in cookie or auth == valid_bearer

        def do_GET(self):
            state["headers_seen"].append((self.path, dict(self.headers.items())))
            path = urllib.parse.urlparse(self.path).path
            if path == "/login":
                html = b"""<!doctype html><html><body>
                <h1>Portal Login</h1>
                <div id="step1">
                  <input id="mobile" name="mobile" type="text" />
                  <button id="send-otp" type="button" onclick="
                    fetch('/api/send-otp', {method:'POST'}).then(() => {
                      document.getElementById('step2').style.display='block';
                    });
                  ">Send OTP</button>
                </div>
                <div id="step2" style="display:none">
                  <div id="otp-boxes">
                    <input class="otp" maxlength="1" /><input class="otp" maxlength="1" />
                    <input class="otp" maxlength="1" /><input class="otp" maxlength="1" />
                    <input class="otp" maxlength="1" /><input class="otp" maxlength="1" />
                  </div>
                  <button id="verify-otp" type="button" onclick="
                    const code = Array.from(document.querySelectorAll('.otp')).map(i => i.value).join('');
                    fetch('/api/verify-otp', {method:'POST', body: JSON.stringify({otp: code})})
                      .then(r => r.json()).then(d => {
                        if (d.ok) document.getElementById('step3').style.display='block';
                      });
                  ">Verify OTP</button>
                </div>
                <div id="step3" style="display:none">
                  <input id="mpin" name="mpin" type="password" />
                  <button id="verify-mpin" type="button" onclick="
                    const pin = document.getElementById('mpin').value;
                    fetch('/api/verify-mpin', {method:'POST', body: JSON.stringify({mpin: pin})})
                      .then(r => r.json()).then(d => {
                        if (d.ok) {
                          localStorage.setItem('portal_token', d.token);
                          window.location.href = '/dashboard';
                        }
                      });
                  ">Confirm MPIN</button>
                </div>
                </body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(html)
                return

            if path == "/redirect-login":
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return

            if path in ("/", "/dashboard"):
                if not self._is_authed():
                    self.send_response(401)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body>Unauthorized</body></html>")
                    return
                body = b"""<html><body>
                  <h1>Welcome Authenticated User</h1>
                  <a href="/loans">My Loans</a>
                  <a href="/profile">My Profile</a>
                </body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(body)
                return

            if path in ("/loans", "/profile"):
                if not self._is_authed():
                    self.send_response(403)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"<html><body>Protected {path}</body></html>".encode())
                return

            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw.decode("utf-8") or "{}")
            if self.path == "/api/send-otp":
                state["otp_sent"] += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"sent":true}')
                return
            if self.path == "/api/verify-otp":
                ok = data.get("otp") == "123456"
                self.send_response(200 if ok else 401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": ok}).encode())
                return
            if self.path == "/api/verify-mpin":
                ok = data.get("mpin") == "4321"
                self.send_response(200 if ok else 401)
                self.send_header("Content-Type", "application/json")
                if ok:
                    self.send_header("Set-Cookie", f"{valid_cookie}; Path=/")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": ok, "token": "jwt-from-mpin"}).encode())
                return
            self.send_response(404)
            self.end_headers()

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    srv = Server(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, port, state, valid_cookie, valid_bearer


def test_generate_totp_matches_rfc6238_vector() -> None:
    # RFC 6238 Appendix B SHA1 secret "12345678901234567890" -> Base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    secret = "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ"
    assert generate_totp(secret, timestamp=59, digits=8) == "94287082"
    assert generate_totp(secret, timestamp=59, digits=6) == "287082"
    with pytest.raises(DastAuthError, match="Base32"):
        generate_totp("!!!not-base32!!!")


def test_session_import_verifies_crawls_and_fails_fast_when_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DAST_ALLOWED_PRIVATE", "127.0.0.1")
    srv, port, _state, valid_cookie, valid_bearer = _make_otp_server()
    try:
        base = f"http://127.0.0.1:{port}"
        egress = ScanEgress([f"{base}/dashboard", f"{base}/redirect-login"])

        # Valid cookie + indicator passes verification and crawls authenticated pages
        good_auth = AuthRequirements(
            auth_type="session",
            session_cookie=valid_cookie,
            session_check_url=f"{base}/dashboard",
            logged_in_indicator="Welcome Authenticated User",
        )
        sess = establish_session(f"{base}/dashboard", good_auth, egress=egress)
        assert sess is not None and sess.verified is True

        crawler = Crawler(url=f"{base}/dashboard", max_urls=10, egress=egress, extra_headers=sess.http_headers())
        urls = crawler.crawl()
        assert f"{base}/loans" in urls and f"{base}/profile" in urls

        hdrs = fetch_http_headers(f"{base}/dashboard", timeout=5, egress=egress, extra_headers=sess.http_headers())
        assert hdrs.get("X-Frame-Options") == "DENY"

        # Valid Bearer header alone also passes
        bearer_auth = AuthRequirements(
            auth_type="session",
            auth_header_name="Authorization",
            auth_header_value=valid_bearer,
            session_check_url=f"{base}/dashboard",
        )
        sess2 = establish_session(f"{base}/dashboard", bearer_auth, egress=egress)
        assert sess2 is not None and sess2.verified is True

        # Expired/wrong cookie fails fast with 401 DastAuthError
        bad_auth = AuthRequirements(
            auth_type="session",
            session_cookie="sid=expired-000",
            session_check_url=f"{base}/dashboard",
        )
        with pytest.raises(DastAuthError, match="401"):
            establish_session(f"{base}/dashboard", bad_auth, egress=egress)

        # Redirect to /login fails fast
        redir_auth = AuthRequirements(
            auth_type="session",
            session_cookie=valid_cookie,
            login_url=f"{base}/login",
            session_check_url=f"{base}/redirect-login",
        )
        with pytest.raises(DastAuthError, match="redirected to login"):
            establish_session(f"{base}/dashboard", redir_auth, egress=egress)

        # Wrong logged_in_indicator fails fast
        miss_auth = AuthRequirements(
            auth_type="session",
            session_cookie=valid_cookie,
            session_check_url=f"{base}/dashboard",
            logged_in_indicator="Not On This Page",
        )
        with pytest.raises(DastAuthError, match="Not On This Page"):
            establish_session(f"{base}/dashboard", miss_auth, egress=egress)
    finally:
        srv.shutdown()
        srv.server_close()


def test_nuclei_session_template_never_exposes_secrets_to_llm_and_materializes_safely() -> None:
    sess = CapturedSession(
        origin="https://portal.example",
        cookie_header="sid=super-secret-cookie",
        extra_headers={"Authorization": "Bearer super-secret-jwt"},
        local_storage={"token": "super-secret-ls"},
    )
    auth = AuthRequirements(auth_type="session", session_cookie="sid=super-secret-cookie")

    # Placeholder template sent to LLM must NEVER contain real secrets
    llm_tpl = get_auth_login_template("https://portal.example/loans", auth, session=sess)
    assert "super-secret-cookie" not in llm_tpl
    assert "super-secret-jwt" not in llm_tpl
    assert "super-secret-ls" not in llm_tpl
    assert COOKIE_PLACEHOLDER in llm_tpl

    # Materializing replaces placeholders cleanly and yields valid Nuclei YAML
    full_yaml = materialize_session_template(llm_tpl.replace("\n<ADD_YOUR_EXPLOIT_ACTIONS_HERE>", ""), sess)
    ok, reason = validate_nuclei_yaml(full_yaml)
    assert ok, reason
    assert "super-secret-cookie" in full_yaml
    assert "super-secret-jwt" in full_yaml
    assert "super-secret-ls" in full_yaml

    # Even if an LLM drops the session steps completely, materialize_session_template re-injects them
    stripped = yaml.safe_dump(
        {
            "id": "xss_probe",
            "info": {"name": "xss_probe", "author": "pdteam", "severity": "high"},
            "headless": [{"steps": [{"action": "navigate", "args": {"url": "https://portal.example/loans"}}]}],
        },
        sort_keys=False,
    )
    reinjected = materialize_session_template(stripped, sess)
    ok2, reason2 = validate_nuclei_yaml(reinjected)
    assert ok2, reason2
    parsed = yaml.safe_load(reinjected)
    actions = [s["action"] for s in parsed["headless"][0]["steps"]]
    assert actions[:2] == ["setheader", "setheader"]
    assert "script" in actions

    # Direct fetch template (extract_html=True) also validates
    fetch_tpl = build_session_nuclei_template(sess, "https://portal.example/loans", extract_html=True)
    ok3, reason3 = validate_nuclei_yaml(fetch_tpl)
    assert ok3, reason3


def test_dast_agent_accepts_session_and_otp_auth_and_fails_fast_on_bad_session(monkeypatch: pytest.MonkeyPatch) -> None:
    from helpers.agent import main as agent_main

    monkeypatch.setenv("DAST_ALLOWED_PRIVATE", "127.0.0.1")
    monkeypatch.setattr(agent_main, "ScanEgress", ScanEgress)
    srv, port, _state, _valid_cookie, _valid_bearer = _make_otp_server()
    try:
        ctx = StartDASTScanData(
            target_url=f"http://127.0.0.1:{port}/dashboard",
            auth=AuthRequirements(
                auth_type="session",
                session_cookie="sid=expired-token",
                session_check_url=f"http://127.0.0.1:{port}/dashboard",
            ),
            scan_speed="fast",
            max_urls=5,
        )
        agent = DASTAgent(dast_context=ctx)
        assert f"http://127.0.0.1:{port}/dashboard" in agent.scan_urls()
        with pytest.raises(DastAuthError, match="401"):
            agent.run()
    finally:
        srv.shutdown()
        srv.server_close()


def test_otp_form_end_to_end_with_split_boxes_and_mpin_in_playwright(monkeypatch: pytest.MonkeyPatch) -> None:
    """Real Playwright Chromium 2-step Mobile -> Split 6-box OTP -> MPIN login through EgressProxy."""
    playwright = pytest.importorskip("playwright.sync_api")
    monkeypatch.setenv("DAST_ALLOWED_PRIVATE", "127.0.0.1")
    srv, port, state, valid_cookie, _valid_bearer = _make_otp_server()
    base = f"http://127.0.0.1:{port}"
    egress = ScanEgress([f"{base}/login", f"{base}/dashboard"])
    proxy = EgressProxy(egress)
    try:
        # Skip cleanly only if Chromium browser binary is not installed in this unit-test environment
        import os

        launch_kw = {"headless": True}
        override = (os.environ.get("DAST_CHROMIUM_PATH") or "").strip()
        if override and os.path.isfile(override):
            launch_kw["executable_path"] = override
        try:
            with playwright.sync_playwright() as p:
                b = p.chromium.launch(**launch_kw)
                b.close()
        except Exception as exc:
            pytest.skip(f"Playwright Chromium browser binary unavailable in this environment: {exc}")

        auth = AuthRequirements(
            auth_type="otp_form",
            login_url=f"{base}/login",
            username="7011554991",
            xpath_of_username_field="//input[@id='mobile']",
            xpath_of_send_otp_button="//button[@id='send-otp']",
            xpath_of_otp_field="//div[@id='otp-boxes']",
            xpath_of_submit_button="//button[@id='verify-otp']",
            otp_source="static",
            otp_code="123456",
            mpin="4321",
            xpath_of_mpin_field="//input[@id='mpin']",
            xpath_of_mpin_submit_button="//button[@id='verify-mpin']",
            session_check_url=f"{base}/dashboard",
            logged_in_indicator="Welcome Authenticated User",
        )
        sess = login_with_otp_form(f"{base}/dashboard", auth, egress_proxy=proxy.url, timeout_seconds=30)
        assert state["otp_sent"] == 1
        assert valid_cookie in sess.cookie_header
        assert sess.local_storage.get("portal_token") == "jwt-from-mpin"

        verified = establish_session(f"{base}/dashboard", auth, egress=egress, egress_proxy=proxy.url, timeout_seconds=30)
        assert verified is not None and verified.verified is True
    finally:
        proxy.close()
        srv.shutdown()
        srv.server_close()


def test_session_from_import_rejects_header_injection() -> None:
    with pytest.raises(DastAuthError, match="newline"):
        session_from_import(
            "https://portal.example",
            AuthRequirements(auth_type="session", session_cookie="a=1\r\nX-Bad: 2"),
        )


def test_same_origin_header_routing_blocks_downgrade_and_third_party_and_dedupes() -> None:
    from helpers.agent.session_auth import _install_same_origin_headers

    captured_handler: list = []

    class _FakeContext:
        def route(self, pattern, handler):
            assert pattern == "**/*"
            captured_handler.append(handler)

    _install_same_origin_headers(
        _FakeContext(),
        "https://app.example.com",
        {"Authorization": "Bearer secret-jwt-123"},
    )
    handler = captured_handler[0]

    def _run(url: str, req_headers: dict[str, str]):
        sent: dict = {}

        class _Req:
            def __init__(self):
                self.url = url
                self.headers = req_headers

        class _Route:
            def __init__(self):
                self.request = _Req()

            def continue_(self, headers=None):
                sent["headers"] = headers

        handler(_Route())
        return sent["headers"]

    # Exact same origin (including explicit default port :443) injects & deduplicates case-insensitively
    h1 = _run("https://app.example.com:443/api/me", {"authorization": "Bearer old", "accept": "*/*"})
    assert h1 == {"accept": "*/*", "Authorization": "Bearer secret-jwt-123"}

    # HTTPS -> HTTP downgrade on same host MUST NOT receive Authorization header
    assert _run("http://app.example.com/pixel.gif", {"accept": "*/*"}) is None

    # Third-party CDN / analytics MUST NOT receive Authorization header
    assert _run("https://cdn.thirdparty.example/app.js", {"accept": "*/*"}) is None


def test_error_scrubbing_handles_long_secrets_and_suppresses_cause() -> None:
    from helpers.agent.session_auth import _scrub_secrets, verify_session

    long_jwt = "Bearer " + ("a" * 260)
    raw = f"network failure with header {long_jwt} and storage_secret=topsecret_ls_99"
    scrubbed = _scrub_secrets(raw, long_jwt, "topsecret_ls_99")[:200]
    assert "aaaaaaa" not in scrubbed
    assert "topsecret_ls_99" not in scrubbed
    assert "[REDACTED]" in scrubbed

    class _FailingEgress:
        def urlopen(self, _req, timeout=10):
            raise RuntimeError(f"boom {long_jwt} and topsecret_ls_99")

    sess = CapturedSession(
        origin="https://app.example.com",
        extra_headers={"Authorization": long_jwt},
        local_storage={"tok": "topsecret_ls_99"},
    )
    auth = AuthRequirements(auth_type="session", auth_header_value=long_jwt)
    with pytest.raises(DastAuthError) as exc_info:
        verify_session(sess, auth, "https://app.example.com/dashboard", egress=_FailingEgress())  # type: ignore[arg-type]
    assert exc_info.value.__cause__ is None
    assert "aaaaaaa" not in str(exc_info.value)
    assert "topsecret_ls_99" not in str(exc_info.value)


def test_captured_session_repr_and_nuclei_doc_scrubbing_and_yaml_fail_closed() -> None:
    from langchain_core.documents import Document

    sess = CapturedSession(
        origin="https://app.example.com",
        cookie_header="sid=super_secret_cookie_val",
        extra_headers={"Authorization": "Bearer jwt_secret_token_999"},
        local_storage={"token": "ls_secret_val_777"},
        session_storage={"skey": "ss_secret_val_888"},
    )
    # repr() must never expose any session secret (prevents LangSmith/traceback leakage)
    rep = repr(sess)
    for secret in ("super_secret_cookie_val", "jwt_secret_token_999", "ls_secret_val_777", "ss_secret_val_888"):
        assert secret not in rep

    # Nuclei -me document scrubbing must strip every secret before LLM prompts see it
    docs = [
        Document(
            page_content=(
                "GET /dashboard HTTP/1.1\n"
                "Cookie: sid=super_secret_cookie_val\n"
                "Authorization: Bearer jwt_secret_token_999\n"
                "localStorage token=ls_secret_val_777 skey=ss_secret_val_888\n"
                "<html>Dashboard</html>"
            ),
            metadata={"source": "req_jwt_secret_token_999.md"},
        )
    ]
    scrubbed = sess.scrub_documents(docs)
    assert len(scrubbed) == 1
    for secret in ("super_secret_cookie_val", "jwt_secret_token_999", "ls_secret_val_777", "ss_secret_val_888"):
        assert secret not in scrubbed[0].page_content
        assert secret not in str(scrubbed[0].metadata)
    assert "<html>Dashboard</html>" in scrubbed[0].page_content

    # materialize_session_template must fail closed on invalid or non-headless YAML
    with pytest.raises(ValueError, match="invalid YAML"):
        materialize_session_template(":::not:valid:yaml: [", sess)
    with pytest.raises(ValueError, match="non-headless"):
        materialize_session_template("id: x\nhttp:\n  - method: GET\n", sess)


def test_egress_redirect_handler_strips_auth_headers_on_origin_or_scheme_change() -> None:
    import urllib.request
    from helpers.net.egress import _SameOriginHeaderRedirectHandler

    handler = _SameOriginHeaderRedirectHandler()
    orig_req = urllib.request.Request(
        "https://app.example.com/start",
        headers={
            "Cookie": "sid=secret_cookie",
            "Authorization": "Bearer secret_jwt",
            "X-API-Key": "secret_key",
            "User-Agent": "TestUA",
        },
    )

    # Same-origin redirect keeps auth headers
    same = handler.redirect_request(orig_req, None, 302, "Found", {}, "https://app.example.com:443/next")
    assert same is not None
    same_hdrs = {k.lower(): v for k, v in same.header_items()}
    assert same_hdrs.get("cookie") == "sid=secret_cookie"
    assert same_hdrs.get("authorization") == "Bearer secret_jwt"

    # HTTPS -> HTTP downgrade strips Cookie, Authorization, X-API-Key
    downgraded = handler.redirect_request(orig_req, None, 302, "Found", {}, "http://app.example.com/next")
    assert downgraded is not None
    down_hdrs = {k.lower(): v for k, v in downgraded.header_items()}
    assert "cookie" not in down_hdrs
    assert "authorization" not in down_hdrs
    assert "x-api-key" not in down_hdrs
    assert down_hdrs.get("user-agent") == "TestUA"

    # Cross-host redirect strips Cookie, Authorization, X-API-Key
    cross = handler.redirect_request(orig_req, None, 302, "Found", {}, "https://other.example.com/next")
    assert cross is not None
    cross_hdrs = {k.lower(): v for k, v in cross.header_items()}
    assert "cookie" not in cross_hdrs
    assert "authorization" not in cross_hdrs
    assert "x-api-key" not in cross_hdrs


