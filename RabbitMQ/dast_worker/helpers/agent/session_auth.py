"""Single-login session management for DAST (Session Import & 2-Step Mobile/OTP Form).

All network traffic runs strictly through the scan's ``ScanEgress`` / ``EgressProxy``.
Secrets (cookies, Bearer tokens, localStorage, OTP codes, TOTP secrets, MPINs) are never
logged and never sent to the LLM prompt.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import yaml
from rich.console import Console

from helpers.agent.context import AuthRequirements
from helpers.net.egress import ScanEgress

console = Console(markup=False)

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
_FORBIDDEN_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection", "cookie"})
_USER_AGENT = "Mozilla/5.0 (compatible; DevSecShield-DAST/1.0)"

COOKIE_PLACEHOLDER = "__DSS_SESSION_COOKIE__"
HEADER_PLACEHOLDER_PREFIX = "__DSS_SESSION_HEADER_"
STORAGE_SCRIPT_PLACEHOLDER = "__DSS_STORAGE_INJECT__"


class DastAuthError(RuntimeError):
    """Raised when an imported session is expired/invalid or OTP login fails (triggers fail-fast + credit refund)."""


def _origin_of(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _sanitize_header_val(val: str, label: str) -> str:
    if "\r" in val or "\n" in val:
        raise DastAuthError(f"{label} must not contain newline characters")
    return val.strip()


def _parse_storage_map(raw: str | None, label: str) -> dict[str, str]:
    if not raw or not str(raw).strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DastAuthError(f"{label} must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise DastAuthError(f"{label} must be a JSON object")
    out: dict[str, str] = {}
    for k, v in parsed.items():
        if not isinstance(k, str) or not k.strip():
            raise DastAuthError(f"{label} keys must be non-empty strings")
        out[k] = v if isinstance(v, str) else json.dumps(v)
    return out


def generate_totp(secret: str, *, timestamp: int | None = None, step: int = 30, digits: int = 6) -> str:
    """RFC 6238 TOTP (HMAC-SHA1), pure stdlib."""
    cleaned = re.sub(r"[\s-]+", "", (secret or "")).upper()
    if not cleaned:
        raise DastAuthError("TOTP secret is empty")
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        key = base64.b32decode(cleaned + pad, casefold=True)
    except Exception as exc:
        raise DastAuthError("TOTP secret is not valid Base32") from exc
    counter = int((time.time() if timestamp is None else timestamp) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


@dataclass
class CapturedSession:
    """Authenticated browser/HTTP state reused across crawl, headers, page analysis, XSS, and SQLi."""

    origin: str
    cookie_header: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    verified: bool = False
    verify_url: str | None = None

    def http_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.cookie_header:
            headers["Cookie"] = self.cookie_header
        for k, v in self.extra_headers.items():
            headers[k] = v
        return headers

    def has_material(self) -> bool:
        return bool(self.cookie_header or self.extra_headers or self.local_storage or self.session_storage)

    def playwright_cookies(self) -> list[dict[str, Any]]:
        if not self.cookie_header:
            return []
        cookies: list[dict[str, Any]] = []
        for pair in self.cookie_header.split(";"):
            part = pair.strip()
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            if name:
                cookies.append({"name": name, "value": value.strip(), "url": self.origin})
        return cookies

    def storage_init_js(self) -> str:
        lines: list[str] = []
        for k, v in self.local_storage.items():
            lines.append(f"window.localStorage.setItem({json.dumps(k)}, {json.dumps(v)});")
        for k, v in self.session_storage.items():
            lines.append(f"window.sessionStorage.setItem({json.dumps(k)}, {json.dumps(v)});")
        return "\n".join(lines)


def session_from_import(target_url: str, auth: AuthRequirements) -> CapturedSession:
    cookie = _sanitize_header_val(auth.session_cookie, "session_cookie") if auth.session_cookie else ""
    extra: dict[str, str] = {}
    if auth.auth_header_value and auth.auth_header_value.strip():
        header_name = (auth.auth_header_name or "Authorization").strip()
        if not _HEADER_NAME_RE.match(header_name) or header_name.lower() in _FORBIDDEN_HEADERS:
            raise DastAuthError(f"Invalid auth header name: {header_name!r}")
        extra[header_name] = _sanitize_header_val(auth.auth_header_value, "auth_header_value")
    ls = _parse_storage_map(auth.local_storage_json, "local_storage_json")
    ss = _parse_storage_map(auth.session_storage_json, "session_storage_json")
    sess = CapturedSession(
        origin=_origin_of(target_url),
        cookie_header=cookie,
        extra_headers=extra,
        local_storage=ls,
        session_storage=ss,
    )
    if not sess.has_material():
        raise DastAuthError("Session import has no cookie, header, or browser storage data")
    return sess


def _launch_browser_kwargs(egress_proxy: str, playwright_browser_type: Any = None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "headless": True,
        "proxy": {"server": egress_proxy},
        "args": [
            "--proxy-bypass-list=<-loopback>",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--no-sandbox",
            "--disable-dev-shm-usage",
        ],
    }
    override = (os.environ.get("DAST_CHROMIUM_PATH") or "").strip()
    if override and os.path.isfile(override):
        kwargs["executable_path"] = override
    elif playwright_browser_type is not None:
        expected = getattr(playwright_browser_type, "executable_path", "")
        if expected and not os.path.isfile(expected):
            sys_chrome = shutil.which("chromium") or shutil.which("google-chrome")
            if sys_chrome:
                kwargs["executable_path"] = sys_chrome
    return kwargs


def _fill_otp_or_pin(page: Any, xpath: str, value: str, timeout_ms: int = 15_000) -> None:
    """Fill a single OTP/MPIN box OR split multi-digit OTP inputs."""
    locator = page.locator(f"xpath={xpath}")
    locator.first.wait_for(state="visible", timeout=timeout_ms)
    count = locator.count()
    if count > 1 and count >= len(value):
        for idx, ch in enumerate(value):
            locator.nth(idx).click()
            locator.nth(idx).fill(ch)
        return

    first = locator.first
    tag = (first.evaluate("el => el.tagName.toLowerCase()") or "").strip()
    if tag != "input":
        nested = first.locator("input")
        ncount = nested.count()
        if ncount >= len(value) and ncount > 1:
            for idx, ch in enumerate(value):
                nested.nth(idx).click()
                nested.nth(idx).fill(ch)
            return
        if ncount == 1:
            first = nested.first

    max_len = first.get_attribute("maxlength")
    first.click()
    if max_len == "1" and len(value) > 1:
        # Many React/Next OTP widgets auto-advance focus on each keystroke when maxlength="1"
        page.keyboard.type(value, delay=40)
    else:
        first.fill(value)


def _wait_after_submit(page: Any, prev_url: str, *, timeout_ms: int = 8_000) -> None:
    """Wait for an SPA fetch/form submit after clicking Verify/Submit to complete and settle."""
    page.wait_for_timeout(350)
    try:
        page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 5_000))
    except Exception:
        pass
    deadline = time.monotonic() + min(timeout_ms / 1000.0, 4.0)
    while time.monotonic() < deadline:
        if (page.url or "") != prev_url:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=3_000)
                page.wait_for_load_state("networkidle", timeout=3_000)
            except Exception:
                pass
            return
        page.wait_for_timeout(200)


def _merge_cookies(existing: str, pw_cookies: list[dict[str, Any]]) -> str:
    jar: dict[str, str] = {}
    for pair in (existing or "").split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.strip():
                jar[k.strip()] = v.strip()
    for c in pw_cookies or []:
        name = str(c.get("name") or "").strip()
        if name:
            jar[name] = str(c.get("value") or "")
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def login_with_otp_form(
    target_url: str,
    auth: AuthRequirements,
    *,
    egress_proxy: str,
    timeout_seconds: int = 60,
) -> CapturedSession:
    """Run a 2-step mobile/email + OTP login (with optional MPIN) once in Chromium via egress_proxy."""
    if not egress_proxy:
        raise DastAuthError("OTP login cannot run without the scan's egress guard")
    if not auth.login_url:
        raise DastAuthError("login_url is required for OTP form login")

    from playwright.sync_api import sync_playwright

    origin = _origin_of(target_url)
    target_host = urllib.parse.urlparse(target_url).netloc.lower()
    timeout_ms = max(10_000, int(timeout_seconds) * 1000)
    observed_auth_headers: dict[str, str] = {}

    if auth.otp_source == "totp":
        otp_value = generate_totp(auth.totp_secret or "")
    else:
        otp_value = (auth.otp_code or "").strip()
    if not otp_value:
        raise DastAuthError("OTP value could not be resolved")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(**_launch_browser_kwargs(egress_proxy, p.chromium))
            try:
                context = browser.new_context(ignore_https_errors=False, user_agent=_USER_AGENT)
                page = context.new_page()
                page.set_default_timeout(timeout_ms)

                def _on_request(req: Any) -> None:
                    try:
                        if urllib.parse.urlparse(req.url).netloc.lower() != target_host:
                            return
                        hdrs = req.headers or {}
                        auth_val = hdrs.get("authorization")
                        if auth_val and "\r" not in auth_val and "\n" not in auth_val:
                            observed_auth_headers["Authorization"] = auth_val
                    except Exception:
                        pass

                page.on("request", _on_request)
                page.goto(auth.login_url, wait_until="domcontentloaded", timeout=timeout_ms)

                # Step 1: Enter mobile number / email
                user_loc = page.locator(f"xpath={auth.xpath_of_username_field}").first
                user_loc.wait_for(state="visible", timeout=timeout_ms)
                user_loc.click()
                user_loc.fill((auth.username or "").strip())

                # Step 2 (optional): Click "Send OTP" / "Continue"
                if auth.xpath_of_send_otp_button and auth.xpath_of_send_otp_button.strip():
                    send_btn = page.locator(f"xpath={auth.xpath_of_send_otp_button}").first
                    send_btn.wait_for(state="visible", timeout=timeout_ms)
                    send_btn.click()

                # Step 3: Fill OTP and submit
                _fill_otp_or_pin(page, auth.xpath_of_otp_field or "", otp_value, timeout_ms=min(timeout_ms, 20_000))
                pre_otp_url = page.url or ""
                submit_btn = page.locator(f"xpath={auth.xpath_of_submit_button}").first
                submit_btn.wait_for(state="visible", timeout=timeout_ms)
                submit_btn.click()
                if not (auth.mpin and auth.mpin.strip() and auth.xpath_of_mpin_field):
                    _wait_after_submit(page, pre_otp_url, timeout_ms=min(timeout_ms, 8_000))
                else:
                    page.wait_for_timeout(350)

                # Step 4 (optional): Post-OTP MPIN step
                if auth.mpin and auth.mpin.strip() and auth.xpath_of_mpin_field:
                    _fill_otp_or_pin(page, auth.xpath_of_mpin_field, auth.mpin.strip(), timeout_ms=min(timeout_ms, 20_000))
                    pre_mpin_url = page.url or ""
                    if auth.xpath_of_mpin_submit_button and auth.xpath_of_mpin_submit_button.strip():
                        mpin_btn = page.locator(f"xpath={auth.xpath_of_mpin_submit_button}").first
                        mpin_btn.wait_for(state="visible", timeout=timeout_ms)
                        mpin_btn.click()
                    _wait_after_submit(page, pre_mpin_url, timeout_ms=min(timeout_ms, 8_000))

                pw_cookies = context.cookies([origin])
                ls = page.evaluate("() => Object.assign({}, window.localStorage)") or {}
                ss = page.evaluate("() => Object.assign({}, window.sessionStorage)") or {}
                final_url = page.url or ""
            finally:
                browser.close()
    except DastAuthError:
        raise
    except Exception as exc:
        raise DastAuthError(f"OTP login failed during browser flow: {type(exc).__name__}: {str(exc)[:240]}") from exc

    session = CapturedSession(
        origin=origin,
        cookie_header=_merge_cookies("", pw_cookies),
        extra_headers=observed_auth_headers,
        local_storage={str(k): str(v) for k, v in ls.items()} if isinstance(ls, dict) else {},
        session_storage={str(k): str(v) for k, v in ss.items()} if isinstance(ss, dict) else {},
    )
    if not session.has_material():
        login_path = urllib.parse.urlparse(auth.login_url).path.rstrip("/")
        final_path = urllib.parse.urlparse(final_url).path.rstrip("/")
        if final_path == login_path:
            raise DastAuthError(
                "OTP login failed: no session cookie, token, or browser storage was established and the page stayed on the login URL."
            )
    console.print(
        f"OTP login completed (cookies={'yes' if session.cookie_header else 'no'}, "
        f"headers={list(session.extra_headers.keys())}, localStorage_keys={len(session.local_storage)})",
        style="bold green",
    )
    return session


def _is_login_redirect(check_url: str, final_url: str, login_url: str | None) -> bool:
    check_path = urllib.parse.urlparse(check_url).path.rstrip("/").lower()
    final_path = urllib.parse.urlparse(final_url).path.rstrip("/").lower()
    if final_path == check_path:
        return False
    if login_url:
        login_path = urllib.parse.urlparse(login_url).path.rstrip("/").lower()
        if login_path and final_path == login_path:
            return True
    return any(tok in final_path for tok in ("/login", "/signin", "/sign-in", "/otp"))


def _verify_session_browser(
    session: CapturedSession,
    check_url: str,
    login_url: str | None,
    indicator: str | None,
    *,
    egress_proxy: str,
    timeout_seconds: int = 25,
) -> None:
    from playwright.sync_api import sync_playwright

    timeout_ms = max(10_000, int(timeout_seconds) * 1000)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(**_launch_browser_kwargs(egress_proxy, p.chromium))
            try:
                context = browser.new_context(
                    ignore_https_errors=False,
                    user_agent=_USER_AGENT,
                    extra_http_headers=session.extra_headers or None,
                )
                pw_cookies = session.playwright_cookies()
                if pw_cookies:
                    context.add_cookies(pw_cookies)
                page = context.new_page()
                page.set_default_timeout(timeout_ms)
                if session.local_storage or session.session_storage:
                    page.goto(session.origin, wait_until="domcontentloaded", timeout=timeout_ms)
                    page.evaluate(f"() => {{ {session.storage_init_js()} }}")
                resp = page.goto(check_url, wait_until="domcontentloaded", timeout=timeout_ms)
                try:
                    page.wait_for_load_state("networkidle", timeout=6_000)
                except Exception:
                    page.wait_for_timeout(800)
                status_code = resp.status if resp is not None else 0
                final_url = page.url or check_url
                html = page.content() or ""
                # Merge any refreshed cookies set after storage hydration
                refreshed = context.cookies([session.origin])
                if refreshed:
                    session.cookie_header = _merge_cookies(session.cookie_header, refreshed)
            finally:
                browser.close()
    except DastAuthError:
        raise
    except Exception as exc:
        raise DastAuthError(
            f"Session verification failed in browser for {check_url}: {type(exc).__name__}: {str(exc)[:200]}"
        ) from exc

    if status_code in (401, 403):
        raise DastAuthError(
            f"Session verification failed (HTTP {status_code}) on {check_url}: session cookie/token is expired or rejected."
        )
    if _is_login_redirect(check_url, final_url, login_url):
        raise DastAuthError(
            f"Session verification failed: {check_url} redirected to login ({final_url}). Session is expired or invalid."
        )
    if indicator and indicator.lower() not in html.lower():
        raise DastAuthError(
            f"Session verification failed: expected logged-in text {indicator!r} was not found on {check_url}."
        )


def verify_session(
    session: CapturedSession,
    auth: AuthRequirements,
    target_url: str,
    *,
    egress: ScanEgress,
    egress_proxy: str | None = None,
    timeout_seconds: int = 20,
) -> None:
    """Confirm the session is active before crawling/scanning; raises DastAuthError on failure (fail-fast)."""
    check_url = (auth.session_check_url or "").strip() or target_url
    indicator = (auth.logged_in_indicator or "").strip() or None

    # Browser storage sessions must be verified in Chromium so JS can read localStorage/sessionStorage.
    if (session.local_storage or session.session_storage) and egress_proxy:
        _verify_session_browser(
            session, check_url, auth.login_url, indicator, egress_proxy=egress_proxy, timeout_seconds=timeout_seconds
        )
        session.verified = True
        session.verify_url = check_url
        return

    headers = {"User-Agent": _USER_AGENT, "Accept": "text/html,application/json,*/*", **session.http_headers()}
    req = urllib.request.Request(check_url, headers=headers, method="GET")
    try:
        with egress.urlopen(req, timeout=timeout_seconds) as resp:
            status_code = getattr(resp, "status", 200)
            final_url = resp.geturl() or check_url
            body = resp.read(262_144).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise DastAuthError(
                f"Session verification failed (HTTP {exc.code}) on {check_url}: session cookie or token is expired or invalid."
            ) from exc
        raise DastAuthError(f"Session verification failed (HTTP {exc.code}) on {check_url}") from exc
    except Exception as exc:
        raise DastAuthError(f"Session verification could not reach {check_url}: {exc}") from exc

    if status_code in (401, 403):
        raise DastAuthError(
            f"Session verification failed (HTTP {status_code}) on {check_url}: session cookie or token is expired or invalid."
        )
    if _is_login_redirect(check_url, final_url, auth.login_url):
        raise DastAuthError(
            f"Session verification failed: {check_url} redirected to login ({final_url}). Capture a fresh session and try again."
        )
    if indicator and indicator.lower() not in body.lower():
        # SPA pages may render indicator only after JS runs; try browser once if proxy available
        if egress_proxy:
            _verify_session_browser(
                session, check_url, auth.login_url, indicator, egress_proxy=egress_proxy, timeout_seconds=timeout_seconds
            )
        else:
            raise DastAuthError(
                f"Session verification failed: expected logged-in text {indicator!r} was not found on {check_url}."
            )

    session.verified = True
    session.verify_url = check_url


def establish_session(
    target_url: str,
    auth: AuthRequirements,
    *,
    egress: ScanEgress,
    egress_proxy: str | None = None,
    timeout_seconds: int = 60,
) -> CapturedSession | None:
    """Establish and verify a reusable session for 'session' or 'otp_form' auth; returns None for 'password'."""
    if auth.auth_type == "password":
        return None
    if auth.auth_type == "session":
        session = session_from_import(target_url, auth)
        verify_session(session, auth, target_url, egress=egress, egress_proxy=egress_proxy, timeout_seconds=min(timeout_seconds, 25))
        return session
    if auth.auth_type == "otp_form":
        if not egress_proxy:
            raise DastAuthError("OTP login requires the scan's egress proxy")
        session = login_with_otp_form(target_url, auth, egress_proxy=egress_proxy, timeout_seconds=timeout_seconds)
        verify_session(session, auth, target_url, egress=egress, egress_proxy=egress_proxy, timeout_seconds=min(timeout_seconds, 25))
        return session
    raise DastAuthError(f"Unsupported auth_type: {auth.auth_type!r}")


def discover_authenticated_urls(
    target_url: str,
    session: CapturedSession,
    *,
    egress_proxy: str,
    max_urls: int = 50,
    timeout_seconds: int = 25,
) -> list[str]:
    """Single headless pass with session injected to discover SPA/JS-rendered same-origin links."""
    if not egress_proxy:
        return []
    try:
        from playwright.sync_api import sync_playwright

        base_netloc = urllib.parse.urlparse(target_url).netloc.lower()
        timeout_ms = max(8_000, int(timeout_seconds) * 1000)
        raw_links: list[str] = []
        with sync_playwright() as p:
            browser = p.chromium.launch(**_launch_browser_kwargs(egress_proxy, p.chromium))
            try:
                context = browser.new_context(
                    ignore_https_errors=False,
                    user_agent=_USER_AGENT,
                    extra_http_headers=session.extra_headers or None,
                )
                pw_cookies = session.playwright_cookies()
                if pw_cookies:
                    context.add_cookies(pw_cookies)
                page = context.new_page()
                page.set_default_timeout(timeout_ms)
                if session.local_storage or session.session_storage:
                    page.goto(session.origin, wait_until="domcontentloaded", timeout=timeout_ms)
                    page.evaluate(f"() => {{ {session.storage_init_js()} }}")
                page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
                try:
                    page.wait_for_load_state("networkidle", timeout=6_000)
                except Exception:
                    page.wait_for_timeout(800)
                raw_links = page.evaluate(
                    """() => {
                        const urls = [];
                        document.querySelectorAll('a[href], form[action]').forEach(el => {
                            const attr = el.getAttribute('href') || el.getAttribute('action');
                            if (attr) urls.push(attr);
                        });
                        return urls;
                    }"""
                ) or []
            finally:
                browser.close()
        out: list[str] = []
        seen: set[str] = set()
        for href in raw_links:
            full = urllib.parse.urljoin(target_url, str(href).strip())
            parsed = urllib.parse.urlparse(full)
            if parsed.scheme not in ("http", "https") or parsed.netloc.lower() != base_netloc:
                continue
            clean = parsed._replace(fragment="").geturl()
            if clean not in seen:
                seen.add(clean)
                out.append(clean)
                if len(out) >= max_urls:
                    break
        return out
    except Exception as exc:
        console.print(f"Headless authenticated link discovery skipped: {type(exc).__name__}", style="dim yellow")
        return []


def _header_placeholder(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9]", "_", name).upper()
    return f"{HEADER_PLACEHOLDER_PREFIX}{safe}__"


def _session_steps(session: CapturedSession, *, placeholder: bool) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    if session.cookie_header:
        steps.append(
            {
                "action": "setheader",
                "args": {
                    "part": "request",
                    "key": "Cookie",
                    "value": COOKIE_PLACEHOLDER if placeholder else session.cookie_header,
                },
            }
        )
    for k, v in session.extra_headers.items():
        steps.append(
            {
                "action": "setheader",
                "args": {
                    "part": "request",
                    "key": k,
                    "value": _header_placeholder(k) if placeholder else v,
                },
            }
        )
    if session.local_storage or session.session_storage:
        steps.append({"action": "navigate", "args": {"url": session.origin}})
        steps.append({"action": "waitload"})
        code = (
            f"() => {{ /* {STORAGE_SCRIPT_PLACEHOLDER} */ }}"
            if placeholder
            else f"() => {{\n{session.storage_init_js()}\n}}"
        )
        steps.append({"action": "script", "args": {"code": code}})
    return steps


def build_session_nuclei_template(
    session: CapturedSession,
    target_url: str,
    *,
    extract_html: bool = False,
    placeholder: bool = False,
) -> str:
    """Build a valid Nuclei headless template that injects the captured session and navigates to target_url."""
    steps = _session_steps(session, placeholder=placeholder)
    steps.append({"action": "navigate", "args": {"url": target_url}})
    steps.append({"action": "waitload"})
    headless_entry: dict[str, Any] = {"steps": steps}
    if extract_html:
        steps.append(
            {
                "action": "script",
                "name": "extract_html",
                "args": {"code": "() => {\n  return document.documentElement.outerHTML;\n}"},
            }
        )
        headless_entry["extractors"] = [
            {"type": "regex", "part": "extract_html", "regex": ["(?s)(.*)"]}
        ]
    doc = {
        "id": "template_template_name",
        "info": {"name": "template_template_name", "author": "pdteam", "severity": "high"},
        "headless": [headless_entry],
    }
    return yaml.safe_dump(doc, sort_keys=False)


def materialize_session_template(yaml_text: str, session: CapturedSession | None) -> str:
    """Inject real session secrets into a placeholder template right before run_nuclei writes a 0600 file."""
    if session is None or not session.has_material():
        return yaml_text
    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        parsed = None

    if not isinstance(parsed, dict) or not isinstance(parsed.get("headless"), list) or not parsed["headless"]:
        # Fall back to safe string replacement if structure is unexpected
        out = yaml_text
        if session.cookie_header:
            out = out.replace(COOKIE_PLACEHOLDER, session.cookie_header)
        for k, v in session.extra_headers.items():
            out = out.replace(_header_placeholder(k), v)
        if session.local_storage or session.session_storage:
            out = out.replace(f"/* {STORAGE_SCRIPT_PLACEHOLDER} */", session.storage_init_js())
        return out

    replaced_cookie = False
    replaced_headers: set[str] = set()
    replaced_storage = False
    for block in parsed["headless"]:
        if not isinstance(block, dict) or not isinstance(block.get("steps"), list):
            continue
        for step in block["steps"]:
            if not isinstance(step, dict) or not isinstance(step.get("args"), dict):
                continue
            args = step["args"]
            if step.get("action") == "setheader":
                val = args.get("value")
                if val == COOKIE_PLACEHOLDER and session.cookie_header:
                    args["value"] = session.cookie_header
                    replaced_cookie = True
                for k, v in session.extra_headers.items():
                    if val == _header_placeholder(k):
                        args["value"] = v
                        replaced_headers.add(k)
            elif step.get("action") == "script" and isinstance(args.get("code"), str):
                if STORAGE_SCRIPT_PLACEHOLDER in args["code"]:
                    args["code"] = f"() => {{\n{session.storage_init_js()}\n}}"
                    replaced_storage = True

    # If the LLM dropped any session step, prepend the missing ones so authenticated testing still works.
    missing: list[dict[str, Any]] = []
    if session.cookie_header and not replaced_cookie:
        missing.append({"action": "setheader", "args": {"part": "request", "key": "Cookie", "value": session.cookie_header}})
    for k, v in session.extra_headers.items():
        if k not in replaced_headers:
            missing.append({"action": "setheader", "args": {"part": "request", "key": k, "value": v}})
    if (session.local_storage or session.session_storage) and not replaced_storage:
        missing.append({"action": "navigate", "args": {"url": session.origin}})
        missing.append({"action": "waitload"})
        missing.append({"action": "script", "args": {"code": f"() => {{\n{session.storage_init_js()}\n}}"}})

    if missing and isinstance(parsed["headless"][0], dict) and isinstance(parsed["headless"][0].get("steps"), list):
        parsed["headless"][0]["steps"] = missing + parsed["headless"][0]["steps"]

    return yaml.safe_dump(parsed, sort_keys=False)
