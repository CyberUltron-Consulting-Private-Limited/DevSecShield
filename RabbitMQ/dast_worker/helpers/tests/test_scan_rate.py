"""Hermetic tests for DAST scan-rate controls.

The live worker was ~0.4 URL/min because each URL ran four checks sequentially,
each XSS/SQLi path invoked multiple Bedrock calls + headless Nuclei, and
scan_speed only slept 5–15s between URLs.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from helpers.agent.context import AuthRequirements, StartDASTScanData
from helpers.agent.main import DASTAgent
from helpers.agent.page_surface import (
    documents_to_text,
    has_injection_surface,
    looks_like_html,
    should_run_injection_agents,
)
from helpers.agent.scan_config import ScanRuntime
from helpers.checks.nuclei.run_nuclei import build_nuclei_command
from helpers.checks.nuclei.yaml_validate import (
    strip_markdown_fences,
    validate_nuclei_yaml,
)
from helpers.checks.page_analysis import PageAnalysisCheck
from helpers.checks.security_headers import findings_from_headers
from langchain_core.documents import Document


JSON_HEALTH = '{"status":"ok","service":"aimeshgateway"}'
HTML_FORM = """
<html><body>
  <form action="/login">
    <input name="user" type="text">
    <input name="pass" type="password">
    <button type="submit">Go</button>
  </form>
</body></html>
"""
HTML_STATIC = "<html><body><h1>Docs</h1><p>No forms here.</p></body></html>"


def test_fast_profile_is_actually_concurrent_and_does_not_sleep():
    runtime = ScanRuntime.from_speed("fast")
    assert runtime.interval_between_requests == 0
    assert runtime.url_workers == 10
    assert runtime.check_workers >= 2
    assert runtime.nuclei_concurrency == 20
    assert runtime.exploit_retries == 1
    assert runtime.skip_injection_if_no_surface is False
    assert runtime.nuclei_timeout_seconds <= 90


def test_medium_is_faster_than_legacy_10s_sleep():
    runtime = ScanRuntime.from_speed("medium")
    assert runtime.interval_between_requests == 0
    assert runtime.url_workers == 5
    assert runtime.check_workers >= 2
    assert runtime.nuclei_concurrency == 10
    assert runtime.skip_injection_if_no_surface is False


def test_slow_runs_two_urls_and_does_not_skip_checks():
    runtime = ScanRuntime.from_speed("slow")
    assert runtime.url_workers == 2
    assert runtime.check_workers >= 2
    assert runtime.nuclei_concurrency == 4
    assert runtime.exploit_retries == 2
    assert runtime.skip_injection_if_no_surface is False
    assert runtime.interval_between_requests == 0


def test_json_health_endpoint_has_no_injection_surface():
    assert looks_like_html(JSON_HEALTH) is False
    assert has_injection_surface(JSON_HEALTH) is False
    assert should_run_injection_agents(JSON_HEALTH, skip_if_no_surface=True) is False


def test_html_form_keeps_xss_sqli_agents():
    assert looks_like_html(HTML_FORM) is True
    assert has_injection_surface(HTML_FORM) is True
    assert should_run_injection_agents(HTML_FORM, skip_if_no_surface=True) is True


def test_static_html_skips_agents_on_fast_but_not_when_forced():
    assert looks_like_html(HTML_STATIC) is True
    assert has_injection_surface(HTML_STATIC) is False
    assert should_run_injection_agents(HTML_STATIC, skip_if_no_surface=True) is False
    assert should_run_injection_agents(HTML_STATIC, skip_if_no_surface=False) is True


def test_empty_page_skips_injection_agents():
    assert should_run_injection_agents("", skip_if_no_surface=True) is False
    assert should_run_injection_agents(None, skip_if_no_surface=False) is False


def test_documents_to_text_joins_page_content():
    docs = [
        Document(page_content="<html>"),
        Document(page_content="<form></form>"),
    ]
    assert "<form>" in documents_to_text(docs)


def test_strip_markdown_fences_from_llm_yaml():
    fenced = "```yaml\nid: xss-test\ninfo:\n  name: x\n```"
    stripped = strip_markdown_fences(fenced)
    assert stripped.startswith("id:")
    assert "```" not in stripped


def test_validate_nuclei_yaml_accepts_headless_template():
    ok, reason = validate_nuclei_yaml(
        "id: demo\ninfo:\n  name: demo\n  severity: high\nheadless:\n  - steps:\n      - action: waitload\n"
    )
    assert ok is True
    assert reason is None


def test_validate_nuclei_yaml_rejects_prose():
    ok, reason = validate_nuclei_yaml("Here is a nuclei template that you should run...")
    assert ok is False
    assert reason


def test_nuclei_command_includes_timeouts_and_no_retry_storm():
    command = build_nuclei_command(
        url="https://example.com/api/health/",
        template_path="/tmp/t.yaml",
        timeout_seconds=45,
    )
    assert command[0] == "nuclei"
    assert "-u" in command
    assert "-timeout" in command
    assert "-retries" in command
    timeout_val = int(command[command.index("-timeout") + 1])
    assert timeout_val <= 45
    retries_val = int(command[command.index("-retries") + 1])
    assert retries_val <= 1


def _scan_context(speed: str) -> StartDASTScanData:
    return StartDASTScanData(
        target_url="https://example.com",
        auth=AuthRequirements(
            login_url="https://example.com/login",
            xpath_of_username_field="//user",
            xpath_of_password_field="//pass",
            username="u",
            password="p",
            xpath_of_submit_button="//go",
        ),
        scan_speed=speed,
    )


def test_dast_agent_fast_runtime_drops_the_legacy_sleep():
    agent = DASTAgent(dast_context=_scan_context("fast"))
    assert agent.interval_between_requests == 0
    assert agent.runtime.url_workers == 10
    assert agent.runtime.check_workers >= 2
    assert agent.runtime.skip_injection_if_no_surface is False


def test_page_analysis_still_runs_on_json_documents(monkeypatch):
    from helpers.schema import FinalVulnResponse

    check = PageAnalysisCheck(
        url="https://example.com/api/health/",
        auth=_scan_context("fast").auth,
    )
    called = {"summary": False}

    def _summary(**_kwargs):
        called["summary"] = True
        return FinalVulnResponse(vulnerabilities=[])

    monkeypatch.setattr(check, "generate_map_reduce_summary", _summary)
    result = check.run(documents=[Document(page_content=JSON_HEALTH)])
    assert called["summary"] is True
    assert result == []


def test_scan_url_runs_xss_sqli_on_json_health(monkeypatch):
    agent = DASTAgent(dast_context=_scan_context("fast"))
    monkeypatch.setattr(agent, "_run_headers", lambda url: [{"title": "header"}])
    monkeypatch.setattr(
        agent,
        "_fetch_page",
        lambda url: (JSON_HEALTH, [Document(page_content=JSON_HEALTH)]),
    )
    monkeypatch.setattr(agent, "_run_page_analysis", lambda url, documents: [])
    called = {"xss": False, "sqli": False}

    def _xss(*_args, **_kwargs):
        called["xss"] = True
        return [{"title": "xss"}]

    def _sqli(*_args, **_kwargs):
        called["sqli"] = True
        return [{"title": "sqli"}]

    monkeypatch.setattr(agent, "_run_xss", _xss)
    monkeypatch.setattr(agent, "_run_sqli", _sqli)
    found = agent._scan_url("https://aimeshgateway.zeroshield.ai/api/health/")
    assert called == {"xss": True, "sqli": True}
    titles = {item["title"] for item in found}
    assert titles == {"header", "xss", "sqli"}


def test_scan_url_runs_xss_sqli_in_parallel_on_html_forms(monkeypatch):
    agent = DASTAgent(dast_context=_scan_context("fast"))
    monkeypatch.setattr(agent, "_run_headers", lambda url: [])
    monkeypatch.setattr(
        agent,
        "_fetch_page",
        lambda url: (HTML_FORM, [Document(page_content=HTML_FORM)]),
    )
    monkeypatch.setattr(agent, "_run_page_analysis", lambda url, documents: [])
    monkeypatch.setattr(agent, "_run_xss", lambda *args, **kwargs: [{"title": "xss"}])
    monkeypatch.setattr(agent, "_run_sqli", lambda *args, **kwargs: [{"title": "sqli"}])
    found = agent._scan_url("https://example.com/login")
    titles = {item["title"] for item in found}
    assert titles == {"xss", "sqli"}


def test_slow_also_runs_xss_and_sqli_together(monkeypatch):
    agent = DASTAgent(dast_context=_scan_context("slow"))
    monkeypatch.setattr(agent, "_run_headers", lambda url: [])
    monkeypatch.setattr(
        agent,
        "_fetch_page",
        lambda url: (HTML_FORM, [Document(page_content=HTML_FORM)]),
    )
    monkeypatch.setattr(agent, "_run_page_analysis", lambda url, documents: [])
    started = {}

    def _xss(*_args, **_kwargs):
        started["xss"] = time.monotonic()
        time.sleep(0.12)
        return [{"title": "xss"}]

    def _sqli(*_args, **_kwargs):
        started["sqli"] = time.monotonic()
        time.sleep(0.12)
        return [{"title": "sqli"}]

    monkeypatch.setattr(agent, "_run_xss", _xss)
    monkeypatch.setattr(agent, "_run_sqli", _sqli)
    t0 = time.monotonic()
    agent._scan_url("https://example.com/login")
    elapsed = time.monotonic() - t0
    assert abs(started["xss"] - started["sqli"]) < 0.08
    assert elapsed < 0.22


def test_xss_and_sqli_start_together_not_back_to_back(monkeypatch):
    agent = DASTAgent(dast_context=_scan_context("fast"))
    monkeypatch.setattr(agent, "_run_headers", lambda url: [])
    monkeypatch.setattr(
        agent,
        "_fetch_page",
        lambda url: (HTML_FORM, [Document(page_content=HTML_FORM)]),
    )
    monkeypatch.setattr(agent, "_run_page_analysis", lambda url, documents: [])
    started = {}

    def _xss(*_args, **_kwargs):
        started["xss"] = time.monotonic()
        time.sleep(0.12)
        return [{"title": "xss"}]

    def _sqli(*_args, **_kwargs):
        started["sqli"] = time.monotonic()
        time.sleep(0.12)
        return [{"title": "sqli"}]

    monkeypatch.setattr(agent, "_run_xss", _xss)
    monkeypatch.setattr(agent, "_run_sqli", _sqli)
    t0 = time.monotonic()
    agent._scan_url("https://example.com/login")
    elapsed = time.monotonic() - t0
    assert "xss" in started and "sqli" in started
    assert abs(started["xss"] - started["sqli"]) < 0.08
    assert elapsed < 0.22
def test_ten_urls_run_in_parallel(monkeypatch):
    _assert_url_workers(monkeypatch, speed="fast", expected_workers=10)


def test_five_urls_run_in_parallel_on_medium(monkeypatch):
    _assert_url_workers(monkeypatch, speed="medium", expected_workers=5)


def test_two_urls_run_in_parallel_on_slow(monkeypatch):
    _assert_url_workers(monkeypatch, speed="slow", expected_workers=2)


def _assert_url_workers(monkeypatch, speed: str, expected_workers: int):
    urls = [f"https://example.com/p/{i}" for i in range(expected_workers * 2)]

    class FakeCrawler:
        def __init__(self, **_kwargs):
            self.metadata = {"urls_included": urls, "urls_excluded": []}

        def crawl(self):
            return list(urls)

    current = 0
    max_seen = 0
    lock = threading.Lock()

    def fake_scan(url):
        nonlocal current, max_seen
        with lock:
            current += 1
            max_seen = max(max_seen, current)
        time.sleep(0.08)
        with lock:
            current -= 1
        return []

    monkeypatch.setattr("helpers.agent.main.Crawler", FakeCrawler)
    agent = DASTAgent(dast_context=_scan_context(speed))
    monkeypatch.setattr(agent, "_scan_url", fake_scan)
    agent.run()
    assert max_seen == expected_workers


def test_nuclei_semaphore_caps_parallel_chromes(monkeypatch, tmp_path):
    from helpers.checks.nuclei import run_nuclei as nuclei_mod

    nuclei_mod.set_nuclei_concurrency(2)
    current = 0
    max_seen = 0
    lock = threading.Lock()

    class FakeProc:
        returncode = 0
        pid = 1234

        def communicate(self, timeout=None):
            nonlocal current, max_seen
            with lock:
                current += 1
                max_seen = max(max_seen, current)
            time.sleep(0.05)
            with lock:
                current -= 1
            return b"", b""

    monkeypatch.setattr(nuclei_mod.subprocess, "Popen", lambda *_args, **_kwargs: FakeProc())
    monkeypatch.setattr(nuclei_mod, "load_dir_to_documents", lambda _path: [])
    template = tmp_path / "t.yaml"
    template.write_text("id: t\ninfo:\n  name: t\nheadless: []\n")

    def one(_):
        nuclei_mod.run_nuclei("https://example.com", str(template), timeout_seconds=5)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(one, range(6)))
    assert max_seen <= 2
    assert max_seen == 2


def test_header_findings_do_not_need_a_browser():
    findings = findings_from_headers(
        {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
        }
    )
    missing = [item for item in findings if "missing" in item.lower()]
    assert any("X-Frame-Options" in item for item in missing)
    assert any("X-Content-Type-Options" in item for item in missing)
    assert not any("Content-Security-Policy header is missing" in item for item in findings)
