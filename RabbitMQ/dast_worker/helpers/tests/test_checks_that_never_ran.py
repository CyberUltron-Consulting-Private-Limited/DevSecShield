"""A DAST scan whose checks could not run must not come back as a clean "Completed, 0 findings".

Found on the local production stack (round 5, L1): with Amazon Bedrock unavailable every XSS, SQLi and
page-analysis check raised; DASTAgent logged each error, counted it as "no findings", and OWASP Juice Shop was
reported "Completed, Critical 0 High 0 Medium 0 Low 0, coverage 100%". Now a check that failed on every URL fails
the scan with a message naming it; checks that failed on some URLs are recorded in metadata["check_errors"].

The checks are replaced by stubs; nothing reaches the network.
Run (no pytest in the worker image; plain asserts):
    docker run --rm --network none -v $PWD/RabbitMQ/dast_worker/helpers:/app/helpers:ro --entrypoint /app/.venv/bin/python \
      <dast-worker image> -m helpers.tests.test_checks_that_never_ran
or with pytest where the worker's dependencies are installed.
"""
from types import SimpleNamespace

import helpers.agent.main as agent_main
from helpers.net.address_rule import parse_allowlist
from helpers.net.egress import ScanEgress
from helpers.schema import FinalVulnResponse

URLS = ["http://shop.test/", "http://shop.test/login"]


class _Crawler:
    def __init__(self, **kw):
        self.metadata = {"urls_included": URLS}

    def crawl(self):
        return list(URLS)


class _Headers:
    def __init__(self, **kw):
        pass

    def run(self):
        return FinalVulnResponse(vulnerabilities=[])


def _bedrock_down(*a, **kw):
    raise RuntimeError("An error occurred (UnrecognizedClientException) when calling the InvokeModel operation")


class _Failing:
    def __init__(self, *a, **kw):
        self.target_url = kw.get("target_url") or kw.get("url")

    def run(self, *a, **kw):
        _bedrock_down()

    run_xss_agent_graph = run_sqli_agent_graph = run


class _FailsOnLogin(_Failing):
    def run(self, *a, **kw):
        if self.target_url.endswith("/login"):
            _bedrock_down()
        return []

    run_xss_agent_graph = run_sqli_agent_graph = run


def _context():
    auth = SimpleNamespace(login_url="http://shop.test/login", username="u", password="p",
                           xpath_of_username_field="//a", xpath_of_password_field="//b", xpath_of_submit_button="//c")
    return SimpleNamespace(target_url=URLS[0], max_urls=10, additional_urls_to_scan=[], include_url_patterns=[],
                           exclude_url_patterns=[], auth=auth, scan_speed="fast")


def _patch(xss=_Failing, sqli=_Failing, page=_Failing):
    saved = {n: getattr(agent_main, n) for n in ("Crawler", "SecurityHeadersCheck", "XSSAgent", "SQLiAgent",
                                                 "PageAnalysisCheck", "fetch_authenticated_page",
                                                 "get_auth_login_template", "reap_orphan_browsers", "ScanEgress")}
    agent_main.Crawler = _Crawler
    agent_main.SecurityHeadersCheck = _Headers
    agent_main.XSSAgent, agent_main.SQLiAgent, agent_main.PageAnalysisCheck = xss, sqli, page
    agent_main.fetch_authenticated_page = lambda url, auth, timeout_seconds=None, **kw: ("<html></html>", [])
    # shop.test does not resolve here: pin the scan's hosts to a public address (the egress tests cover the rule)
    agent_main.ScanEgress = lambda urls: ScanEgress(urls, rules=parse_allowlist(""), resolve=lambda _h: ["93.184.216.34"])
    agent_main.get_auth_login_template = lambda url, auth: ""
    agent_main.reap_orphan_browsers = lambda: None
    return saved


def _restore(saved):
    for n, v in saved.items():
        setattr(agent_main, n, v)


def test_checks_that_failed_on_every_url_fail_the_scan():
    saved = _patch()
    try:
        agent = agent_main.DASTAgent(_context())
        try:
            agent.run()
        except agent_main.DastChecksDidNotRun as e:
            msg = str(e)
        else:
            raise AssertionError("a scan whose XSS, SQLi and page checks never ran was reported as finished")
        for name in ("page analysis", "XSS", "SQL injection"):
            assert name in msg, msg
        assert "security headers" not in msg.split("(")[0]  # the headers check did run
        assert "UnrecognizedClientException" in msg and "2 URLs" in msg
    finally:
        _restore(saved)


def test_a_check_that_failed_on_some_urls_is_recorded_but_the_scan_finishes():
    saved = _patch(xss=_FailsOnLogin, sqli=_FailsOnLogin, page=_FailsOnLogin)
    try:
        agent = agent_main.DASTAgent(_context())
        vulns, metadata = agent.run()
        assert vulns == []
        assert metadata["check_errors"] == {"urls_scanned": 2,
                                            "failed_urls_per_check": {"page": 1, "xss": 1, "sqli": 1}}
    finally:
        _restore(saved)


if __name__ == "__main__":
    test_checks_that_failed_on_every_url_fail_the_scan()
    test_a_check_that_failed_on_some_urls_is_recorded_but_the_scan_finishes()
    print("dast checks-that-never-ran: ok")
