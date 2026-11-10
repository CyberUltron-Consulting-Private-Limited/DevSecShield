"""Manual DAST (estimate and start) follows the profile-scan URL rule; DNS answers are checked address by address.

Found on the local production stack (round 5, L1): POST /{team}/dast/scan/{id}/estimate_credits accepted
http://169.254.169.254/latest/meta-data/ and made the DAST worker crawl http://backend:8080/health (worker log:
"Crawling: http://backend:8080/health ... Discovered 1 URLs"): manual estimate/start had no URL check at all, only
automatic profiles did. Both go through format_input_for_scan, which now refuses with 400 and the policy's message.

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_dast_manual_ssrf.py -q -p no:cacheprovider
"""
import asyncio

import pytest
from fastapi import HTTPException

from backend.utilities.dast import ssrf
from backend.utilities.dast.ssrf import DastSsrfError, assert_manual_dast_allowed
from backend.utilities.db.schemas import AuthRequirements, StartDASTScanData, StartScanPayload
from backend.utilities.scan.format_input import format_input_for_scan

DNS = {
    "app.example": ["93.184.216.34"],
    "backend": ["172.20.0.5"],  # a Docker service name on the stack's network
    "localhost": ["127.0.0.1", "::1"],
    "rebind.example": ["93.184.216.34", "10.0.0.7"],  # one public, one private answer
    "meta.example": ["169.254.169.254"],
}


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    monkeypatch.delenv("DAST_ALLOWED_PRIVATE", raising=False)

    def resolve(host):
        if host not in DNS:
            raise DastSsrfError(f"Could not resolve host {host}")
        return list(DNS[host])
    monkeypatch.setattr(ssrf, "_resolve_ips", resolve)


@pytest.mark.parametrize("target, message", [
    ("http://169.254.169.254/latest/meta-data/", "metadata"),
    ("http://meta.example/", "metadata"),
    ("http://backend:8080/health", "private"),
    ("http://localhost:3000/", "private"),
    ("http://127.0.0.1/", "private"),
    ("http://10.20.30.40/", "private"),
    ("http://rebind.example/", "resolves to 10.0.0.7"),
    ("ftp://app.example/", "Only http"),
    ("file:///etc/passwd", "Only http"),
])
def test_manual_targets_refused(target, message):
    with pytest.raises(DastSsrfError, match=message):
        assert_manual_dast_allowed(target, None, None)


def test_public_target_with_its_login_page_is_allowed():
    assert_manual_dast_allowed("https://app.example/", "https://app.example/login", ["https://app.example/a"])


def test_login_and_additional_urls_are_checked_too():
    with pytest.raises(DastSsrfError, match="not in allowlist"):
        assert_manual_dast_allowed("https://app.example/", "http://backend:8080/login", None)
    with pytest.raises(DastSsrfError, match="not in allowlist"):
        assert_manual_dast_allowed("https://app.example/", None, ["http://backend:8080/admin"])
    with pytest.raises(DastSsrfError, match="metadata"):
        assert_manual_dast_allowed("https://app.example/", None, ["http://169.254.169.254/"])


def test_operator_allowlist_opens_private_hosts_but_never_metadata(monkeypatch):
    monkeypatch.setenv("DAST_ALLOWED_PRIVATE", "backend, 10.0.0.0/8, 169.254.0.0/16, meta.example")
    assert_manual_dast_allowed("http://backend:8080/health", None, None)
    assert_manual_dast_allowed("http://10.20.30.40/", None, None)
    assert_manual_dast_allowed("http://rebind.example/", None, None)
    for target in ("http://169.254.169.254/", "http://meta.example/"):
        with pytest.raises(DastSsrfError, match="metadata"):
            assert_manual_dast_allowed(target, None, None)


def _payload(target, login=None):
    return StartScanPayload(dast=StartDASTScanData(target_url=target, auth=AuthRequirements(
        login_url=login or target, xpath_of_username_field="//a", xpath_of_password_field="//b",
        username="u", password="p", xpath_of_submit_button="//c")))


@pytest.mark.parametrize("target", ["http://169.254.169.254/latest/meta-data/", "http://backend:8080/health"])
def test_estimate_and_start_refuse_with_400(target):
    with pytest.raises(HTTPException) as err:
        asyncio.run(format_input_for_scan(scan_type="dast", start_scan_payload=_payload(target), uploaded_file=None))
    assert err.value.status_code == 400 and ("metadata" in err.value.detail or "private" in err.value.detail)


def test_estimate_and_start_pass_a_public_target_through():
    kwargs = asyncio.run(format_input_for_scan(scan_type="dast", start_scan_payload=_payload("https://app.example/"),
                                               uploaded_file=None))
    assert kwargs["dast_dict_context"]["target_url"] == "https://app.example/"
