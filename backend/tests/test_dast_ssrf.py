"""Hermetic SSRF allowlist for automatic DAST (no live DNS required)."""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import pytest

from backend.utilities.dast.ssrf import DastSsrfError, assert_urls_allowed, host_from_url


def test_host_from_url_strips_port_and_path() -> None:
    assert host_from_url("https://demo.testfire.net:443/login.jsp") == "demo.testfire.net"


def test_public_host_in_allowlist_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "backend.utilities.dast.ssrf._resolve_ips",
        lambda _host: ["23.22.30.252"],
    )
    assert_urls_allowed(
        ["https://demo.testfire.net/index.jsp"],
        allowed_hosts=["demo.testfire.net"],
    )


def test_host_not_in_allowlist_is_rejected() -> None:
    with pytest.raises(DastSsrfError, match="not in allowlist"):
        assert_urls_allowed(
            ["https://evil.example/login"],
            allowed_hosts=["demo.testfire.net"],
        )


def test_loopback_ip_rejected_unless_allowlisted() -> None:
    with pytest.raises(DastSsrfError, match="private"):
        assert_urls_allowed(["http://127.0.0.1:8080/"], allowed_hosts=["example.com"])


def test_rfc1918_needs_the_operator_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    # Product decision (round 5): a customer's allowed_hosts narrows the scope but cannot open a private address;
    # only the operator's DAST_ALLOWED_PRIVATE can.
    monkeypatch.delenv("DAST_ALLOWED_PRIVATE", raising=False)
    with pytest.raises(DastSsrfError, match="private"):
        assert_urls_allowed(["http://10.1.2.3/app"], allowed_hosts=["10.1.2.3"])
    monkeypatch.setenv("DAST_ALLOWED_PRIVATE", "10.1.0.0/16")
    assert_urls_allowed(["http://10.1.2.3/app"], allowed_hosts=["10.1.2.3"])


def test_cloud_metadata_ip_always_rejected() -> None:
    with pytest.raises(DastSsrfError, match="metadata"):
        assert_urls_allowed(
            ["http://169.254.169.254/latest/meta-data"],
            allowed_hosts=["169.254.169.254"],
        )


def test_login_url_must_also_pass_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "backend.utilities.dast.ssrf._resolve_ips",
        lambda host: ["1.2.3.4"] if host == "demo.testfire.net" else ["9.9.9.9"],
    )
    with pytest.raises(DastSsrfError, match="not in allowlist"):
        assert_urls_allowed(
            ["https://demo.testfire.net/", "https://other.example/login"],
            allowed_hosts=["demo.testfire.net"],
        )
