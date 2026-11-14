"""#126 (review of #161): the Jira SSRF guard let CGNAT and other non-global addresses through. ``validate_jira_url``
now asks every resolved address the same question as every other integration (``outbound.check_address``): loopback,
link-local, metadata (Alibaba's 100.100.100.200), CGNAT 100.64/10, NAT64 and reserved addresses are never allowed;
private ones only when the operator lists them in INTEGRATION_ALLOWED_PRIVATE; public ones pass."""
from __future__ import annotations

import socket

import pytest

from backend.utilities.integrations import jira as J
from backend.utilities.integrations import outbound


def _resolving(monkeypatch, *addresses: str):
    def fake(host, port, *a, **kw):
        out = []
        for addr in addresses:
            fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
            out.append((fam, socket.SOCK_STREAM, 6, "", (addr, 0, 0, 0) if fam == socket.AF_INET6 else (addr, 0)))
        return out

    monkeypatch.setattr(J.socket, "getaddrinfo", fake)


@pytest.mark.parametrize("address", [
    "100.64.0.1",          # CGNAT (RFC 6598)
    "100.100.100.200",     # Alibaba Cloud metadata (inside CGNAT)
    "100.127.255.254",     # CGNAT, top
    "64:ff9b::a9fe:a9fe",  # NAT64 of 169.254.169.254
    "::ffff:169.254.169.254",
    "192.0.0.8",           # IETF protocol assignments
    "240.0.0.1",           # reserved
])
def test_non_global_addresses_are_refused_even_with_an_ordinary_name(monkeypatch, address):
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    _resolving(monkeypatch, address)
    with pytest.raises(ValueError, match="never allowed"):
        J.validate_jira_url("https://jira.example.com")


def test_one_bad_address_among_good_ones_refuses_the_name(monkeypatch):
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    _resolving(monkeypatch, "8.8.8.8", "100.64.0.1")
    with pytest.raises(ValueError):
        J.validate_jira_url("https://bank.atlassian.net")


def test_a_public_jira_passes(monkeypatch):
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    _resolving(monkeypatch, "104.192.141.1", "2401:1d80:1010::150")
    assert J.validate_jira_url("https://bank.atlassian.net") is True


def test_a_private_jira_needs_the_operator_allowlist_and_cgnat_stays_refused_even_then(monkeypatch):
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    _resolving(monkeypatch, "10.20.0.5")
    with pytest.raises(ValueError, match="private"):
        J.validate_jira_url("https://jira.bank.local")
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "10.20.0.0/16")
    assert J.validate_jira_url("https://jira.bank.local") is True  # .local is fine once the operator lists it
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "0.0.0.0/0")
    _resolving(monkeypatch, "100.100.100.200")
    with pytest.raises(ValueError, match="never allowed"):
        J.validate_jira_url("https://jira.example.com")


def test_internal_names_resolving_to_public_addresses_are_still_refused(monkeypatch):
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    _resolving(monkeypatch, "8.8.8.8")
    with pytest.raises(ValueError, match="internal domain"):
        J.validate_jira_url("https://metadata.google.internal")
