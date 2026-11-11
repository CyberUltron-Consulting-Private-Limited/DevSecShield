"""Shared fixtures for the hermetic DAST worker tests."""
import pytest

import helpers.agent.main as agent_main
from helpers.net.address_rule import parse_allowlist
from helpers.net.egress import ScanEgress


@pytest.fixture(autouse=True)
def _scan_hosts_resolve_to_a_public_address(monkeypatch):
    """DASTAgent.run() checks and pins its hosts before any connection (helpers/net/egress.py). These tests have no
    DNS (example.com, shop.test): pin every host to a public documentation address. test_egress_pinning.py tests the
    rule and the pinning themselves with explicit fake resolvers."""
    monkeypatch.setattr(
        agent_main, "ScanEgress",
        lambda urls: ScanEgress(urls, rules=parse_allowlist(""), resolve=lambda _host: ["93.184.216.34"]),
    )
