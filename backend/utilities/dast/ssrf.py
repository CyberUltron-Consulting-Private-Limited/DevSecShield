"""SSRF / host-allowlist checks for every DAST target: automatic profiles, CI runs and manual scans (estimate and start).

One rule for all of them (found on the local stack, round 5: manual estimate/start had no check at all, and the
DAST worker crawled http://backend:8080 and accepted http://169.254.169.254 on a customer's say-so):

* only http:// and https:// URLs;
* every URL's host must be in scope: a profile's ``allowed_hosts``, else the target URL's own host;
* the host name is resolved and EVERY address it resolves to is checked (a literal address is checked as it is)
  against the address rule in ``address_rule.py``: metadata/link-local refused always; private, loopback, reserved
  and CGNAT only with the operator's ``DAST_ALLOWED_PRIVATE``. A customer's ``allowed_hosts`` narrows the scope; it
  can never open a private address.

The DAST worker applies the same rule again when it connects (``address_rule.py`` is byte-identical in
RabbitMQ/dast_worker/helpers/net/): it resolves each in-scope host once, checks it, and pins every connection of the
scan to the checked addresses, so a DNS answer that changes after this check (DNS rebinding) is never followed.
"""
from __future__ import annotations

import os

from backend.utilities.dast.address_rule import (
    ENV_ALLOWED_PRIVATE,
    DastSsrfError,
    OperatorAllowlist,
    check_address,
    check_scheme,
    checked_addresses,
    host_from_url,
    literal_address,
    parse_allowlist,
    system_resolve,
)

__all__ = [
    "ENV_ALLOWED_PRIVATE", "DastSsrfError", "assert_manual_dast_allowed", "assert_urls_allowed", "dast_target_urls",
    "host_from_url", "operator_allowlist",
]


def operator_allowlist() -> OperatorAllowlist:
    """The operator's DAST_ALLOWED_PRIVATE (read on every call: tests and operators change it)."""
    rules = parse_allowlist(os.environ.get(ENV_ALLOWED_PRIVATE))
    if rules.ignored:
        from backend.utilities.cbom_sources.common import log

        for entry in rules.ignored:
            log("WARNING private_allowlist entry_ignored", source=ENV_ALLOWED_PRIVATE, entry=repr(entry))
    return rules


def _resolve_ips(host: str) -> list[str]:
    return system_resolve(host)


def assert_urls_allowed(urls: list[str], allowed_hosts: list[str]) -> None:
    allowed = {h.lower().strip().rstrip(".") for h in (allowed_hosts or []) if h and h.strip()}
    if not allowed:
        raise DastSsrfError("allowed_hosts is empty")
    rules = operator_allowlist()

    for raw in urls:
        if not raw or not str(raw).strip():
            continue
        check_scheme(raw)
        host = host_from_url(raw)
        literal = literal_address(host)
        if literal is not None:
            check_address(host, str(literal), True, rules)
        if host not in allowed:
            raise DastSsrfError(f"Host {host} is not in allowlist")
        checked_addresses(host, rules, lambda name: _resolve_ips(name))


def dast_target_urls(target_url: str, login_url: str | None, additional_urls: list[str] | None) -> list[str]:
    """Every URL of a DAST run the worker will open."""
    return [u for u in [target_url, login_url or "", *(additional_urls or [])] if u and str(u).strip()]


def assert_manual_dast_allowed(target_url: str, login_url: str | None, additional_urls: list[str] | None) -> None:
    """A manual DAST scan (estimate or start) follows the profile rule with the default scope: the target's host."""
    check_scheme(target_url)
    assert_urls_allowed(dast_target_urls(target_url, login_url, additional_urls), [host_from_url(target_url)])
