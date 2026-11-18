"""The address rule for the URLs an MCP or custom LLM scan connects to (issue #53).

An MCP scan's ``server_url`` and a custom LLM scan's ``model_uri`` are customer input the scan worker connects to. They
had no address rule, so a scan could make the worker reach the cloud metadata service (169.254.169.254) or a service
on the stack's private network. They now follow the CBOM SSRF guard's rule (``cbom_sources/address_rule.py``, the rule
``safe_fetch.py`` runs, reused here, not re-implemented) before the API estimates, charges for or dispatches a scan:

* an http:// or https:// URL with a host (the scheme the MCP and LLM clients speak; ports are not restricted);
* the host is resolved and EVERY address it resolves to must be public: not private (RFC 1918, unique-local fc00::/7,
  site-local), loopback, link-local (the metadata service), CGNAT, unspecified, multicast, reserved, or an IPv4-mapped
  or translated form of one. One refused address refuses the URL: DNS may hand that address out later;
* no operator allowlist: the product has no documented setting that opens private addresses to these scans
  (``CBOM_IDP_ALLOWED_PRIVATE`` and ``CBOM_LAB_ALLOW_PRIVATE_FETCH`` are for CBOM metadata fetches only).

The worker runs the same file again when it connects (``RabbitMQ/worker/helpers/net/guard.py``): DNS can answer
differently by then, and a server can redirect.
"""
from __future__ import annotations

from backend.utilities.cbom_sources import address_rule as AR


class TargetAddressRefused(ValueError):
    """``str(err)`` is safe to show to the customer: it names only the host they entered."""


def check_scan_target(url: str | None, what: str) -> list[str]:
    """The checked addresses of ``url``'s host, or TargetAddressRefused. ``what`` names the field in the message."""
    try:
        host, port = AR.scan_target(url)
    except AR.TargetURLError as exc:
        raise TargetAddressRefused(f"{what} {exc}") from None
    try:
        return AR.checked_addresses(host, port)
    except AR.Unresolvable:
        raise TargetAddressRefused(f"{what}: {host} does not resolve") from None
    except AR.AddressRefused as exc:  # "<host> resolves to a private or reserved address"
        raise TargetAddressRefused(f"{what}: {exc}; only public addresses can be scanned") from None
    except ValueError:  # UnicodeError from IDNA (a label over 63 characters, an empty label) and the like
        raise TargetAddressRefused(f"{what}: {host[:100]} is not a valid host name") from None


__all__ = ["TargetAddressRefused", "check_scan_target"]
