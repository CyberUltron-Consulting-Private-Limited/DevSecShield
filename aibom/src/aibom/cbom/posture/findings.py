"""Posture finding catalog. Verdict-derived codes stay empty on UNKNOWN."""

from __future__ import annotations

from collections.abc import Mapping

POSTURE_CODES = frozenset(
    {
        "UNENCRYPTED_AT_REST",
        "UNENCRYPTED_IN_TRANSIT",
        "PLAINTEXT_LISTENER",
        "TLS_VERIFICATION_DISABLED",
        "DOWNGRADE_PROTECTION_MISSING",
        "KNOWN_TLS_VULNERABILITY",
        "KMS_KEY_ROTATION_DISABLED",
        "KMS_KEY_POLICY_PUBLIC",
        "KMS_KEY_DELETION_UNPROTECTED",
        "AT_REST_ENCRYPTION_WEAK",
        # Stored data encrypted only by the provider's default, with a key the provider owns and manages (no key
        # choice declared). RBI, CERT-In and NIST SP 800-57 expect key custody under the organisation's control
        # (customer-managed / BYOK keys) for regulated data; Low, because the data is encrypted.
        "PROVIDER_MANAGED_KEY",
        # A Dockerfile builds on a base image whose distribution release is past its end of life.
        "EOL_BASE_IMAGE",
    }
)

VERDICT_DERIVED = frozenset(
    {
        "UNENCRYPTED_AT_REST",
        "UNENCRYPTED_IN_TRANSIT",
        "PLAINTEXT_LISTENER",
    }
)

SIGNAL_DERIVED = POSTURE_CODES - VERDICT_DERIVED

SEVERITY = {
    "UNENCRYPTED_AT_REST": "error",
    "UNENCRYPTED_IN_TRANSIT": "error",
    "PLAINTEXT_LISTENER": "warning",
    "TLS_VERIFICATION_DISABLED": "error",
    "DOWNGRADE_PROTECTION_MISSING": "warning",
    "KNOWN_TLS_VULNERABILITY": "error",
    "KMS_KEY_ROTATION_DISABLED": "warning",
    "KMS_KEY_POLICY_PUBLIC": "error",
    "KMS_KEY_DELETION_UNPROTECTED": "note",
    "AT_REST_ENCRYPTION_WEAK": "warning",
    "PROVIDER_MANAGED_KEY": "note",
    "EOL_BASE_IMAGE": "warning",
}

WEIGHT = {
    "error": 8,
    "warning": 4,
    "note": 1,
}


def derive_findings(fact: object, scored: Mapping[str, bool]) -> tuple[str, ...]:
    """Return sorted codes. ``scored`` holds explicit signals, not the verdict."""
    verdict = getattr(fact, "verdict", None)
    codes: list[str] = []
    if verdict != "UNKNOWN":
        if verdict == "NOT_ENCRYPTED" and scored.get("at_rest"):
            codes.append("UNENCRYPTED_AT_REST")
        if verdict == "NOT_ENCRYPTED" and scored.get("in_transit"):
            codes.append("UNENCRYPTED_IN_TRANSIT")
        if scored.get("plaintext_listener") and verdict == "NOT_ENCRYPTED":
            codes.append("PLAINTEXT_LISTENER")
    for code in sorted(SIGNAL_DERIVED):
        if scored.get(code) and not scored.get(f"{code}:unresolved"):
            codes.append(code)
    return tuple(codes)
