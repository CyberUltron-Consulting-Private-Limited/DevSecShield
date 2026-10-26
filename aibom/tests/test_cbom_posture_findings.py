"""Finding derivation. UNKNOWN drops only the verdict-derived codes."""

from types import SimpleNamespace

from aibom.cbom.posture.findings import POSTURE_CODES, VERDICT_DERIVED, derive_findings
from aibom.cbom.weakness import WEAK_CRYPTO_CODES


def test_catalog_is_the_ten_codes() -> None:
    assert len(POSTURE_CODES) == 10
    assert POSTURE_CODES.isdisjoint(WEAK_CRYPTO_CODES)


def test_unknown_verdict_emits_no_verdict_code() -> None:
    fact = SimpleNamespace(verdict="UNKNOWN")
    scored = {"at_rest": True, "in_transit": True, "plaintext_listener": True}
    assert derive_findings(fact, scored) == ()


def test_signal_fires_on_an_explicit_signal_even_when_unknown() -> None:
    fact = SimpleNamespace(verdict="UNKNOWN")
    scored = {"TLS_VERIFICATION_DISABLED": True}
    assert derive_findings(fact, scored) == ("TLS_VERIFICATION_DISABLED",)


def test_unresolved_finding_default_does_not_fire() -> None:
    fact = SimpleNamespace(verdict="UNKNOWN")
    scored = {
        "KMS_KEY_ROTATION_DISABLED": True,
        "KMS_KEY_ROTATION_DISABLED:unresolved": True,
    }
    assert derive_findings(fact, scored) == ()


def test_verdict_codes_are_the_three_named_ones() -> None:
    expected = {
        "UNENCRYPTED_AT_REST",
        "UNENCRYPTED_IN_TRANSIT",
        "PLAINTEXT_LISTENER",
    }
    assert expected == VERDICT_DERIVED
