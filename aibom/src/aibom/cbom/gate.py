"""CI gate for the code and dependency scan.

High findings fail ``aibom cbom``. Quantum-vulnerable and custom-crypto
findings are reported and do not fail the build.
"""

from __future__ import annotations

from collections.abc import Iterable

from aibom.model.result import Flag

VULNERABLE_CRYPTO_LIBRARY = "VULNERABLE_CRYPTO_LIBRARY"
CUSTOM_CRYPTO = "CUSTOM_CRYPTO"

# The high set agreed for the code scanner. REUSED_NONCE is the static-IV
# case that covers more than one encryption.
FAIL_CODES = frozenset(
    {
        "WEAK_ALGORITHM",
        "WEAK_CIPHER_MODE",
        "WEAK_KEY_SIZE",
        "HARDCODED_KEY",
        "STATIC_IV",
        "REUSED_NONCE",
        "WEAK_RNG",
        "WEAK_PADDING",
        "TLS_VERIFICATION_DISABLED",
        VULNERABLE_CRYPTO_LIBRARY,
    }
)


def failing_flags(flags: Iterable[Flag]) -> list[Flag]:
    """Flags whose code is in the CI fail set, in input order."""
    return [flag for flag in flags if flag.code in FAIL_CODES]
