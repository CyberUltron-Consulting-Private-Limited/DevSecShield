"""The explicit BOM signing key of the tests (D5, review 6026853603).

``bom_signing`` refuses to derive a key from a short or placeholder secret, so a test that needs signed output uses
this fixture key instead of relying on whatever ``CERTIN_HMAC_SECRET`` the environment holds. The key is given as
``CBOM_SIGNING_KEY_PEM`` (the configured-key path), built from a public, test-only seed: nothing secret is committed,
no PEM sits in the repository for secret scanners to flag, and ``bom_signing.weak_seed`` refuses the seed itself
("tests-only"), so no deployment can derive this key from ``CERTIN_HMAC_SECRET`` by accident.
"""
from __future__ import annotations

from backend.utilities.cbom_sources import bom_signing as SIGN

FIXTURE_SEED = "zeroshield-tests-only-bom-signing-fixture-seed-v1-public"  # public by design: tests only
FIXTURE_KID = "zs-tests-fixture"


def fixture_pem() -> str:
    from cryptography.hazmat.primitives import serialization

    key = SIGN._derive(FIXTURE_SEED, 1)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")


def use_fixture_key(monkeypatch) -> SIGN.KeyRing:
    """Clear every signing variable, then configure the fixture key; returns the key ring."""
    for name in SIGN._ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CBOM_SIGNING_KEY_PEM", fixture_pem())
    monkeypatch.setenv("CBOM_SIGNING_KEY_ID", FIXTURE_KID)
    SIGN._CACHE.clear()
    return SIGN.keyring()
