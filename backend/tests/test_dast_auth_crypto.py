"""Hermetic Fernet helpers for DAST profile auth (password never stored plaintext)."""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("JWT_SECRET_KEY", "dast-auto-test-secret-not-for-prod")

from backend.utilities.dast.auth_crypto import (  # noqa: E402
    decrypt_auth,
    encrypt_auth,
    redact_auth,
)


_PLAIN = {
    "login_url": "https://demo.testfire.net/login.jsp",
    "xpath_of_username_field": "//input[@name='uid']",
    "xpath_of_password_field": "//input[@name='passw']",
    "username": "jsmith",
    "password": "demo123",
    "xpath_of_submit_button": "//input[@type='submit']",
}


def test_encrypt_auth_does_not_store_plaintext_password() -> None:
    stored = encrypt_auth(_PLAIN)
    assert stored["username"] == "jsmith"
    assert stored["password"] != "demo123"
    assert "demo123" not in str(stored)


def test_decrypt_auth_roundtrip() -> None:
    stored = encrypt_auth(_PLAIN)
    out = decrypt_auth(stored)
    assert out["password"] == "demo123"
    assert out["login_url"] == _PLAIN["login_url"]


def test_redact_auth_drops_password() -> None:
    redacted = redact_auth(_PLAIN)
    assert "password" not in redacted
    assert redacted["username"] == "jsmith"
    assert redacted["login_url"] == _PLAIN["login_url"]


def test_redact_encrypted_blob_never_exposes_password() -> None:
    stored = encrypt_auth(_PLAIN)
    redacted = redact_auth(stored)
    assert "password" not in redacted
    assert "demo123" not in str(redacted)
