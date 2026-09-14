"""Hermetic tests for Jira API-token storage used by team settings + create_ticket."""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("JWT_SECRET_KEY", "jira-ticketing-test-secret-not-for-prod")

from backend.utilities.db.encryption import (  # noqa: E402
    SECRET_PLACEHOLDER,
    decrypt_if_encrypted,
    decrypt_value,
    encrypt_value,
    is_encrypted,
    is_secret_placeholder,
    prepare_secret_for_storage,
)

# Shape-similar to an Atlassian API token (not a real credential).
_PLAIN = "ATATT3xFfGF0" + ("A" * 80) + "=21DD4020"


def test_encrypt_roundtrip_is_detected_as_encrypted() -> None:
    stored = encrypt_value(_PLAIN)
    assert stored != _PLAIN
    assert not stored.startswith("gAAAAA")
    assert is_encrypted(stored)
    assert decrypt_value(stored) == _PLAIN
    assert decrypt_if_encrypted(stored) == _PLAIN


def test_create_ticket_path_decrypts_stored_token() -> None:
    stored = prepare_secret_for_storage(_PLAIN, existing_value=None)
    used = decrypt_if_encrypted(stored)
    assert used == _PLAIN
    assert used != stored


def test_plaintext_atlassian_token_is_not_treated_as_ciphertext() -> None:
    assert not is_encrypted(_PLAIN)
    assert decrypt_if_encrypted(_PLAIN) == _PLAIN


def test_placeholder_keeps_existing_ciphertext() -> None:
    stored = prepare_secret_for_storage(_PLAIN)
    again = prepare_secret_for_storage(SECRET_PLACEHOLDER, existing_value=stored)
    assert again == stored
    assert decrypt_if_encrypted(again) == _PLAIN


def test_empty_token_keeps_existing() -> None:
    stored = prepare_secret_for_storage(_PLAIN)
    again = prepare_secret_for_storage("", existing_value=stored)
    assert again == stored


def test_placeholder_helper() -> None:
    assert is_secret_placeholder(SECRET_PLACEHOLDER)
    assert is_secret_placeholder("")
    assert is_secret_placeholder(None)
    assert not is_secret_placeholder(_PLAIN)
