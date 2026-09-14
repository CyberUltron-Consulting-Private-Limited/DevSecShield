"""
Fernet-based encryption for sensitive fields (API keys, tokens, credentials).
Uses environment variable ENCRYPTION_KEY or generates a secure key.
"""
import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    """
    Get or create a Fernet instance using the ENCRYPTION_KEY env var.
    If not set, derives a key from JWT_SECRET_KEY (both must be 256-bit secure).
    """
    key = os.environ.get("ENCRYPTION_KEY")
    
    if key:
        # If provided as a raw key, ensure it's Fernet-compatible (32 bytes, base64-encoded)
        try:
            # Try to use it directly if it's already Fernet-formatted
            return Fernet(key.encode() if isinstance(key, str) else key)
        except Exception:
            # If not valid Fernet key, derive one from the provided key
            pass
    
    # Fallback: derive from JWT_SECRET_KEY
    jwt_secret = os.environ.get("JWT_SECRET_KEY")
    if not jwt_secret:
        raise RuntimeError(
            "Neither ENCRYPTION_KEY nor JWT_SECRET_KEY is set. "
            "Cannot initialize encryption."
        )
    
    # Derive a 32-byte key using SHA-256
    derived = hashlib.sha256(jwt_secret.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(derived)
    return Fernet(fernet_key)


def encrypt_value(plaintext: str) -> str:
    """
    Encrypt a plaintext string and return base64-encoded ciphertext.
    Returns empty string if input is empty/None.
    """
    if not plaintext:
        return ""
    
    fernet = _get_fernet()
    ciphertext = fernet.encrypt(plaintext.encode("utf-8"))
    return base64.urlsafe_b64encode(ciphertext).decode("utf-8")


def _fernet_token_candidates(ciphertext: str) -> list[bytes]:
    """
    encrypt_value() wraps a Fernet token in an extra urlsafe-b64 layer.
    Older rows may store the raw Fernet token (prefix gAAAAA). Try both.
    """
    raw = ciphertext.encode("utf-8")
    candidates = [raw]
    try:
        unwrapped = base64.urlsafe_b64decode(raw)
        if unwrapped and unwrapped != raw:
            candidates.append(unwrapped)
    except Exception:
        pass
    return candidates


def decrypt_value(ciphertext: str) -> str:
    """
    Decrypt a stored secret and return plaintext.
    Accepts both encrypt_value() output (outer urlsafe-b64 + Fernet) and a raw Fernet token.
    Returns empty string if input is empty/None.
    Raises ValueError if decryption fails (invalid key or corrupted data).
    """
    if not ciphertext:
        return ""

    fernet = _get_fernet()
    last_error: Exception | None = None
    for token in _fernet_token_candidates(ciphertext):
        try:
            return fernet.decrypt(token).decode("utf-8")
        except InvalidToken as e:
            last_error = e
        except Exception as e:
            last_error = e
    logger.error("Failed to decrypt value: invalid token or key mismatch")
    raise ValueError("Decryption failed: invalid token or key") from last_error


def is_encrypted(value: str) -> bool:
    """
    True when `value` decrypts with the current key.

    Prefix heuristics are not enough: encrypt_value() double-encodes Fernet
    tokens so they start with Z0FBQU... rather than gAAAAA. A plaintext
    Atlassian API token must not be treated as ciphertext.
    """
    if not value or len(value) < 50:
        return False
    try:
        decrypt_value(value)
        return True
    except Exception:
        return False


# GET /team masks api_token as this exact string. Re-saving settings must not
# encrypt the mask and wipe the real token.
SECRET_PLACEHOLDER = "••••••••"


def is_secret_placeholder(value: str | None) -> bool:
    if value is None:
        return True
    stripped = value.strip()
    return (not stripped) or stripped == SECRET_PLACEHOLDER


def decrypt_if_encrypted(value: str | None) -> str:
    """Return plaintext for a stored secret (encrypted or legacy plaintext)."""
    if not value:
        return ""
    if is_encrypted(value):
        return decrypt_value(value)
    return value


def prepare_secret_for_storage(new_value: str | None, existing_value: str | None = None) -> str:
    """
    Encrypt a newly submitted secret, or keep the existing ciphertext when the
    client echoed the masked placeholder / left the field blank.
    """
    if is_secret_placeholder(new_value):
        return existing_value or ""
    if is_encrypted(new_value):
        return new_value or ""
    return encrypt_value(new_value or "")


def encrypt_if_not_encrypted(value: str) -> str:
    """
    Encrypt a value only if it's not already encrypted.
    Useful for migration scenarios.
    """
    if not value:
        return ""
    if is_encrypted(value):
        return value
    return encrypt_value(value)


def rotate_encryption_key(old_key: str, new_key: str, ciphertext: str) -> str:
    """
    Re-encrypt a value with a new key.
    Useful for key rotation scenarios.
    """
    if not ciphertext:
        return ""
    
    # Create Fernet with old key
    old_derived = hashlib.sha256(old_key.encode()).digest()
    old_fernet = Fernet(base64.urlsafe_b64encode(old_derived))
    
    # Decrypt with old key
    encrypted_bytes = base64.urlsafe_b64decode(ciphertext.encode("utf-8"))
    plaintext = old_fernet.decrypt(encrypted_bytes).decode("utf-8")
    
    # Create Fernet with new key and encrypt
    new_derived = hashlib.sha256(new_key.encode()).digest()
    new_fernet = Fernet(base64.urlsafe_b64encode(new_derived))
    new_ciphertext = new_fernet.encrypt(plaintext.encode("utf-8"))
    
    return base64.urlsafe_b64encode(new_ciphertext).decode("utf-8")


# Migration helper
def migrate_plaintext_to_encrypted(plaintext_api_key: str) -> str:
    """
    Migrate a plaintext API key to encrypted format.
    This is a convenience wrapper for encrypt_if_not_encrypted.
    """
    return encrypt_if_not_encrypted(plaintext_api_key)
