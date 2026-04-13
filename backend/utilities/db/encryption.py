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


def decrypt_value(ciphertext: str) -> str:
    """
    Decrypt a base64-encoded ciphertext and return plaintext.
    Returns empty string if input is empty/None.
    Raises ValueError if decryption fails (invalid key or corrupted data).
    """
    if not ciphertext:
        return ""
    
    fernet = _get_fernet()
    try:
        # Decode from our outer base64 encoding
        encrypted_bytes = base64.urlsafe_b64decode(ciphertext.encode("utf-8"))
        plaintext_bytes = fernet.decrypt(encrypted_bytes)
        return plaintext_bytes.decode("utf-8")
    except InvalidToken as e:
        logger.error("Failed to decrypt value: invalid token or key mismatch")
        raise ValueError("Decryption failed: invalid token or key") from e
    except Exception as e:
        logger.error(f"Failed to decrypt value: {type(e).__name__}")
        raise ValueError(f"Decryption failed: {type(e).__name__}") from e


def is_encrypted(value: str) -> bool:
    """
    Check if a value appears to be encrypted (heuristic based on format).
    Encrypted values are base64 and start with 'gAAAAA' (Fernet format).
    """
    if not value or len(value) < 50:
        return False
    
    try:
        decoded = base64.urlsafe_b64decode(value.encode("utf-8"))
        # Fernet tokens start with version byte 0x80 followed by timestamp
        return decoded[:1] == b'\x80' or value.startswith('gAAAAA')
    except Exception:
        return False


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
