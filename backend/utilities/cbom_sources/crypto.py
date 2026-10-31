"""Secret storage for CBOM sources and scrubbing of anything that comes back from a scan node.

Secrets for one source are kept as one Fernet token over a JSON object (``encrypt_value`` from
``backend/utilities/db/encryption.py``, key ``ENCRYPTION_KEY``).  They are decrypted in exactly one
place: when the scan node that owns the source claims a job for it (``jobs.claim_next``).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

from cryptography.fernet import Fernet

from backend.utilities.cbom_sources.common import log
from backend.utilities.db.encryption import decrypt_value, encrypt_value

# A private-key block is removed up to its END line, or to the end of the text when it was truncated.
_PEM_PRIVATE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.DOTALL
)
# ZeroShield tokens, HashiCorp Vault tokens and AWS session tokens.
_TOKENS = re.compile(r"\bzs[rnv]_[A-Za-z0-9_-]{16,}|\bhv[sbr]\.[A-Za-z0-9_-]{20,}|(?:IQoJb3JpZ2lu|FwoGZXIvYXdz)[A-Za-z0-9/+=]{40,}")
_SECRET_KEYS = re.compile(r"(password|passwd|secret|token|private_key|privatekey|kubeconfig|api_key|apikey|credential)", re.I)
# Collected facts legitimately use words like "password_encryption" or "token_endpoint", so for them only
# these exact keys are value-redacted.
_SECRET_KEYS_EXACT = frozenset({
    "password", "passwd", "client_secret", "private_key", "privatekey", "requirepass", "masterauth",
    "authentication_string", "tls-key-file-pass", "kubeconfig", "api_key", "apikey", "secret_value", "token",
    "access_token", "refresh_token", "session_token", "secret_access_key", "tls.key",
})
REDACTED = "[redacted]"
_warned = False


def warn_if_key_is_weak() -> None:
    """Say loudly (once) when stored credentials depend on the JWT secret instead of ENCRYPTION_KEY."""
    global _warned
    if _warned:
        return
    _warned = True
    key = os.environ.get("ENCRYPTION_KEY") or ""
    try:
        Fernet(key.encode())
        return
    except Exception:
        log("WARNING encryption_key=missing_or_invalid fallback=jwt_secret_key")


def encrypt_secrets(values: dict[str, str]) -> str | None:
    clean = {k: v for k, v in values.items() if isinstance(v, str) and v != ""}
    if not clean:
        return None
    return encrypt_value(json.dumps(clean, separators=(",", ":"), sort_keys=True))


def decrypt_secrets(blob: str | None) -> dict[str, str]:
    if not blob:
        return {}
    data = json.loads(decrypt_value(blob))
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def scrub(value: Any, known_secrets: list[str] | None = None, *, depth: int = 0, exact_keys: bool = False) -> Any:
    """Remove secret values, private-key blocks and tokens from untrusted node output.

    ``exact_keys`` redacts only values under the exact secret key names (for collected facts, where
    ``password_encryption: md5`` is a finding, not a secret); otherwise any key that looks secret is.
    """
    if depth > 12:
        return None
    secrets_ = [s for s in (known_secrets or []) if isinstance(s, str) and len(s) >= 4]
    if isinstance(value, str):
        text = _PEM_PRIVATE.sub(REDACTED, value)
        text = _TOKENS.sub(REDACTED, text)
        for secret in secrets_:
            if secret in text:
                text = text.replace(secret, REDACTED)
        return text.replace("\x00", "")
    if isinstance(value, dict):
        out = {}
        for key, item in list(value.items())[:500]:
            name = str(key)[:128]
            secret_key = name.lower() in _SECRET_KEYS_EXACT if exact_keys else bool(_SECRET_KEYS.search(name))
            if secret_key and isinstance(item, str):
                out[name] = REDACTED
            else:
                out[name] = scrub(item, secrets_, depth=depth + 1, exact_keys=exact_keys)
        return out
    if isinstance(value, list):
        return [scrub(item, secrets_, depth=depth + 1, exact_keys=exact_keys) for item in value[:2000]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1000]
