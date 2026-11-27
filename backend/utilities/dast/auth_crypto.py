"""Encrypt / decrypt / redact DAST login credentials (password, session import, OTP form)."""
from __future__ import annotations

from typing import Any

from backend.utilities.db.encryption import decrypt_value, encrypt_value

SECRET_AUTH_KEYS: tuple[str, ...] = (
    "password",
    "session_cookie",
    "auth_header_value",
    "local_storage_json",
    "session_storage_json",
    "otp_code",
    "totp_secret",
    "mpin",
)
_SECRET_SET = frozenset(SECRET_AUTH_KEYS)

PUBLIC_AUTH_KEYS: tuple[str, ...] = (
    "auth_type",
    "login_url",
    "xpath_of_username_field",
    "xpath_of_password_field",
    "username",
    "xpath_of_submit_button",
    "auth_header_name",
    "session_check_url",
    "logged_in_indicator",
    "xpath_of_send_otp_button",
    "xpath_of_otp_field",
    "otp_source",
    "xpath_of_mpin_field",
    "xpath_of_mpin_submit_button",
)

_LEGACY_KEYS: tuple[str, ...] = (
    "login_url",
    "xpath_of_username_field",
    "xpath_of_password_field",
    "username",
    "password",
    "xpath_of_submit_button",
)

_AUTH_KEYS: tuple[str, ...] = PUBLIC_AUTH_KEYS + SECRET_AUTH_KEYS


def _selected_keys(auth: dict[str, Any]) -> tuple[str, ...]:
    auth_type = auth.get("auth_type")
    if not auth_type or auth_type == "password":
        extras = tuple(k for k in _AUTH_KEYS if k not in _LEGACY_KEYS and auth.get(k) is not None)
        return _LEGACY_KEYS + extras
    return tuple(k for k in _AUTH_KEYS if k == "auth_type" or auth.get(k) is not None)


def encrypt_auth(auth: dict[str, Any]) -> dict[str, Any]:
    out = {k: auth.get(k) for k in _selected_keys(auth)}
    for secret_key in SECRET_AUTH_KEYS:
        val = out.get(secret_key)
        if val:
            try:
                decrypt_value(str(val))
            except (ValueError, Exception):
                out[secret_key] = encrypt_value(str(val))
    return out


def decrypt_auth(auth: dict[str, Any]) -> dict[str, Any]:
    out = {k: auth.get(k) for k in _selected_keys(auth)}
    for secret_key in SECRET_AUTH_KEYS:
        val = out.get(secret_key)
        if val:
            try:
                out[secret_key] = decrypt_value(str(val))
            except ValueError:
                pass
    return out


def redact_auth(auth: dict[str, Any] | None) -> dict[str, Any] | None:
    if not auth:
        return auth
    return {k: v for k, v in auth.items() if k not in _SECRET_SET}


def redact_scan_metadata(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    if not meta:
        return meta
    out = dict(meta)
    if isinstance(out.get("auth"), dict):
        out["auth"] = redact_auth(out["auth"])
    return out
