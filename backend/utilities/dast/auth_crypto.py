"""Encrypt / decrypt / redact DAST login credentials."""
from __future__ import annotations

from typing import Any

from backend.utilities.db.encryption import decrypt_value, encrypt_value

_AUTH_KEYS = (
    "login_url",
    "xpath_of_username_field",
    "xpath_of_password_field",
    "username",
    "password",
    "xpath_of_submit_button",
)


def encrypt_auth(auth: dict[str, Any]) -> dict[str, Any]:
    out = {k: auth.get(k) for k in _AUTH_KEYS}
    password = out.get("password") or ""
    if password:
        try:
            decrypt_value(str(password))
        except (ValueError, Exception):
            out["password"] = encrypt_value(str(password))
    return out


def decrypt_auth(auth: dict[str, Any]) -> dict[str, Any]:
    out = {k: auth.get(k) for k in _AUTH_KEYS}
    password = out.get("password") or ""
    if password:
        try:
            out["password"] = decrypt_value(str(password))
        except ValueError:
            pass
    return out


def redact_auth(auth: dict[str, Any] | None) -> dict[str, Any] | None:
    if not auth:
        return auth
    return {k: v for k, v in auth.items() if k != "password"}


def redact_scan_metadata(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    if not meta:
        return meta
    out = dict(meta)
    if isinstance(out.get("auth"), dict):
        out["auth"] = redact_auth(out["auth"])
    return out
