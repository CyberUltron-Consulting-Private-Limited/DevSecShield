"""Request/response schemas for automatic DAST profiles and CI."""
from __future__ import annotations

import base64
import json
import re
from typing import Literal

from pydantic import BaseModel, Field, model_validator

ScheduleKind = Literal[
    "off",
    "hourly",
    "every_n_hours",
    "daily",
    "weekdays",
    "weekly",
    "monthly",
    "once",
    "cron",
]

DastAuthType = Literal["password", "session", "otp_form"]
DastOtpSource = Literal["static", "totp"]

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
_FORBIDDEN_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection", "cookie"})
_MAX_STORAGE_JSON_BYTES = 65_536


def _has_text(val: str | None) -> bool:
    return bool(val and str(val).strip())


def _reject_crlf(val: str | None, label: str) -> None:
    if val and ("\r" in val or "\n" in val):
        raise ValueError(f"{label} must not contain newline characters")


def validate_storage_json(raw: str | None, label: str) -> None:
    if not _has_text(raw):
        return
    assert raw is not None
    if len(raw.encode("utf-8")) > _MAX_STORAGE_JSON_BYTES:
        raise ValueError(f"{label} exceeds {_MAX_STORAGE_JSON_BYTES} bytes")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be a valid JSON object") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be a JSON object mapping key names to string values")
    for k, v in parsed.items():
        if not isinstance(k, str) or not k.strip():
            raise ValueError(f"{label} keys must be non-empty strings")
        if not isinstance(v, (str, int, float, bool)):
            raise ValueError(f"{label}[{k!r}] must be a string or primitive value")


def validate_totp_secret(secret: str | None) -> None:
    if not _has_text(secret):
        raise ValueError("TOTP secret is required when otp_source is 'totp'")
    assert secret is not None
    cleaned = re.sub(r"[\s-]+", "", secret).upper()
    if len(cleaned) < 8:
        raise ValueError("TOTP secret is too short (expected Base32 secret)")
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        raw = base64.b32decode(cleaned + pad, casefold=True)
    except Exception as exc:
        raise ValueError("TOTP secret must be valid Base32") from exc
    if not raw:
        raise ValueError("TOTP secret must not be empty")


def validate_auth_fields(
    *,
    auth_type: DastAuthType,
    login_url: str | None,
    xpath_of_username_field: str | None,
    xpath_of_password_field: str | None,
    username: str | None,
    password: str | None,
    xpath_of_submit_button: str | None,
    session_cookie: str | None,
    auth_header_name: str | None,
    auth_header_value: str | None,
    local_storage_json: str | None,
    session_storage_json: str | None,
    xpath_of_otp_field: str | None,
    otp_source: DastOtpSource | None,
    otp_code: str | None,
    totp_secret: str | None,
    mpin: str | None,
    xpath_of_mpin_field: str | None,
    require_secrets: bool,
) -> None:
    _reject_crlf(session_cookie, "session_cookie")
    _reject_crlf(auth_header_name, "auth_header_name")
    _reject_crlf(auth_header_value, "auth_header_value")
    validate_storage_json(local_storage_json, "local_storage_json")
    validate_storage_json(session_storage_json, "session_storage_json")

    if _has_text(auth_header_name):
        name = auth_header_name.strip()  # type: ignore[union-attr]
        if not _HEADER_NAME_RE.match(name) or name.lower() in _FORBIDDEN_HEADERS:
            raise ValueError(f"Invalid auth_header_name: {name!r}")

    if auth_type == "password":
        if not _has_text(login_url):
            raise ValueError("login_url is required for password authentication")
        if not _has_text(xpath_of_username_field):
            raise ValueError("xpath_of_username_field is required for password authentication")
        if not _has_text(xpath_of_password_field):
            raise ValueError("xpath_of_password_field is required for password authentication")
        if not _has_text(username):
            raise ValueError("username is required for password authentication")
        if not _has_text(xpath_of_submit_button):
            raise ValueError("xpath_of_submit_button is required for password authentication")
        if require_secrets and not _has_text(password):
            raise ValueError("password is required for password authentication")
        return

    if auth_type == "session":
        has_any_secret = any(
            _has_text(v)
            for v in (session_cookie, auth_header_value, local_storage_json, session_storage_json)
        )
        if require_secrets and not has_any_secret:
            raise ValueError(
                "Session import requires at least one of session_cookie, auth_header_value, "
                "local_storage_json, or session_storage_json"
            )
        return

    if auth_type == "otp_form":
        if not _has_text(login_url):
            raise ValueError("login_url is required for OTP form authentication")
        if not _has_text(username):
            raise ValueError("username (mobile number or email) is required for OTP form authentication")
        if not _has_text(xpath_of_username_field):
            raise ValueError("xpath_of_username_field is required for OTP form authentication")
        if not _has_text(xpath_of_otp_field):
            raise ValueError("xpath_of_otp_field is required for OTP form authentication")
        if not _has_text(xpath_of_submit_button):
            raise ValueError("xpath_of_submit_button is required for OTP form authentication")
        src = otp_source or "static"
        if src == "totp":
            if require_secrets or _has_text(totp_secret):
                validate_totp_secret(totp_secret)
        else:
            if require_secrets and not _has_text(otp_code):
                raise ValueError("otp_code is required when otp_source is 'static'")
        if _has_text(mpin) and not _has_text(xpath_of_mpin_field):
            raise ValueError("xpath_of_mpin_field is required when mpin is provided")
        return

    raise ValueError(f"Unsupported auth_type: {auth_type!r}")


class DastAuthWrite(BaseModel):
    auth_type: DastAuthType = "password"
    login_url: str | None = None
    xpath_of_username_field: str | None = None
    xpath_of_password_field: str | None = None
    username: str | None = None
    password: str | None = Field(default=None, repr=False)
    xpath_of_submit_button: str | None = None
    # Session import (cookies / Bearer header / browser storage)
    session_cookie: str | None = Field(default=None, repr=False)
    auth_header_name: str | None = None
    auth_header_value: str | None = Field(default=None, repr=False)
    local_storage_json: str | None = Field(default=None, repr=False)
    session_storage_json: str | None = Field(default=None, repr=False)
    session_check_url: str | None = None
    logged_in_indicator: str | None = None
    # 2-step mobile/email + OTP form (with optional MPIN)
    xpath_of_send_otp_button: str | None = None
    xpath_of_otp_field: str | None = None
    otp_source: DastOtpSource = "static"
    otp_code: str | None = Field(default=None, repr=False)
    totp_secret: str | None = Field(default=None, repr=False)
    mpin: str | None = Field(default=None, repr=False)
    xpath_of_mpin_field: str | None = None
    xpath_of_mpin_submit_button: str | None = None

    @model_validator(mode="after")
    def _validate_structure(self) -> DastAuthWrite:
        validate_auth_fields(
            auth_type=self.auth_type,
            login_url=self.login_url,
            xpath_of_username_field=self.xpath_of_username_field,
            xpath_of_password_field=self.xpath_of_password_field,
            username=self.username,
            password=self.password,
            xpath_of_submit_button=self.xpath_of_submit_button,
            session_cookie=self.session_cookie,
            auth_header_name=self.auth_header_name,
            auth_header_value=self.auth_header_value,
            local_storage_json=self.local_storage_json,
            session_storage_json=self.session_storage_json,
            xpath_of_otp_field=self.xpath_of_otp_field,
            otp_source=self.otp_source,
            otp_code=self.otp_code,
            totp_secret=self.totp_secret,
            mpin=self.mpin,
            xpath_of_mpin_field=self.xpath_of_mpin_field,
            require_secrets=False,  # profile update may leave secrets blank to preserve stored ones
        )
        return self


class DastScheduleConfig(BaseModel):
    kind: ScheduleKind = "off"
    times: list[str] | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=24)
    weekday: int | None = Field(default=None, ge=0, le=6)
    monthday: int | None = Field(default=None, ge=1, le=28)
    once_at: str | None = None
    cron: str | None = None


class DastProfileCreate(BaseModel):
    title: str = "DAST Profile"
    target_url: str
    auth: DastAuthWrite
    allowed_hosts: list[str] | None = None
    scan_speed: Literal["fast", "medium", "slow"] = "medium"
    max_urls: int = Field(default=100, ge=1, le=10000)
    additional_urls_to_scan: list[str] | None = None
    exclude_url_patterns: list[str] | None = None
    include_url_patterns: list[str] | None = None
    schedule_kind: ScheduleKind = "off"
    schedule_time: str | None = None
    schedule_weekday: int | None = Field(default=None, ge=0, le=6)
    schedule_config: DastScheduleConfig | None = None
    enabled: bool = True
    consent_ok: bool = False


class DastProfileUpdate(BaseModel):
    title: str | None = None
    target_url: str | None = None
    auth: DastAuthWrite | None = None
    allowed_hosts: list[str] | None = None
    scan_speed: Literal["fast", "medium", "slow"] | None = None
    max_urls: int | None = Field(default=None, ge=1, le=10000)
    additional_urls_to_scan: list[str] | None = None
    exclude_url_patterns: list[str] | None = None
    include_url_patterns: list[str] | None = None
    schedule_kind: ScheduleKind | None = None
    schedule_time: str | None = None
    schedule_weekday: int | None = Field(default=None, ge=0, le=6)
    schedule_config: DastScheduleConfig | None = None
    enabled: bool | None = None
    consent_ok: bool | None = None


class CicdDastScanRequest(BaseModel):
    profile_id: int
    target_url: str | None = None
