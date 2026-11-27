from typing import Literal

from pydantic import BaseModel, Field

DastAuthType = Literal["password", "session", "otp_form"]
DastOtpSource = Literal["static", "totp"]


class AuthRequirements(BaseModel):
    auth_type: DastAuthType = "password"
    login_url: str | None = None
    xpath_of_username_field: str | None = None
    xpath_of_password_field: str | None = None
    username: str | None = None
    password: str | None = Field(default=None, repr=False)
    xpath_of_submit_button: str | None = None
    # Session import (cookies / Authorization header / browser storage)
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

    def validate_for_worker(self) -> None:
        validate_auth_for_worker(self)


def validate_auth_for_worker(auth) -> None:
    auth_type = getattr(auth, "auth_type", None) or "password"
    if auth_type == "password":
        if (
            not getattr(auth, "username", None)
            or not getattr(auth, "password", None)
            or not getattr(auth, "xpath_of_username_field", None)
            or not getattr(auth, "xpath_of_password_field", None)
            or not getattr(auth, "xpath_of_submit_button", None)
        ):
            raise Exception(
                "Username, password, xpath of username field, xpath of password field, "
                "and xpath of submit button are required for authentication"
            )
        return
    if auth_type == "session":
        if not any(
            (v and str(v).strip())
            for v in (
                getattr(auth, "session_cookie", None),
                getattr(auth, "auth_header_value", None),
                getattr(auth, "local_storage_json", None),
                getattr(auth, "session_storage_json", None),
            )
        ):
            raise Exception(
                "Session import requires at least one of session_cookie, auth_header_value, "
                "local_storage_json, or session_storage_json"
            )
        return
    if auth_type == "otp_form":
        if (
            not getattr(auth, "login_url", None)
            or not getattr(auth, "username", None)
            or not getattr(auth, "xpath_of_username_field", None)
            or not getattr(auth, "xpath_of_otp_field", None)
            or not getattr(auth, "xpath_of_submit_button", None)
        ):
            raise Exception(
                "login_url, username, xpath_of_username_field, xpath_of_otp_field, "
                "and xpath_of_submit_button are required for OTP form authentication"
            )
        otp_source = getattr(auth, "otp_source", None) or "static"
        if otp_source == "totp":
            if not (getattr(auth, "totp_secret", None) and str(auth.totp_secret).strip()):
                raise Exception("totp_secret is required when otp_source is 'totp'")
        else:
            if not (getattr(auth, "otp_code", None) and str(auth.otp_code).strip()):
                raise Exception("otp_code is required when otp_source is 'static'")
        mpin = getattr(auth, "mpin", None)
        if mpin and not (getattr(auth, "xpath_of_mpin_field", None) and str(auth.xpath_of_mpin_field).strip()):
            raise Exception("xpath_of_mpin_field is required when mpin is provided")
        return
    raise Exception(f"Unsupported auth_type: {auth_type}")


class StartDASTScanData(BaseModel):
    """
    Both include and exclude url patterns are not going to be used together
    """
    target_url: str
    auth: AuthRequirements
    scan_speed: Literal["fast", "medium", "slow"] = "medium"
    max_urls: int = 100
    additional_urls_to_scan: list[str] | None = None  # these urls will be scanned definitely
    exclude_url_patterns: list[str] | None = None  # either exclude urls that match these patterns or include urls that match these patterns
    include_url_patterns: list[str] | None = None  # either exclude urls that match these patterns or include urls that match these patterns
