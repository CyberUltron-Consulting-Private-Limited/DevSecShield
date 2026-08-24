"""Request/response schemas for automatic DAST profiles and CI."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

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


class DastAuthWrite(BaseModel):
    login_url: str
    xpath_of_username_field: str
    xpath_of_password_field: str
    username: str
    password: str | None = None
    xpath_of_submit_button: str


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
