"""Public (password-free) DAST profile payloads."""
from __future__ import annotations

from backend.new_models import DastScanProfile
from backend.utilities.dast.auth_crypto import redact_auth


def public_profile(profile: DastScanProfile) -> dict:
    auth = redact_auth(profile.auth_encrypted or {})
    return {
        "id": profile.id,
        "team_id": profile.team_id,
        "owner_user_id": profile.owner_user_id,
        "title": profile.title,
        "enabled": profile.enabled,
        "target_url": profile.target_url,
        "allowed_hosts": profile.allowed_hosts or [],
        "auth": auth,
        "scan_speed": profile.scan_speed,
        "max_urls": profile.max_urls,
        "additional_urls_to_scan": profile.additional_urls_to_scan,
        "exclude_url_patterns": profile.exclude_url_patterns,
        "include_url_patterns": profile.include_url_patterns,
        "schedule_kind": profile.schedule_kind,
        "schedule_time": profile.schedule_time,
        "schedule_weekday": profile.schedule_weekday,
        "schedule_config": profile.schedule_config or {},
        "next_run_at": profile.next_run_at.isoformat() if profile.next_run_at else None,
        "inflight_scan_id": profile.inflight_scan_id,
        "last_scan_id": profile.last_scan_id,
        "last_run_at": profile.last_run_at.isoformat() if profile.last_run_at else None,
        "consent_ok": profile.consent_ok,
        "created_at": profile.created_at.isoformat() if profile.created_at else None,
        "last_updated": profile.last_updated.isoformat() if profile.last_updated else None,
    }
