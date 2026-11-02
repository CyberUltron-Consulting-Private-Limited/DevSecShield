"""What a credit estimate measured, so /start never charges an estimate made for a different input.

The estimate route stores, in ONE conditional update with the credits, a digest of what it measured and the version
of the formula that priced it (``Scan.credit_estimate``). /start computes the digest of what it is about to scan;
when it differs (another zip, another repository or branch, other scan options), or the formula changed, or the
scan predates the digest, /start re-estimates inside its atomic claim before charging.

The digest covers:
* the scan type and its start payload, minus secrets (access tokens and passwords never enter it);
* an uploaded file's size and SHA-256 (the storage object key is not part of it: every upload gets a new one);
* for repositories, the URL and branch. The commit is resolved by the worker when it clones, so the API cannot
  include it: a branch that moves between the estimate and the start is charged at the estimate.

Minimum charge (decision D3): a CBOM code scan (repository or zip) costs at least ``CBOM_CODE_SCAN_MIN_CREDITS``;
analysing an uploaded CBOM file stays a flat 0.01. The worker applies the same minimum when it estimates.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

CBOM_CODE_SCAN_MIN_CREDITS = 1.0
CBOM_FILE_CREDITS = 0.01
# Bump a type's version whenever its pricing changes: estimates priced by an older formula are re-estimated at start.
# cbom-2026.11-min1-bin5: the scan option "scan binaries" adds images / binaries / firmware at 1 credit per 5 MB (WP8).
FORMULA_VERSIONS: dict[str, str] = {"cbom": "cbom-2026.11-min1-bin5"}
DEFAULT_FORMULA = "v1"
_SECRET_KEYS = {"pat", "password", "token", "api_key", "apikey", "secret", "client_secret", "auth", "authorization",
                "headers", "cookies", "cookie", "login_password", "bearer"}


def formula_version(scan_type: str) -> str:
    return FORMULA_VERSIONS.get(scan_type, DEFAULT_FORMULA)


def _without_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _without_secrets(v) for k, v in sorted(value.items()) if str(k).lower() not in _SECRET_KEYS}
    if isinstance(value, list):
        return [_without_secrets(v) for v in value]
    return value


def input_digest(scan_type: str, payload_section: dict[str, Any] | None, file_bytes: bytes | None) -> dict[str, Any]:
    """``{"digest", "formula", "file_size", "file_sha256"}`` of what an estimate for this input measures."""
    file_info = None
    if file_bytes is not None:
        file_info = {"size": len(file_bytes), "sha256": hashlib.sha256(file_bytes).hexdigest()}
    blob = json.dumps({"type": scan_type, "payload": _without_secrets(payload_section or {}), "file": file_info},
                      sort_keys=True, separators=(",", ":"), default=str)
    return {"digest": hashlib.sha256(blob.encode("utf-8")).hexdigest(), "formula": formula_version(scan_type),
            "file_size": file_info["size"] if file_info else None,
            "file_sha256": file_info["sha256"] if file_info else None}


def is_cbom_code_scan(scan_type: str, payload_section: dict[str, Any] | None) -> bool:
    return scan_type == "cbom" and not (payload_section or {}).get("cbom_file_used")


def minimum_credits(scan_type: str, payload_section: dict[str, Any] | None) -> float:
    """The least a scan of this kind is charged (0 when there is no minimum)."""
    return CBOM_CODE_SCAN_MIN_CREDITS if is_cbom_code_scan(scan_type, payload_section) else 0.0


def priced(scan_type: str, payload_section: dict[str, Any] | None, credits: float) -> float:
    """The estimate with the minimum charge applied, rounded to cents."""
    return round(max(float(credits), minimum_credits(scan_type, payload_section)), 2)


def needs_reestimate(stored: dict[str, Any] | None, current: dict[str, Any]) -> bool:
    """True when the stored estimate is not for this input or this formula (or predates the digest)."""
    if not isinstance(stored, dict):
        return True
    return stored.get("digest") != current.get("digest") or stored.get("formula") != current.get("formula")


__all__ = ["CBOM_CODE_SCAN_MIN_CREDITS", "CBOM_FILE_CREDITS", "formula_version", "input_digest", "is_cbom_code_scan",
           "minimum_credits", "needs_reestimate", "priced"]
