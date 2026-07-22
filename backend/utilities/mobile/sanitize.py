"""Strip third-party analyzer branding from user-facing mobile scan text."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

_MOBSF_MSTG_PREFIX = "https://github.com/MobSF/owasp-mstg/"
_OWASP_MSTG_PREFIX = "https://github.com/OWASP/owasp-mstg/"

_MOBSF_PATTERNS = (
    (re.compile(r"https?://github\.com/MobSF/owasp-mstg/", re.I), _OWASP_MSTG_PREFIX),
    (re.compile(r"https?://github\.com/MobSF/", re.I), "https://github.com/OWASP/"),
    (re.compile(r"\bMobSF\b"), "mobile security analyzer"),
    (re.compile(r"\bmobsf\b", re.I), "mobile security analyzer"),
)


def sanitize_mobile_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    for pattern, replacement in _MOBSF_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def normalize_mstg_reference(ref: str) -> str:
    url = sanitize_mobile_text(ref)
    if url.startswith(_MOBSF_MSTG_PREFIX):
        url = _OWASP_MSTG_PREFIX + url[len(_MOBSF_MSTG_PREFIX) :]
    return url


def mstg_reference_label(url: str) -> str:
    clean = normalize_mstg_reference(url)
    if "/Document/" not in clean:
        return "OWASP MSTG reference"
    doc_part = clean.split("/Document/", 1)[1]
    doc_name = unquote(doc_part.split("#", 1)[0])
    anchor = doc_part.split("#", 1)[1] if "#" in doc_part else ""
    title = doc_name.replace(".md", "").replace("-", " ").strip()
    if title.lower().startswith("0x"):
        title = title.split(" ", 1)[-1] if " " in title else title
    label = f"OWASP MSTG — {title}" if title else "OWASP MSTG reference"
    if anchor:
        label = f"{label} ({anchor.replace('-', ' ')})"
    return label


def sanitize_compliance_controls(controls: Any) -> dict[str, str]:
    if not isinstance(controls, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in controls.items():
        safe_key = sanitize_mobile_text(key)
        raw = str(value or "").strip()
        if safe_key in {"MSTG", "OWASP_MSTG"} or (
            raw.startswith("http") and "owasp-mstg" in raw.lower()
        ):
            out["OWASP_MSTG"] = normalize_mstg_reference(raw)
        else:
            out[safe_key or key] = sanitize_mobile_text(raw)
    return out


def sanitize_owasp_map(owasp: Any) -> dict[str, str]:
    if not isinstance(owasp, dict):
        return {}
    return {sanitize_mobile_text(k): sanitize_mobile_text(v) for k, v in owasp.items() if v}


def sanitize_mobile_finding(finding: dict[str, Any]) -> dict[str, Any]:
    out = dict(finding)
    out["title"] = sanitize_mobile_text(out.get("title"))
    out["description"] = sanitize_mobile_text(out.get("description"))
    out["suggested_fix"] = sanitize_mobile_text(out.get("suggested_fix"))
    out["file_path"] = sanitize_mobile_text(out.get("file_path"))
    out["location"] = sanitize_mobile_text(out.get("location") or out.get("file_path"))
    out["compliance_controls"] = sanitize_compliance_controls(out.get("compliance_controls"))
    out["owasp_top_10"] = sanitize_owasp_map(out.get("owasp_top_10"))
    return out


def compliance_controls_for_display(controls: Any) -> dict[str, str]:
    clean = sanitize_compliance_controls(controls)
    out: dict[str, str] = {}
    for key, value in clean.items():
        if key == "OWASP_MSTG":
            out[key] = mstg_reference_label(value)
        else:
            out[key] = value
    return out


def compliance_metric_label(value: str) -> str:
    text = sanitize_mobile_text(value)
    if text.startswith("http") and "owasp-mstg" in text.lower():
        return mstg_reference_label(text)
    return text
