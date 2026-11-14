"""Scrub secrets from evidence (HAR, JSON, logs) and prove none is left.

What is scrubbed (DEVILS-ADVOCATE G17): Authorization headers, cookies, bearer and JWT tokens, the node registration
token, passwords, vendor links, and the lab canaries' *non-allowed* copies are left to canary.py (they must stay
visible there, so a leak is detected rather than hidden). A scrubbed value becomes ``[REDACTED:<kind>:<sha12>]`` so two
copies of one token stay comparable without revealing it.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .rundir import write_text

SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-zs-node-token",
                  "x-zs-registration-token", "x-api-key"}
SECRET_KEYS = re.compile(
    r"^(access_token|refresh_token|id_token|token|node_token|registration_token|password|new_password|"
    r"current_password|old_password|secret|client_secret|api_key|apikey|verification_code|otp|vendor_link|"
    r"link_token|private_key|passphrase)$", re.I)
SECRET_QUERY = re.compile(r"^(token|access_token|verification_code|key|sig|signature|link)$", re.I)
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
BEARER = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})")
REG_TOKEN = re.compile(r"(ZS_REGISTRATION_TOKEN=)('?)([^'\s\\]+)")
# the product's own tokens carry a prefix: zsr_ node registration, zsn_ node credential, zsv_ vendor link (/q/<token>),
# zsp_ pool enrolment
ZS_TOKEN = re.compile(r"\bzs[rnvp]_[A-Za-z0-9_-]{16,}")


def mark(kind: str, value: str) -> str:
    return f"[REDACTED:{kind}:{hashlib.sha256(value.encode()).hexdigest()[:12]}]"


def scrub_text(text: str) -> str:
    text = REG_TOKEN.sub(lambda m: m.group(1) + m.group(2) + mark("registration-token", m.group(3)), text)
    text = BEARER.sub(lambda m: "Bearer " + mark("bearer", m.group(1)), text)
    text = JWT.sub(lambda m: mark("jwt", m.group(0)), text)
    text = ZS_TOKEN.sub(lambda m: mark(m.group(0)[:3], m.group(0)), text)
    return text


def scrub_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if isinstance(key, str) and SECRET_KEYS.match(key) and isinstance(value, (str, int)) and str(value):
                out[key] = mark(key.lower(), str(value))
            else:
                out[key] = scrub_obj(value)
        return out
    if isinstance(obj, list):
        return [scrub_obj(v) for v in obj]
    if isinstance(obj, str):
        return scrub_text(obj)
    return obj


def scrub_url(url: str) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return scrub_text(url)
    query = [(k, mark(k.lower(), v) if SECRET_QUERY.match(k) and v else v)
             for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return scrub_text(urlunsplit(parts._replace(query=urlencode(query, safe="[]:"))))


def _scrub_body(text: str | None, mime: str | None) -> str | None:
    if not text:
        return text
    if "json" in (mime or "") or text[:1] in "{[":
        try:
            return json.dumps(scrub_obj(json.loads(text)), separators=(",", ":"))
        except ValueError:
            pass
    if "x-www-form-urlencoded" in (mime or ""):
        pairs = [(k, mark(k.lower(), v) if SECRET_KEYS.match(k) and v else v)
                 for k, v in parse_qsl(text, keep_blank_values=True)]
        return urlencode(pairs)
    return scrub_text(text)


def scrub_har(har: dict[str, Any]) -> dict[str, Any]:
    for entry in har.get("log", {}).get("entries", []):
        for side in ("request", "response"):
            msg = entry.get(side) or {}
            for header in msg.get("headers") or []:
                if str(header.get("name", "")).lower() in SECRET_HEADERS:
                    header["value"] = mark(header["name"].lower(), str(header.get("value", "")))
                else:
                    header["value"] = scrub_text(str(header.get("value", "")))
            msg["cookies"] = [{"name": c.get("name"), "value": mark("cookie", str(c.get("value", "")))}
                              for c in msg.get("cookies") or []]
            if side == "request":
                msg["url"] = scrub_url(str(msg.get("url", "")))
                for q in msg.get("queryString") or []:
                    if SECRET_QUERY.match(str(q.get("name", ""))):
                        q["value"] = mark(str(q["name"]).lower(), str(q.get("value", "")))
                post = msg.get("postData") or {}
                if post.get("text"):
                    post["text"] = _scrub_body(post["text"], post.get("mimeType"))
                for param in post.get("params") or []:
                    if SECRET_KEYS.match(str(param.get("name", ""))):
                        param["value"] = mark(str(param["name"]).lower(), str(param.get("value", "")))
            else:
                content = msg.get("content") or {}
                if content.get("encoding") == "base64":
                    continue  # binary (images, fonts); text bodies are what carry tokens
                if content.get("text"):
                    content["text"] = _scrub_body(content["text"], content.get("mimeType"))
                if msg.get("redirectURL"):
                    msg["redirectURL"] = scrub_url(msg["redirectURL"])
    return har


def scrub_har_file(path: Path) -> Path:
    path = Path(path)
    har = json.loads(path.read_text(encoding="utf-8"))
    write_text(path, json.dumps(scrub_har(har), indent=1))
    return path


def residual_secrets(text: str, known: list[str] | tuple[str, ...] = ()) -> list[str]:
    """What still looks like a secret after scrubbing: unredacted JWTs/bearers/registration tokens, or any of the
    ``known`` raw secret values (the run's own tokens and passwords, passed in by the runner). Returns kinds only,
    never the values."""
    found = []
    if JWT.search(text):
        found.append("jwt")
    for m in BEARER.finditer(text):
        if not m.group(1).startswith("[REDACTED"):
            found.append("bearer")
            break
    for m in REG_TOKEN.finditer(text):
        if not m.group(3).startswith("[REDACTED"):
            found.append("registration-token")
            break
    if ZS_TOKEN.search(text):
        found.append("zs-token")
    for i, value in enumerate(known):
        if value and len(value) >= 8 and value in text:
            found.append(f"known-secret-{i}")
    return found
