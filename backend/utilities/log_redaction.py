"""Credential redaction for log records (installed by backend/main.py on the root logger and the security handlers).

The record is formatted first (``record.getMessage()``: %-args, a single dict arg, or a message that is already a
plain string such as an f-string or ``str.format`` result) and the finished text is redacted; ``args`` is then
emptied so no handler formats it again.  Before, the patterns ran over the TEMPLATE: "password ... user_id=%s"
became "password ... user_id=[REDACTED]" while the args stayed, and formatting raised TypeError ("not all
arguments converted") in every handler; under a handler that re-raises logging errors (pytest's) that crashed
the request that logged it.  The filter never raises: whatever fails, the record goes out with a redacted message.
"""
import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

PATTERNS = [
    (re.compile(r'(mongodb://|amqp://|redis://|postgres://|postgresql://)[^\s]+', re.I), r'\1[REDACTED]'),
    (re.compile(r'(api[_-]?key.*?[:=]\s*["\']?)([a-zA-Z0-9]{16,})', re.I), r'\1[REDACTED]'),
    (re.compile(r'(Bearer\s+)([a-zA-Z0-9._~+/=-]+)', re.I), r'\1[REDACTED]'),
    (re.compile(r'(Basic\s+)([A-Za-z0-9+/=]{6,})', re.I), r'\1[REDACTED]'),
    # str(pydantic.ValidationError): "[type=..., input_value={'PAT': ...}, input_type=dict]"
    (re.compile(r'(input_value=).*?(, input_type=)', re.S), r'\1[REDACTED]\2'),
    (re.compile(r'(password.*?[:=]\s*["\']?)([^\s"\']+)', re.I), r'\1[REDACTED]'),
    (re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'), '[JWT_REDACTED]'),
    (re.compile(r'(secret.*?[:=]\s*["\']?)([^\s"\']{8,})', re.I), r'\1[REDACTED]'),
]

UNREDACTABLE = "[log message withheld: it could not be redacted]"


def redact(text: str) -> str:
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class CredentialRedactionFilter(logging.Filter):
    """Redacts credentials from the formatted message; keeps every record; never raises."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            try:
                message = record.getMessage()
            except Exception:
                # the template and its args do not match (a bug in the caller): keep the template, drop the args
                message = f"{record.msg} [log arguments dropped: they did not match the message]"
            record.msg = redact(str(message))
            record.args = ()
        except Exception:
            record.msg, record.args = UNREDACTABLE, ()
        return True


# ------------------------------------------------------------------------------------------------ structured values
# Issue #88: printing a worker's kwargs (``model_dump()`` of the payload, which includes ``repr=False`` fields) leaked
# an LLM api_key, MCP request headers and repository PATs. ``safe_repr`` is the one way to print such a value: secret
# fields by name, every header value, URL credentials and secret query parameters are replaced, then the text
# patterns above run over the result.
REDACTED = "[REDACTED]"
_SECRET_NAME_PARTS = ("password", "passwd", "secret", "token", "apikey", "authorization", "cookie", "credential",
                      "privatekey", "accesskey", "sessionkey", "signature", "bearer", "passphrase")
_SECRET_NAMES = frozenset({
    "pat", "key", "pwd", "auth_header", "auth_header_value", "proxy_authorization",
    "otp_code", "mpin", "local_storage_json", "session_storage_json", "session_cookie", "totp_secret",
})
# a name whose last word is one of these (ssh_key, github_pat, sshKey, api-key) is a secret too
_SECRET_LAST_WORDS = frozenset({"pat", "key", "pwd", "pem", "jwt"})
_SECRET_QUERY = frozenset({"key", "apikey", "api_key", "token", "access_token", "auth", "sig", "signature", "secret",
                           "password", "x-amz-signature", "x-amz-credential", "x-amz-security-token", "code",
                           "session", "sessionid", "sid", "jwt", "pat"})
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+", re.I)


def _secret_name(name: Any) -> bool:
    text = str(name)
    key = re.sub(r"[^a-z0-9]", "", text.lower())
    if key in {re.sub(r"[^a-z0-9]", "", n) for n in _SECRET_NAMES} or any(p in key for p in _SECRET_NAME_PARTS):
        return True
    words = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", text)
    return bool(words) and words[-1].lower() in _SECRET_LAST_WORDS


def _headers_name(name: Any) -> bool:
    return str(name).lower().replace("-", "_").endswith("headers")


def _clean_url(match: "re.Match[str]") -> str:
    url = match.group(0)
    try:
        parts = urlsplit(url)
        netloc = parts.netloc
        if "@" in netloc:
            netloc = REDACTED + "@" + netloc.rsplit("@", 1)[1]
        return urlunsplit((parts.scheme, netloc, parts.path, _clean_pairs(parts.query),
                           _clean_pairs(parts.fragment)))
    except ValueError:
        return REDACTED


def _clean_pairs(text: str) -> str:
    """A query string or fragment (``#access_token=...``): secret parameters' values replaced."""
    if "=" not in text:
        return text
    pairs = parse_qsl(text, keep_blank_values=True)
    return urlencode([(k, REDACTED if k.lower() in _SECRET_QUERY or _secret_name(k) else v) for k, v in pairs],
                     safe="[]")


def _clean_text(text: str) -> str:
    return _URL.sub(_clean_url, text)


def redact_secrets(value: Any, _depth: int = 0) -> Any:
    """A copy of ``value`` (dicts, lists, tuples, pydantic models) with every secret replaced (see above); the input
    is never modified. Header containers keep their names and lose every value."""
    if _depth > 20:
        return REDACTED
    if hasattr(value, "model_dump") and callable(value.model_dump):
        value = value.model_dump()
    if isinstance(value, dict):
        out: dict = {}
        for k, v in value.items():
            if _secret_name(k):
                out[k] = REDACTED if v not in (None, "") else v
            elif _headers_name(k):
                out[k] = _header_values(v)
            else:
                out[k] = redact_secrets(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [redact_secrets(v, _depth + 1) for v in value]
        return type(value)(items) if isinstance(value, (tuple, list)) else items
    if isinstance(value, str):
        return _clean_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return REDACTED  # raw bytes (a key file, an uploaded body): never printed
    return value


def _header_values(headers: Any) -> Any:
    if isinstance(headers, dict):
        return {k: REDACTED for k in headers}
    if isinstance(headers, (list, tuple)):
        return [(item[0], REDACTED) if isinstance(item, (list, tuple)) and item else REDACTED for item in headers]
    return REDACTED if headers not in (None, "") else headers


def safe_repr(value: Any) -> str:
    """The text to print or log for a kwargs dict / payload model: redacted structurally, then by pattern. Never
    raises (a value that cannot be printed becomes UNREDACTABLE)."""
    try:
        return redact(repr(redact_secrets(value)))
    except Exception:
        return UNREDACTABLE
