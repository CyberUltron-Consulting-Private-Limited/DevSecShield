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

PATTERNS = [
    (re.compile(r'(mongodb://|amqp://|redis://|postgres://|postgresql://)[^\s]+', re.I), r'\1[REDACTED]'),
    (re.compile(r'(api[_-]?key.*?[:=]\s*["\']?)([a-zA-Z0-9]{16,})', re.I), r'\1[REDACTED]'),
    (re.compile(r'(Bearer\s+)([a-zA-Z0-9._-]+)', re.I), r'\1[REDACTED]'),
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
