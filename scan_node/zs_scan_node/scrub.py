"""Remove secrets from everything the node sends or logs.

Two layers: the exact secret values this job holds (passwords, tokens, keys, kubeconfig credentials, the node's
own token) and patterns that are secrets whatever they belong to (PEM private keys, ZeroShield tokens, Vault
tokens, AWS secret-looking strings next to a key id).  A PEM private key is redacted from BEGIN to its END line,
or to the end of the text when the END line is missing (a truncated key is still a key).
"""
from __future__ import annotations

import re
from typing import Any

REDACTED = "[redacted]"
MIN_SECRET_LEN = 4

_PEM_PRIVATE = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*?(?:-----END \1PRIVATE KEY-----|\Z)", re.S
)
_OPENSSH_PRIVATE = re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----.*?(?:-----END OPENSSH PRIVATE KEY-----|\Z)", re.S)
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bzs[rnvp]_[A-Za-z0-9_\-]{16,}"), REDACTED),  # ZeroShield registration / node / vendor / pool tokens
    (re.compile(r"\bhv[sbr]\.[A-Za-z0-9_\-]{20,}"), REDACTED),  # HashiCorp Vault tokens
    (re.compile(r"(?i)(aws_secret_access_key|secretaccesskey)(\s*[=:]\s*)[A-Za-z0-9/+]{40}"), r"\1\2" + REDACTED),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]{10,}"), r"\1" + REDACTED),
]


class Scrubber:
    def __init__(self, secrets: list[str] | None = None) -> None:
        self._secrets: list[str] = []
        for value in secrets or []:
            self.add(value)

    def add(self, value: Any) -> None:
        if not isinstance(value, str):
            return
        candidates = {value, value.strip()}
        # multi-line secrets (keys, kubeconfigs): every long line is a secret on its own
        if "\n" in value:
            candidates.update(line.strip() for line in value.splitlines() if len(line.strip()) >= 16)
        for item in candidates:
            if len(item) >= MIN_SECRET_LEN and item not in self._secrets:
                self._secrets.append(item)
        self._secrets.sort(key=len, reverse=True)

    def text(self, value: str) -> str:
        if not value:
            return value
        out = _PEM_PRIVATE.sub(REDACTED, value)
        out = _OPENSSH_PRIVATE.sub(REDACTED, out)
        for pattern, replacement in _PATTERNS:
            out = pattern.sub(replacement, out)
        for secret in self._secrets:
            if secret in out:
                out = out.replace(secret, REDACTED)
        return out

    def obj(self, value: Any, depth: int = 0) -> Any:
        if depth > 20:
            return None
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.text(str(k)): self.obj(v, depth + 1) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.obj(v, depth + 1) for v in value]
        return value


_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def printable(value: str, limit: int = 512) -> str:
    """Strip control characters (ANSI escapes, NUL) from text that came from a remote system."""
    text = _CONTROL.sub("", value or "")
    text = text.replace("\x1b", "")
    return text[:limit]
