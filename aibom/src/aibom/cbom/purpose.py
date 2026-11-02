"""Why a hash is computed: to protect a secret, or only to name or check content.

MD5 / SHA-1 are broken for collision resistance, which matters when the digest stands for a secret or a signed
value. A digest that only names content (a cache key, an ETag, a file checksum, a de-duplication or partition key) with
no secret input is not an attack surface; reporting it as WEAK_ALGORITHM teaches users to ignore the finding.

A hashing line is a NON-SECURITY use when nothing secret reaches it and either

* the call says so (Python ``usedforsecurity=False``), or
* its purpose is named where it is used: the function it is in or the variable it is assigned to is a cache key /
  ETag / checksum / partition key.

A secret word on the line or among the enclosing function's parameters (``password``, ``secret``, ``token``,
``salt``, ``key`` material ...) always makes it a security use, so naming a variable ``cache_key`` does not hide
``md5(password)``.
"""

from __future__ import annotations

import re

_USED_FOR_SECURITY_FALSE = re.compile(r"\busedforsecurity\s*=\s*False\b")
_PURPOSE_WORDS = (
    ("cache-key", re.compile(r"cache|memo", re.I)),
    ("etag", re.compile(r"e_?tag", re.I)),
    ("checksum", re.compile(r"checksum|check_?sum|\bcrc|content_?hash|content_?address", re.I)),
    ("partition", re.compile(r"dedup|de_dup|bucket|shard|partition", re.I)),
)
# ``fingerprint`` is deliberately absent: a certificate / key fingerprint used for pinning is a security use.
_SECRET = re.compile(
    r"pass(?:word|wd|phrase)?|\bpwd\b|secret|token|credential|private|salt|session|auth|api_?key|\bkey_?material"
    r"|\bsign|hmac|\botp\b|\bpin\b|cookie",
    re.I,
)
_PY_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)")
_C_LIKE_DEF = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)"                    # JS function
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"  # JS arrow
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)"            # Go
    r"|[\w<>\[\]]+\s+([a-z_]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\{)"  # Java / C# / C
)
_ASSIGN_TARGET = re.compile(r"^\s*(?:(?:const|let|var|final|String|byte\[\])\s+)*([A-Za-z_$][\w$.]*)\s*[:+]?=(?!=)")
_FUNC_WINDOW = 60


def _enclosing(lines: list[str], idx: int, lang: str) -> tuple[str, str] | None:
    """(name, parameters) of the function the 0-based line ``idx`` is in, or None."""
    if lang == "python":
        indent = len(lines[idx]) - len(lines[idx].lstrip())
        for j in range(idx, max(-1, idx - _FUNC_WINDOW), -1):
            m = _PY_DEF.match(lines[j])
            if m and (j == idx or len(m.group(1)) < indent):
                return m.group(2), m.group(3)
        return None
    for j in range(idx, max(-1, idx - _FUNC_WINDOW), -1):
        m = _C_LIKE_DEF.search(lines[j])
        if m:
            groups = list(m.groups())
            for k in range(0, len(groups), 2):
                if groups[k]:
                    return groups[k], groups[k + 1] or ""
    return None


def hash_purpose(lines: list[str], line_no: int, lang: str) -> str | None:
    """The non-security purpose of the hash used on 1-based ``line_no`` (``cache-key`` / ``etag`` / ``checksum``
    / ``partition`` / ``usedforsecurity=False``), or None when it is (or may be) a security use."""
    if not 0 < line_no <= len(lines):
        return None
    line = lines[line_no - 1]
    func = _enclosing(lines, line_no - 1, lang)
    if _SECRET.search(_USED_FOR_SECURITY_FALSE.sub("", line)) or (func and _SECRET.search(func[1])):
        return None
    if _USED_FOR_SECURITY_FALSE.search(line):
        return "usedforsecurity=False"
    names = []
    target = _ASSIGN_TARGET.match(line)
    if target:
        names.append(target.group(1))
    if func:
        names.append(func[0])
    for name in names:
        if _SECRET.search(name):
            return None
        for label, pattern in _PURPOSE_WORDS:
            if pattern.search(name):
                return label
    return None


__all__ = ["hash_purpose"]
