"""Recognize private algorithm implementations by well-known constants.

A known-library call is not required. A comment that merely names the
constant is ignored. This does not execute the file.
"""

from __future__ import annotations

import re

_AES = re.compile(
    r"0x63\W{1,8}0x7c\W{1,8}0x77\W{1,8}0x7b\W{1,8}0xf2",
    re.IGNORECASE,
)
_SHA256 = re.compile(
    r"0x6a09e667.{0,80}0xbb67ae85",
    re.IGNORECASE | re.DOTALL,
)
_MD5 = re.compile(
    r"0x67452301.{0,80}0xefcdab89",
    re.IGNORECASE | re.DOTALL,
)

_KINDS = (
    ("aes", "AES (custom implementation)", "block-cipher", _AES),
    ("sha256", "SHA-256 (custom implementation)", "hash", _SHA256),
    ("md5", "MD5 (custom implementation)", "hash", _MD5),
)


def _blank_comments(text: str) -> str:
    """Replace comments with spaces. ``https://`` is not a line comment."""
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            out.append(" " * (end - index))
            index = end
            continue
        slash = text.startswith("//", index) and (index == 0 or text[index - 1] != ":")
        if slash or text[index] == "#":
            end = text.find("\n", index)
            end = length if end < 0 else end
            out.append(" " * (end - index))
            index = end
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


def detect_custom_crypto(text: str) -> tuple[str, str, str] | None:
    """Return ``(kind, display name, primitive)`` or None."""
    code = _blank_comments(text)
    for kind, name, primitive, pattern in _KINDS:
        if pattern.search(code):
            return kind, name, primitive
    return None
