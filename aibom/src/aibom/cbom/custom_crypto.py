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
# 0x67452301 / 0xefcdab89 / 0x98badcfe / 0x10325476 open the state of MD4, MD5, SHA-1 and RIPEMD-160 alike: MD5 is
# named only next to a constant of its own, the first sine-table word T[1] = 0xd76aa478 or the round-1 shift
# schedule 7, 12, 17, 22 (MD4 shifts 3, 7, 11, 19).
_MD_IV = re.compile(
    r"0x67452301.{0,80}0xefcdab89",
    re.IGNORECASE | re.DOTALL,
)
_MD5_OWN = re.compile(r"0xd76aa478|\b7\s*,\s*12\s*,\s*17\s*,\s*22\b", re.IGNORECASE)

# (kind, display name, primitive, patterns that must ALL be found)
_KINDS = (
    ("aes", "AES (custom implementation)", "block-cipher", (_AES,)),
    ("sha256", "SHA-256 (custom implementation)", "hash", (_SHA256,)),
    ("md5", "MD5 (custom implementation)", "hash", (_MD_IV, _MD5_OWN)),
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


_CONSTANT_TOKENS = ("0x63", "0x6a09e667", "0x67452301")  # every _KINDS pattern needs one of these


def detect_custom_crypto(text: str) -> tuple[str, str, str] | None:
    """Return ``(kind, display name, primitive)`` or None."""
    low = text.lower()
    if not any(tok in low for tok in _CONSTANT_TOKENS):
        return None  # no constant to recognize: skip the comment blanking (a character loop)
    code = _blank_comments(text)
    for kind, name, primitive, patterns in _KINDS:
        if all(p.search(code) for p in patterns):
            return kind, name, primitive
    return None


# --------------------------------------------------------------------------- #
# Private constructions recognized by their STRUCTURE (no constant needed).
# --------------------------------------------------------------------------- #
# Repeating-key XOR: a data element XORed with a key element whose index wraps around the key's length
# (``data[i] ^ key[i % len(key)]``, ``buf[i] ^= k[i % k.length]``, ``key[i % keyLen]``). A modulus that is a
# constant (``table[i % 256]``) is a table lookup, not a key, and does not match.
_XOR_KEY_INDEX = re.compile(
    r"(?P<k>[A-Za-z_]\w*)\s*\[\s*[A-Za-z_]\w*\s*(?:\+\+|--)?\s*%\s*"
    r"(?:len\(\s*(?P=k)\s*\)|(?P=k)\s*\.\s*(?:length|Length|size\(\s*\)|len\(\s*\)|count)"
    r"|[A-Za-z_]*(?:[Ll]en|LEN|[Ss]ize|SIZE)\w*)\s*\]"
)
_XOR_OP = re.compile(r"(?<![\^*])\^=?(?!\^)")
# Python ``zip(data, cycle(key))`` / ``itertools.cycle(key)`` with a ``^`` in the same expression.
_XOR_CYCLE = re.compile(r"\bcycle\(\s*(?P<k>[A-Za-z_]\w*)\s*\)")
# A repeating XOR operand named a mask is masking, not encryption: RFC 6455 WebSocket client frames
# (``payload[i] ^ mask[i % 4]``, the "masking key"), bit masks. It hides nothing from anyone holding the frame.
_MASK_OPERAND = re.compile(r"mask", re.I)
_LOOP = re.compile(r"\b(?:for|while|forEach|map)\b")
_LOOP_WINDOW = 4

# Feistel round: the halves swap through a temporary while one becomes ``other ^ F(this half, key)``:
#   t = R;  R = L ^ F(R, k);  L = t;      (or Python ``L, R = R, L ^ f(R, k)``)
_SIMPLE_ASSIGN = re.compile(
    r"^\s*(?:(?:final\s+)?[A-Za-z_][\w<>\[\]]*\s+)?(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[^=].*?)\s*;?\s*$"
)
_TUPLE_FEISTEL = re.compile(
    r"\b(?P<l>[A-Za-z_]\w*)\s*,\s*(?P<r>[A-Za-z_]\w*)\s*=\s*(?P=r)\s*,\s*(?P<mix>.+)$"
)


def _mixes(rhs: str, left: str, right: str) -> bool:
    """``rhs`` is ``left ^ f(right, ...)`` (either operand order): the other half XORed with a function of this
    half and something more (a round key, a round function call). Shifts of the two halves alone
    (``s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26)``, a xorshift PRNG step) have no key and no round function."""
    if "^" not in rhs or not re.search(rf"(?<![\w.]){re.escape(left)}(?!\w)", rhs):
        return False
    rest = re.sub(rf"(?<![\w.]){re.escape(left)}(?!\w)", "", rhs, count=1)
    if not re.search(rf"(?<![\w.]){re.escape(right)}(?!\w)", rest):
        return False
    others = set(re.findall(r"[A-Za-z_]\w*", rest)) - {right, left}
    return bool(others) or bool(re.search(r"[A-Za-z_]\w*\s*\(", rest))


def _xor_key_lines(lines: list[str]) -> list[int]:
    out: list[int] = []
    for idx, line in enumerate(lines):
        if not _XOR_OP.search(line):
            continue
        keys = [m.group("k") for pat in (_XOR_KEY_INDEX, _XOR_CYCLE) for m in pat.finditer(line)]
        if not any(not _MASK_OPERAND.search(k) for k in keys):
            continue
        window = lines[max(0, idx - _LOOP_WINDOW): idx + 1]
        if any(_LOOP.search(w) for w in window):
            out.append(idx + 1)
    return out


def _feistel_lines(lines: list[str]) -> list[int]:
    out: list[int] = []
    for idx, line in enumerate(lines):
        t = _TUPLE_FEISTEL.search(line)
        if t and _mixes(t.group("mix"), t.group("l"), t.group("r")):
            out.append(idx + 1)
            continue
        first = _SIMPLE_ASSIGN.match(line)
        if not first or not re.fullmatch(r"[A-Za-z_]\w*", first.group("rhs")):
            continue
        tmp, right = first.group("lhs"), first.group("rhs")
        for j in range(idx + 1, min(len(lines), idx + 3)):
            mix = _SIMPLE_ASSIGN.match(lines[j])
            if not mix or mix.group("lhs") != right:
                continue
            left = next((n for n in re.findall(r"[A-Za-z_]\w*", mix.group("rhs")) if n != right), None)
            if left is None or not _mixes(mix.group("rhs"), left, right):
                break
            for k in range(j + 1, min(len(lines), j + 3)):
                back = _SIMPLE_ASSIGN.match(lines[k])
                if back and back.group("lhs") == left and back.group("rhs") == tmp:
                    out.append(j + 1)
                    break
            break
    return out


_CONSTRUCTIONS = (
    ("xor", "XOR cipher (custom implementation)", "stream-cipher", _xor_key_lines),
    ("feistel", "Feistel cipher (custom implementation)", "block-cipher", _feistel_lines),
)


def detect_custom_constructions(text: str) -> list[tuple[str, str, str, list[int]]]:
    """``(kind, display name, primitive, lines)`` for each private construction the file implements: a
    repeating-key XOR inside a loop, a Feistel round (the halves swap through a temporary while one becomes
    ``L ^ F(R, k)``)."""
    if "^" not in text:
        return []  # both constructions XOR
    lines = _blank_comments(text).split("\n")
    found: list[tuple[str, str, str, list[int]]] = []
    for kind, name, primitive, finder in _CONSTRUCTIONS:
        hits = finder(lines)
        if hits:
            found.append((kind, name, primitive, hits))
    return found
