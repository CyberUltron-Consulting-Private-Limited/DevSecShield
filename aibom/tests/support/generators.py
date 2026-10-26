"""Input builders for the posture parser timing tests."""

from __future__ import annotations

import random

MIB = 1_048_576


def structure_aware(size: int = MIB) -> list[tuple[str, str]]:
    """Hostile shapes, each about ``size`` characters."""

    def tile(unit: str) -> str:
        if not unit:
            return "a" * size
        count = max(1, size // len(unit))
        text = unit * count
        if len(text) < size:
            text += unit[: size - len(text)]
        return text[:size]

    escaped = '"' + '\\"' * max(1, (size - 1) // 2)
    shapes = [
        ("quote-escape", escaped[:size] if len(escaped) > size else escaped),
        ("quotes", tile('"')),
        ("single", tile("'")),
        ("triple-single", tile("'''")),
        ("triple-double", tile('"""')),
        ("block", tile("/*")),
        ("block-space", tile("/* ")),
        ("xml-comment", tile("<!--")),
        ("xml-comment-space", tile("<!-- ")),
        ("cdata", tile("<![CDATA[")),
        ("heredoc", tile("<<EOF\n")),
        ("dollar", tile("${")),
        ("quoted-dollar", tile('"${')),
        ("brace", tile("{")),
        ("bracket", tile("[")),
        ("brackets", tile("[]")),
    ]
    return shapes


def generic_corpus(size: int = MIB) -> list[tuple[str, str]]:
    """Flat repetitions that stress a line scanner."""
    units = ("a", " ", '"', "\\", "${", "=", "\t", "key")
    rows = [(f"unit-{unit!r}", (unit * size)[:size]) for unit in units]
    rows.append(("anchor", "a" * size + "!"))
    return rows


def fragments(pattern: str) -> list[str]:
    """Maximal literal runs of two or more characters in a pattern source."""
    found: list[str] = []
    buf: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            buf.append(pattern[index + 1])
            index += 2
            continue
        if char.isalnum() or char in "/*._-<>":
            buf.append(char)
        else:
            if len(buf) >= 2:
                found.append("".join(buf))
            buf = []
        index += 1
    if len(buf) >= 2:
        found.append("".join(buf))
    return found


def mutate_bytes(seed: int, count: int = 50, base: bytes = b"") -> list[bytes]:
    """``count`` payloads. Each fixture is flipped one to five times."""
    rng = random.Random(seed)
    if not base:
        base = b'{"a": 1, "b": [true, "x"]}\n'
    payloads: list[bytes] = []
    for _ in range(count):
        data = bytearray(base)
        flips = rng.randint(1, 5)
        for _flip in range(flips):
            if not data:
                data.append(rng.randrange(256))
                continue
            data[rng.randrange(len(data))] = rng.randrange(256)
        extra = bytes(rng.randrange(256) for _ in range(rng.randint(0, 32)))
        payloads.append(bytes(data) + extra)
    return payloads
