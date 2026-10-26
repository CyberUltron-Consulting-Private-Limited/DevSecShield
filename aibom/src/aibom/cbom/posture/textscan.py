"""Linear blanking of comments, CDATA, and docstrings. No regex rescans."""

from __future__ import annotations

XML_PAIRS: tuple[tuple[str, str], ...] = (
    ("<!--", "-->"),
    ("<![CDATA[", "]]>"),
)
_TRIPLE_PAIRS: tuple[tuple[str, str], ...] = (('"""', '"""'), ("'''", "'''"))
_BLOCK_PAIRS: tuple[tuple[str, str], ...] = (("/*", "*/"),)

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[object, ...] = ()
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS


def _blank_keep_nl(chunk: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in chunk)


def blank_spans(
    text: str,
    pairs: tuple[tuple[str, str], ...],
    *,
    unterminated: str,
) -> str | None:
    """Blank opener-to-closer spans. Newlines stay. One pass over ``pairs``.

    ``unterminated="error"`` returns None when a closer is missing.
    ``unterminated="skip"`` leaves that opener in place and does not search
    for it again.
    """
    cursor = 0
    known: dict[str, int | None] = {opener: None for opener, _closer in pairs}
    dead: set[str] = set()
    pieces: list[str] = []
    copied = 0
    length = len(text)
    while cursor < length:
        best_at: int | None = None
        best: tuple[str, str] | None = None
        for opener, closer in pairs:
            if opener in dead:
                continue
            found = known[opener]
            if found is None or found >= 0 and found < cursor:
                found = text.find(opener, cursor)
                known[opener] = found
            if found is None or found < 0:
                continue
            if best_at is None or found < best_at:
                best_at = found
                best = (opener, closer)
        if best is None or best_at is None:
            break
        opener, closer = best
        close_at = text.find(closer, best_at + len(opener))
        if close_at < 0:
            if unterminated == "error":
                return None
            dead.add(opener)
            cursor = best_at + len(opener)
            continue
        end = close_at + len(closer)
        pieces.append(text[copied:best_at])
        pieces.append(_blank_keep_nl(text[best_at:end]))
        copied = end
        cursor = end
    pieces.append(text[copied:])
    return "".join(pieces)


def blank_noncode(text: str) -> str:
    """Blank triple-quoted spans, then block comments. Line count is kept."""
    quoted = blank_spans(text, _TRIPLE_PAIRS, unterminated="skip")
    if quoted is None:
        quoted = text
    blocked = blank_spans(quoted, _BLOCK_PAIRS, unterminated="skip")
    if blocked is None:
        return quoted
    return blocked
