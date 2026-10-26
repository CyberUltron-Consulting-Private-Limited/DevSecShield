"""Pure-Python PDF content-stream reader used by the posture document pins.

Copied from the reader already used by the MEDIUM document tests. No poppler.
"""

from __future__ import annotations

import base64
import contextlib
import re
import zlib

_PDF_STRING = rb"\((?:\\.|[^\\()])*\)"
_PDF_BREAK_OPS = rb"(?<![A-Za-z0-9/])(?:T\*|Td|TD|Tm|ET|BT)(?![A-Za-z0-9*])"
_PDF_TOKEN = re.compile(_PDF_STRING + rb"|" + _PDF_BREAK_OPS, re.S)
_SIMPLE_ESCAPES = {110: b"\n", 114: b"\r", 116: b"\t", 98: b"\b", 102: b"\f"}


def _pdf_unescape(literal: bytes) -> str:
    body, out, index = literal[1:-1], bytearray(), 0
    while index < len(body):
        byte = body[index]
        if byte != 0x5C or index + 1 >= len(body):
            out.append(byte)
            index += 1
            continue
        nxt = body[index + 1]
        if 0x30 <= nxt <= 0x37:
            cursor, digits = index + 1, b""
            while cursor < len(body) and len(digits) < 3 and 0x30 <= body[cursor] <= 0x37:
                digits += bytes([body[cursor]])
                cursor += 1
            out.append(int(digits, 8) & 0xFF)
            index = cursor
        elif nxt in (0x0A, 0x0D):
            index += 2
        else:
            out += _SIMPLE_ESCAPES.get(nxt, bytes([nxt]))
            index += 2
    return out.decode("cp1252", errors="replace")


def content_streams(raw: bytes) -> list[bytes]:
    streams: list[bytes] = []
    for match in re.finditer(rb"(?<!end)stream\r?\n(.*?)endstream", raw, re.S):
        data = match.group(1).strip()
        with contextlib.suppress(ValueError, OverflowError):
            data = base64.a85decode(data, adobe=True)
        with contextlib.suppress(zlib.error):
            data = zlib.decompress(data)
        streams.append(data)
    return streams


def pdf_pages_text(raw: bytes) -> list[str]:
    """Text of each page. A text-positioning operator starts a new line."""
    pages: list[str] = []
    for stream in content_streams(raw):
        if b" Tf" not in stream or b"BT" not in stream:
            continue
        lines: list[str] = []
        pending: list[str] = []
        for token in _PDF_TOKEN.finditer(stream):
            value = token.group(0)
            if value.startswith(b"("):
                pending.append(_pdf_unescape(value))
            elif pending:
                lines.append("".join(pending))
                pending = []
        if pending:
            lines.append("".join(pending))
        pages.append("\n".join(lines))
    return pages


def pdf_text(raw: bytes) -> str:
    return "\n".join(pdf_pages_text(raw))
