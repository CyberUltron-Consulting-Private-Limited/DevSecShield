"""SQL statement labeller. The statement text is not retained."""

from __future__ import annotations

from aibom.cbom.posture.diagnostics import safe_parse

SQL_LABELS = frozenset(
    {
        "tde_database_encryption_key",
        "tde_enable",
        "always_encrypted_column",
        "mysql_table_encryption",
        "pgcrypto_symmetric",
        "pgcrypto_public_key",
        "mysql_encrypted_tablespace",
    }
)

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[object, ...] = ()
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS

_CREATE = "CREATE"
_TABLE = "TABLE"
_TABLESPACE = "TABLESPACE"


def label_sql(text: str) -> tuple[tuple[str, int], ...]:
    """Return ``(label, line)`` pairs. Keywords inside strings never match."""
    labels: list[tuple[str, int]] = []
    words: list[str] = []
    mode: str | None = None
    expect_y = False
    after_with = False
    index = 0
    line = 1
    length = len(text)

    def emit(label: str, at: int) -> None:
        if label in SQL_LABELS:
            labels.append((label, at))

    def push(word: str, at: int) -> None:
        nonlocal mode, expect_y, after_with
        token = word.upper()
        words.append(token)
        del words[:-8]
        if token == _TABLESPACE and _prev(1) == _CREATE:
            mode = "tablespace"
        elif token == _TABLE and _prev(1) == _CREATE:
            mode = "table"
        if len(words) >= 4 and words[-4:] == [_CREATE, "DATABASE", "ENCRYPTION", "KEY"]:
            emit("tde_database_encryption_key", at)
        if (
            len(words) >= 6
            and words[-6] == "ALTER"
            and words[-5] == "DATABASE"
            and words[-3:] == ["SET", "ENCRYPTION", "ON"]
        ):
            emit("tde_enable", at)
        if after_with and token == "COLUMN_ENCRYPTION_KEY":
            emit("always_encrypted_column", at)
            after_with = False
        if token == "ENCRYPTION":
            expect_y = True
        elif token not in {"=", "WITH", "ENCRYPTION"}:
            expect_y = False
        if token in {"PGP_SYM_ENCRYPT", "PGP_PUB_ENCRYPT"}:
            return

    def _prev(back: int) -> str:
        if len(words) > back:
            return words[-1 - back]
        return ""

    while index < length:
        char = text[index]
        if char == "\n":
            line += 1
            index += 1
            continue
        if char.isspace():
            index += 1
            continue
        if text.startswith("--", index):
            newline = text.find("\n", index)
            if newline < 0:
                break
            index = newline
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            if close < 0:
                break
            line += text.count("\n", index, close)
            index = close + 2
            continue
        if char == "'":
            value, index, line = _skip_quote(text, index, line)
            if expect_y and value is not None and value.upper() == "Y":
                if mode == "tablespace":
                    emit("mysql_encrypted_tablespace", line)
                elif mode == "table":
                    emit("mysql_table_encryption", line)
            expect_y = False
            continue
        if char == "$":
            index, line = _skip_dollar(text, index, line)
            continue
        if char in '"`':
            index, line = _skip_wrapped(text, index, line, char)
            continue
        if char == "[":
            index, line = _skip_wrapped(text, index, line, "]", opener="[")
            continue
        if char == "(":
            if words and words[-1] == "PGP_SYM_ENCRYPT":
                emit("pgcrypto_symmetric", line)
            elif words and words[-1] == "PGP_PUB_ENCRYPT":
                emit("pgcrypto_public_key", line)
            elif len(words) >= 2 and words[-2:] == ["ENCRYPTED", "WITH"]:
                after_with = True
            index += 1
            continue
        if char == ";":
            mode = None
            expect_y = False
            after_with = False
            words.clear()
            index += 1
            continue
        if char == "=":
            if words and words[-1] == "ENCRYPTION":
                expect_y = True
            index += 1
            continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            push(text[index:end], line)
            index = end
            continue
        index += 1
    return tuple(labels)


def _skip_quote(text: str, index: int, line: int) -> tuple[str | None, int, int]:
    index += 1
    buf: list[str] = []
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\n":
            line += 1
        if char == "'":
            if index + 1 < length and text[index + 1] == "'":
                buf.append("'")
                index += 2
                continue
            return "".join(buf), index + 1, line
        buf.append(char)
        index += 1
    return None, length, line


def _skip_dollar(text: str, index: int, line: int) -> tuple[int, int]:
    cursor = index + 1
    length = len(text)
    while cursor < length and (text[cursor].isalnum() or text[cursor] == "_"):
        cursor += 1
    if cursor >= length or text[cursor] != "$":
        return index + 1, line
    tag = text[index : cursor + 1]
    end = text.find(tag, cursor + 1)
    if end < 0:
        return length, line + text.count("\n", index)
    line += text.count("\n", index, end)
    return end + len(tag), line


def _skip_wrapped(
    text: str,
    index: int,
    line: int,
    closer: str,
    opener: str | None = None,
) -> tuple[int, int]:
    start = index + (0 if opener else 1)
    if opener:
        start = index + 1
    end = text.find(closer, start)
    if end < 0:
        return len(text), line + text.count("\n", index)
    line += text.count("\n", index, end)
    return end + len(closer), line


def load_sql(data: bytes, record, *, path: str = "", sink: object | None = None):
    def run(raw: bytes) -> tuple[tuple[str, int], ...]:
        try:
            return label_sql(raw.decode("utf-8", "replace"))
        except Exception:
            if sink is not None:
                target = getattr(sink, "diagnostics", sink)
                target.add("parse_error", path, 0)
            raise

    result = safe_parse(run, data, record)
    return result if isinstance(result, tuple) else ()
