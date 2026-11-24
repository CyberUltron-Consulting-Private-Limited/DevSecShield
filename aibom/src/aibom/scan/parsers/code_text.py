"""Source text with comments and string literals masked, offsets preserved.

The SDK-client detection (``net_env_scan``) must match code, never prose:
``# client = OpenAI()`` in a comment, or ``"OpenAI("`` inside a string, is not a
call (review 6037909737 of #498, M1). :func:`mask` returns two copies of the text
in which every masked character is a space (newlines kept), so a match offset in
either copy is the same offset in the original:

* ``code``: comments blanked, string literals kept (an import such as
  ``from 'openai'`` is a string in JavaScript);
* ``bare``: comments and the contents of string literals blanked (the quotes are
  kept), for matching calls and reading their arguments.

A small hand-written scanner, not a parser: Python (``#``, single, double and
triple quotes), JavaScript / TypeScript (``//``, ``/* */``, quotes and template
literals) and ``#`` comments for configuration files. Deterministic, stdlib only.
"""

from __future__ import annotations

_JS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})


def language_of(source: str) -> str:
    """``js`` for a JavaScript / TypeScript file, else ``py`` (``#`` comments)."""
    dot = source.rfind(".")
    return "js" if dot >= 0 and source[dot:].lower() in _JS else "py"


def _blank(chars: list[str], start: int, end: int) -> None:
    for k in range(start, end):
        if chars[k] != "\n":
            chars[k] = " "


def mask(text: str, lang: str = "py") -> tuple[str, str]:
    """``(code, bare)``: comments blanked; comments and string contents blanked."""
    n = len(text)
    code = list(text)
    bare = list(text)
    i = 0
    while i < n:
        c = text[i]
        if (lang == "py" and c == "#") or (lang == "js" and text.startswith("//", i)):
            j = text.find("\n", i)
            j = n if j < 0 else j
            _blank(code, i, j)
            _blank(bare, i, j)
            i = j
            continue
        if lang == "js" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            _blank(code, i, j)
            _blank(bare, i, j)
            i = j
            continue
        if c in "'\"" or (lang == "js" and c == "`"):
            quote = c * 3 if lang == "py" and text.startswith(c * 3, i) else c
            j = i + len(quote)
            closed = False
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text.startswith(quote, j):
                    closed = True
                    break
                if len(quote) == 1 and quote != "`" and text[j] == "\n":
                    break  # an unterminated one-line string ends at the line
                j += 1
            j = min(j, n)
            _blank(bare, i + len(quote), j)
            i = j + (len(quote) if closed else 0)
            continue
        i += 1
    return "".join(code), "".join(bare)


def call_arguments(bare: str, open_paren: int, limit: int = 20000) -> str | None:
    """The text between the parenthesis at ``open_paren`` and its balanced closing
    parenthesis in ``bare`` text, or None when it does not close within ``limit``
    characters (the arguments cannot be read)."""
    if open_paren >= len(bare) or bare[open_paren] != "(":
        return None
    depth = 0
    end = min(len(bare), open_paren + limit)
    for k in range(open_paren, end):
        ch = bare[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return bare[open_paren + 1 : k] if ch == ")" else None
    return None


__all__ = ["call_arguments", "language_of", "mask"]
