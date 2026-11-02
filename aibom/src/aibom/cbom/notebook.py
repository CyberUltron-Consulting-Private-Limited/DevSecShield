"""A Jupyter notebook (``.ipynb``) read as the source it holds.

A notebook is JSON: its code lives in cell ``source`` strings and what the code printed is saved in cell
``outputs``. The lanes read code, so a notebook is turned into one *virtual source*: the code cells in order (IPython
``%``/``%%`` magics and ``!`` shell escapes blanked, so the rest parses as Python), each followed by its text outputs
as comment lines starting with :data:`OUTPUT_PREFIX` (comments are never read as code, but a key a cell printed is
still visible to the material lane). Markdown cells and image / HTML outputs are dropped. Line numbers the CBOM
reports for a notebook are lines of this virtual source; :func:`cell_of_line` maps one back to its cell.

nbformat 4 (``cells``) and 3 (``worksheets[].cells``, ``input`` / ``prompt_number``) are read. The size limit of a
scan applies to the virtual source, not to the JSON (whose embedded images can be large).
"""

from __future__ import annotations

import json

#: Prefix of an output line in the virtual source (a Python comment).
OUTPUT_PREFIX = "#> "
#: Largest notebook JSON read (images inflate it; they are dropped before the scan's own size limit applies).
MAX_NOTEBOOK_BYTES = 20_000_000
_MAX_OUTPUT_LINES = 200  # per output: a long data dump is not code


def _lines(value: object) -> list[str]:
    if isinstance(value, list):
        text = "".join(str(v) for v in value)
    elif isinstance(value, str):
        text = value
    else:
        return []
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _code_line(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith(("%", "!")):  # IPython magic / shell escape
        return ""
    return line


def _cells(doc: dict) -> list[dict]:
    if isinstance(doc.get("cells"), list):
        return [c for c in doc["cells"] if isinstance(c, dict)]
    out: list[dict] = []
    for sheet in doc.get("worksheets") or []:  # nbformat 3
        if isinstance(sheet, dict):
            out.extend(c for c in sheet.get("cells") or [] if isinstance(c, dict))
    return out


def _output_text(output: dict) -> list[str]:
    kind = output.get("output_type")
    if kind == "stream":
        return _lines(output.get("text"))
    if kind in ("execute_result", "display_data", "pyout"):
        data = output.get("data")
        if isinstance(data, dict) and "text/plain" in data:
            return _lines(data["text/plain"])
        return _lines(output.get("text"))  # nbformat 3 keeps text/plain at the top level
    if kind in ("error", "pyerr"):
        return [str(t) for t in output.get("traceback") or []][:20]
    return []


def virtual_source(raw: bytes) -> tuple[str, list[tuple[int, str]]] | None:
    """(virtual source text, per-line ``(cell number, "code" | "output")``) or None when not a notebook."""
    try:
        doc = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    cells = _cells(doc)
    if not cells and "cells" not in doc and "worksheets" not in doc:
        return None
    lines: list[str] = []
    origin: list[tuple[int, str]] = []
    for number, cell in enumerate(cells, start=1):
        if cell.get("cell_type") != "code":
            continue
        source = _lines(cell.get("source", cell.get("input")))
        if source and source[-1] == "":  # "x = 1\n" is one line
            source.pop()
        for line in source:
            lines.append(_code_line(line))
            origin.append((number, "code"))
        for output in cell.get("outputs") or []:
            if not isinstance(output, dict):
                continue
            for line in _output_text(output)[:_MAX_OUTPUT_LINES]:
                if line.strip():
                    lines.append(OUTPUT_PREFIX + line)
                    origin.append((number, "output"))
    return "\n".join(lines), origin


def cell_of_line(origin: list[tuple[int, str]], line: int) -> tuple[int, str] | None:
    """The (cell number, code|output) a 1-based virtual-source line came from."""
    return origin[line - 1] if 0 < line <= len(origin) else None


def is_notebook(name: str) -> bool:
    return name.lower().endswith(".ipynb")


__all__ = ["MAX_NOTEBOOK_BYTES", "OUTPUT_PREFIX", "cell_of_line", "is_notebook", "virtual_source"]
