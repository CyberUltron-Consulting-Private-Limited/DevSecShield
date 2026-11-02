# Knowledge-base extensions

One Python module per feature area. At import a module calls `kb_text.entry(code, ...)` for each new finding
code (same fields as `kb_text.py`) and exports `NODE_CODES` (scan-node classifier codes) and/or `CODE_CODES`
(code-scan engine codes). `build_kb.py` imports every `*.py` here in name order and merges them, so parallel
work never edits the same lines of `kb_text.py` or the code lists in `build_kb.py`.
