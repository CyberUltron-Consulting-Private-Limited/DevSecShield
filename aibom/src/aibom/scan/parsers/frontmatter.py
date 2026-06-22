"""YAML front-matter extraction for Markdown cards.

Model cards and dataset cards (HuggingFace / Datasheet convention) carry their
machine-readable metadata in a leading ``---`` fenced YAML block. This helper
splits that block from the prose body. PURE: no I/O beyond the passed text.
"""

from __future__ import annotations

from typing import Any

import yaml

_FENCE = "---"


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Return ``(frontmatter_dict, body)`` for Markdown ``text``.

    If there is no leading ``---`` YAML fence, returns ``({}, text)``. A present
    but empty/non-mapping front-matter block yields ``{}``.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != _FENCE:
        return {}, text

    for idx in range(1, len(lines)):
        if lines[idx].strip() == _FENCE:
            raw = "\n".join(lines[1:idx])
            body = "\n".join(lines[idx + 1 :]).lstrip("\n")
            loaded = yaml.safe_load(raw) if raw.strip() else None
            return (loaded if isinstance(loaded, dict) else {}), body

    # Unterminated fence -> treat the whole thing as body (no metadata).
    return {}, text


__all__ = ["split_frontmatter"]
