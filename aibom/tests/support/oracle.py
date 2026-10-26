"""Oracle reader stub. WP8 fills the fixture trees."""

from __future__ import annotations

import json
from pathlib import Path


def read_oracle(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
