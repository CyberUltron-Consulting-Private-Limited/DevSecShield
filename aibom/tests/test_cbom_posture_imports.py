"""Import-closure probe. Posture modules must not load a banned library."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from support.airgap import engine_sources, imported_banned, module_name  # noqa: E402


def test_posture_import_closure_excludes_banned_modules() -> None:
    names = [module_name(path) for path in engine_sources()]
    assert names
    assert imported_banned(names) == []


def test_probe_reports_a_planted_requests_import(tmp_path: Path) -> None:
    (tmp_path / "requests.py").write_text("MARKER = 1\n", encoding="utf-8")
    (tmp_path / "plant.py").write_text("import requests\n", encoding="utf-8")
    assert imported_banned(["plant"], extra_paths=[tmp_path]) == ["requests"]
