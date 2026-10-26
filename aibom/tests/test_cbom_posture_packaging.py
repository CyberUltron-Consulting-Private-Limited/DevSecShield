"""Package-data loading. A probe file, three layouts, no shipped JSON."""

from __future__ import annotations

import hashlib
import importlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

PROBE = b'{"probe":1}\n'
PROJECT = Path(__file__).resolve().parents[1]


def _copy_tree(src: Path, dest: Path) -> None:
    shutil.copytree(
        src,
        dest,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )


def _write_probe(package: Path) -> None:
    data = package / "cbom" / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "probe_registry.json").write_bytes(PROBE)


def _digest(path_head: Path) -> str:
    saved_path = sys.path[:]
    saved = {
        name: module
        for name, module in sys.modules.items()
        if name == "aibom" or name.startswith("aibom.")
    }
    try:
        for name in list(saved):
            del sys.modules[name]
        sys.path.insert(0, str(path_head))
        module = importlib.import_module("aibom.cbom.posture.defaults")
        raw = module.read_data_bytes("probe_registry.json")
        return hashlib.sha256(raw).hexdigest()
    finally:
        sys.path[:] = saved_path
        for name in list(sys.modules):
            if name == "aibom" or name.startswith("aibom."):
                del sys.modules[name]
        sys.modules.update(saved)


def test_three_layouts_return_the_same_sha256(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _copy_tree(PROJECT / "src" / "aibom", root / "aibom")
    _write_probe(root / "aibom")
    extracted = tmp_path / "extracted"
    _copy_tree(root / "aibom", extracted / "aibom")
    archive = tmp_path / "pkg.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for path in (root / "aibom").rglob("*"):
            if path.is_file():
                handle.write(path, path.relative_to(root).as_posix())
    expected = hashlib.sha256(PROBE).hexdigest()
    assert _digest(root) == expected
    assert _digest(extracted) == expected
    assert _digest(archive) == expected


@pytest.mark.xfail(strict=False, reason="K-1")
def test_hatchling_wheel_build(tmp_path: Path) -> None:
    dest = tmp_path / "proj"
    dest.mkdir()
    _copy_tree(PROJECT / "src", dest / "src")
    shutil.copy(PROJECT / "pyproject.toml", dest / "pyproject.toml")
    readme = PROJECT / "README.md"
    if readme.is_file():
        shutil.copy(readme, dest / "README.md")
    config = PROJECT / "config"
    if config.is_dir():
        _copy_tree(config, dest / "config")
    completed = subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "wheel"],
        cwd=dest,
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
