"""Static air-gap guard for posture engine modules."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from support.airgap import engine_sources, static_violations  # noqa: E402

_FORBIDDEN = (
    "import socket\n",
    "import subprocess\n",
    "from urllib.request import urlopen\n",
    "import requests\n",
    "import httpx\n",
    "import boto3\n",
    "value = eval('1')\n",
    "exec('value = 1')\n",
    "import jsonschema\n",
    "import importlib\n",
    "from importlib import import_module\n",
)

_ALLOWED = (
    "from importlib.resources import files\n",
    "import importlib.resources\n",
    "from importlib import resources\n",
    "import json\nfrom pathlib import Path\n",
    "import pydantic\nimport yaml\nfrom aibom.cbom.posture.model import fact_id\n",
    "from .model import fact_id\n",
)


def test_posture_modules_stay_inside_the_allow_list() -> None:
    paths = engine_sources()
    names = {path.name for path in paths}
    assert "assemble.py" in names
    assert "posture_iac_scan.py" in names
    findings: list[str] = []
    for path in paths:
        findings.extend(static_violations(path))
    assert findings == []


@pytest.mark.parametrize("source", _FORBIDDEN)
def test_a_deliberate_violation_is_reported(tmp_path: Path, source: str) -> None:
    path = tmp_path / "bad.py"
    path.write_text(source, encoding="utf-8")
    assert static_violations(path)


@pytest.mark.parametrize("source", _ALLOWED)
def test_stdlib_pydantic_yaml_aibom_and_importlib_resources_pass(
    tmp_path: Path, source: str
) -> None:
    path = tmp_path / "ok.py"
    path.write_text(source, encoding="utf-8")
    assert static_violations(path) == []
