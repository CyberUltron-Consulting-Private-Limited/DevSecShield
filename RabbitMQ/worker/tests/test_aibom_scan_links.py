"""The worker's AI-BOM source scanner (the production AI-BOM path) never reads through a symbolic link.

An uploaded archive or a checkout is attacker-controlled.  Zip entries and git links are already written as plain
files (helpers/tests/test_scan_input_links.py); this proves the scanner itself, the second wall: a file link to a
file outside the tree, a file link to /proc/self/environ and a link to a directory outside the tree are neither
read nor reported, while the regular file next to them is (positive control).
"""
import os
import sys
from pathlib import Path

import pytest

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKER)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX links")


def _tree(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "steal.py").write_text("import anthropic\nclient = anthropic.Anthropic()\n")
    (outside / "requirements.txt").write_text("langchain==0.2.0\n")
    (outside / "weights.safetensors").write_bytes(b"\x00" * 64)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import openai\nclient = openai.OpenAI()\nmodel = 'gpt-4'\n")
    os.symlink(outside / "steal.py", repo / "leak.py")
    os.symlink("/proc/self/environ", repo / "env.py")
    os.symlink(outside / "requirements.txt", repo / "requirements.txt")
    os.symlink(outside / "weights.safetensors", repo / "model.safetensors")
    os.symlink(outside, repo / "linked")  # a directory link: everything above again
    return repo


def test_ai_bom_source_scanner_never_reads_through_a_link(tmp_path):
    from helpers.tools.ai_bom_agent import source_scanner as ss

    detections = ss.scan_directory(str(_tree(tmp_path)))
    locations = {d.location for d in detections}
    names = " ".join((d.component_name or "").lower() for d in detections)
    assert locations == {"app.py"}, locations  # positive control: the regular file is read
    assert "openai" in names or "gpt-4" in names
    for bait in ("anthropic", "langchain", "safetensors"):
        assert bait not in names, bait
