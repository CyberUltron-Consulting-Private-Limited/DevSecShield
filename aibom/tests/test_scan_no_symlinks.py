"""AI-BOM (non-CBOM) scanners never follow a symbolic link (rule of aibom.cbom.files).

A cloned repository is attacker-controlled: ``key.pem -> /proc/self/environ`` or a
link to a directory outside the tree must not put the worker's environment or host
files into the BOM. The repository below has one regular file (the positive control)
and, for every AI-BOM scanner, a file link it would otherwise read, plus a linked
directory holding the same bait.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from aibom.scan import safe_files
from aibom.scan.pipeline import scan_repo

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX links")

OUTSIDE_KEY = "sk-outside0123456789abcdef"
BAIT_NAMES = (
    "transformers",
    "anthropic",
    "langchain",
    "outside-pkg",
    "OutsideModel",
    "weights.safetensors",
    "model.safetensors",
)


def _outside(base: Path) -> Path:
    out = base / "outside"
    out.mkdir()
    (out / "steal.py").write_text(
        f'import transformers\nOPENAI_API_KEY = "{OUTSIDE_KEY}"\n'
    )
    (out / "reqs.txt").write_text("anthropic==0.30.0\n")
    (out / "pyproject.toml").write_text(
        '[project]\nname = "outside-pkg"\ndependencies = ["langchain"]\n'
    )
    (out / "weights.safetensors").write_bytes(b"\x00outside-weights")
    (out / "model_card.md").write_text("---\nname: OutsideModel\nversion: 1.0\n---\n")
    (out / "config.json").write_text('{"architectures": ["OutsideForCausalLM"]}\n')
    (out / "infra.tf").write_text('resource "aws_bedrock_model" "x" {}\n')
    (out / "Dockerfile").write_text("FROM ollama/ollama:latest\n")
    (out / "hosts.yaml").write_text("url: https://api.anthropic.com/v1\n")
    return out


def _repo(base: Path, outside: Path) -> Path:
    repo = base / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        'import torch\nOPENAI_API_KEY = "sk-inrepo0123456789abcdef"\n'
    )
    links = {
        "key.pem": "/proc/self/environ",
        "leak.py": "/proc/self/environ",
        "leak.tf": outside / "infra.tf",
        "leak.yaml": outside / "hosts.yaml",
        "requirements.txt": outside / "reqs.txt",
        "model_card.md": outside / "model_card.md",
        "config.json": outside / "config.json",
        "Dockerfile": outside / "Dockerfile",
        "model.safetensors": outside / "weights.safetensors",
        "linked": outside,  # a directory link: all of the above again + pyproject
    }
    for name, target in links.items():
        os.symlink(target, repo / name)
    return repo


@pytest.fixture()
def scanned(tmp_path):
    # Before the fix this scan reported OutsideModel, anthropic, AWS Bedrock, Ollama,
    # the outside weights' hash, and model names / API hosts read from the worker's
    # /proc/self/environ through leak.py.
    repo = _repo(tmp_path, _outside(tmp_path))
    return scan_repo(str(repo), level=4)


def test_no_link_target_reaches_the_bom(scanned):
    names = {c.name for c in scanned.components}
    sources = {(c.properties or {}).get("discovery:source") for c in scanned.components}
    # positive control: the one regular file is still read (code-import, secret)
    assert "torch" in names
    secrets = [c for c in scanned.components if c.kind == "secret"]
    assert [(c.properties or {}).get("discovery:source") for c in secrets] == ["app.py"]
    # nothing behind a link: environment, manifests, card, weights, IaC, image, host
    for bait in BAIT_NAMES:
        assert bait not in names, bait
    linked = {s for s in sources if s and (s.startswith("linked") or "leak" in s)}
    assert not linked and "key.pem" not in sources
    kinds = ("cloud_service", "endpoint", "container", "model")
    assert not [c for c in scanned.components if c.kind in kinds]
    dump = repr(scanned)
    for canary in (OUTSIDE_KEY, "outside0123", "OutsideForCausalLM"):
        assert canary not in dump


def test_walk_skips_links_and_skip_dirs_and_stays_under_root(tmp_path):
    repo = _repo(tmp_path, _outside(tmp_path))
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "dep.py").write_text("import torch\n")
    (repo / "src").mkdir()
    (repo / "src" / "ok.py").write_text("x = 1\n")
    files = safe_files.walk_files(repo, {"node_modules"})
    assert [p.relative_to(repo).as_posix() for p in files] == ["app.py", "src/ok.py"]


def test_reads_refuse_links_fifos_and_oversized_files(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("hello\r\nworld\n")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert safe_files.read_text(real) == "hello\nworld\n"
    assert safe_files.read_text(link) is None
    assert safe_files.read_text(fifo) is None  # never blocks on a FIFO
    assert safe_files.read_text(real, max_bytes=3) is None
    assert safe_files.read_text(tmp_path / "missing") is None
    assert safe_files.is_regular_file(real)
    assert not safe_files.is_regular_file(link)
    assert not safe_files.is_regular_file(fifo)
    with safe_files.open_regular(real) as fh:
        assert fh.read() == b"hello\r\nworld\n"
    for refused in (link, fifo):
        with pytest.raises(OSError):
            safe_files.open_regular(refused)
