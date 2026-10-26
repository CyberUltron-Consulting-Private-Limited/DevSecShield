"""Each in-house scanner finishes in under a second on a 1 MiB hostile line."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_CHILD = r"""
import time

from support.generators import structure_aware
from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.directives import parse_nginx, split_words
from aibom.cbom.posture.hcl import parse_hcl
from aibom.cbom.posture.jsonsafe import json_scan
from aibom.cbom.posture.codeowners import parse_codeowners
from aibom.cbom.posture.sqllabels import label_sql
from aibom.cbom.posture.textscan import XML_PAIRS, blank_noncode, blank_spans
from aibom.cbom.posture.tomlsafe import toml_scan
from aibom.cbom.posture.xmlsafe import xml_start_lines

sink = DiagnosticSink()

def run_hcl(text):
    parse_hcl(text, path="h.tf", sink=sink)

def run_nginx(text):
    parse_nginx(text, path="n.conf", sink=sink)

def run_words(text):
    split_words(text)

def run_blank(text):
    blank_spans(text, XML_PAIRS, unterminated="skip")

def run_owners(text):
    parse_codeowners(text, path="CODEOWNERS", sink=sink)

jobs = [
    ("json_scan", json_scan),
    ("toml_scan", toml_scan),
    ("blank_spans", run_blank),
    ("blank_noncode", blank_noncode),
    ("xml_start_lines", xml_start_lines),
    ("hcl", run_hcl),
    ("split_words", run_words),
    ("sql", label_sql),
    ("nginx", run_nginx),
    ("codeowners", run_owners),
]
for name, func in jobs:
    for label, text in structure_aware():
        started = time.perf_counter()
        func(text)
        elapsed = time.perf_counter() - started
        print(f"{name} {label} {elapsed:.4f}", flush=True)
"""


def test_hostile_inputs_finish_within_one_second() -> None:
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(root / "src"), str(root / "tests"), env.get("PYTHONPATH", "")]
    )
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD],
        check=False,
        capture_output=True,
        text=True,
        timeout=25,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert lines
    slow = []
    for line in lines:
        elapsed = float(line.rsplit(" ", 1)[-1])
        if elapsed >= 1.0:
            slow.append(line)
    assert slow == []
