"""Run Syft inventory SBOM (CycloneDX JSON preferred)."""

from __future__ import annotations

import json
import shutil
import subprocess

from helpers.context.cancellation import run_tool
import tempfile
from pathlib import Path

from rich.console import Console

console = Console()


def run_syft(directory: Path | str) -> Path | None:
    """Generate a CycloneDX JSON SBOM via Syft. Returns path or None if unavailable."""
    if not shutil.which("syft"):
        console.print("Syft not on PATH — inventory tool skipped", style="bold yellow")
        return None
    directory = Path(directory)
    out = Path(tempfile.mkstemp(suffix=".syft.cdx.json")[1])
    try:
        cmd = [
            "syft",
            f"dir:{directory}",
            "-o",
            f"cyclonedx-json={out}",
            "-q",
        ]
        result = run_tool(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0 or not out.is_file() or out.stat().st_size == 0:
            console.print(
                f"Syft failed: {result.stderr[:400] if result.stderr else 'empty output'}",
                style="bold red",
            )
            out.unlink(missing_ok=True)
            return None
        # Validate JSON
        json.loads(out.read_text(encoding="utf-8", errors="ignore"))
        console.print(f"Syft CycloneDX written → {out}", style="bold green")
        return out
    except Exception as e:
        console.print(f"Syft error: {e}", style="bold red")
        out.unlink(missing_ok=True)
        return None
