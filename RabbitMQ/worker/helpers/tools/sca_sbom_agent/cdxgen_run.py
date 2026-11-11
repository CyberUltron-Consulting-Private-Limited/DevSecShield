"""Run cdxgen CycloneDX 1.6 inventory (peer of bench/sbom/run.sh)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from helpers.context.cancellation import run_tool
import tempfile
from pathlib import Path

from rich.console import Console

console = Console()


def run_cdxgen(directory: Path | str) -> Path | None:
    """Generate CycloneDX 1.6 via npx @cyclonedx/cdxgen. Returns path or None."""
    if not shutil.which("npx"):
        console.print("npx not on PATH — cdxgen skipped", style="bold yellow")
        return None
    directory = Path(directory)
    out = Path(tempfile.mkstemp(suffix=".cdxgen.cdx.json")[1])
    try:
        cmd = [
            "npx",
            "--yes",
            "@cyclonedx/cdxgen@11",
            "-t",
            "python",
            "--spec-version",
            "1.6",
            "-o",
            str(out),
            str(directory),
        ]
        env = {**os.environ, "FETCH_LICENSE": "false"}
        result = run_tool(
            cmd, capture_output=True, text=True, timeout=600, env=env
        )
        if result.returncode != 0 or not out.is_file() or out.stat().st_size == 0:
            console.print(
                f"cdxgen failed: {(result.stderr or result.stdout or '')[:400]}",
                style="bold red",
            )
            out.unlink(missing_ok=True)
            return None
        json.loads(out.read_text(encoding="utf-8", errors="ignore"))
        console.print(f"cdxgen CycloneDX written → {out}", style="bold green")
        return out
    except Exception as e:
        console.print(f"cdxgen error: {e}", style="bold red")
        out.unlink(missing_ok=True)
        return None
