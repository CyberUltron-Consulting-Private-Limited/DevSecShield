"""Run cdxgen (CycloneDX 1.6) inventory: the pinned binary the scan-worker image installs (RabbitMQ/worker/Dockerfile).

It reads every ecosystem's manifests and lock files it recognises (no ``-t``), with ``--no-install-deps``: it never
runs pip / npm / mvn on the scanned code (that would execute the repository's build scripts and needs a network).
There is no ``npx`` fallback: a download at scan time would not work air-gapped and is not pinned.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from helpers.context.cancellation import run_tool
from rich.console import Console

console = Console()


def cdxgen_binary() -> str | None:
    explicit = (os.environ.get("CDXGEN_BIN") or "").strip()
    if explicit:
        return explicit if Path(explicit).is_file() else None
    return shutil.which("cdxgen")


def cdxgen_command(binary: str, directory: Path | str, out: Path | str) -> list[str]:
    return [binary, "--spec-version", "1.6", "--no-install-deps", "-o", str(out), str(directory)]


def cdxgen_env() -> dict[str, str]:
    return {
        **os.environ,
        "FETCH_LICENSE": "false",  # registry licence lookups need a network; the backend resolves licences offline-first
    }


def run_cdxgen(directory: Path | str) -> Path | None:
    """Generate CycloneDX 1.6 via cdxgen. Returns the path, or None when cdxgen is not installed or failed."""
    binary = cdxgen_binary()
    if not binary:
        console.print("cdxgen not installed — inventory tool skipped", style="bold yellow")
        return None
    out = Path(tempfile.mkstemp(suffix=".cdxgen.cdx.json")[1])
    try:
        result = run_tool(cdxgen_command(binary, directory, out), capture_output=True, text=True, timeout=600,
                          env=cdxgen_env())
        if result.returncode != 0 or not out.is_file() or out.stat().st_size == 0:
            console.print(
                f"cdxgen failed: {(result.stderr or result.stdout or '')[-400:]}",
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
