"""Run Syft inventory SBOM: CycloneDX 1.6 JSON plus Syft's native JSON (for version constraints).

Config: ``syft.yaml`` next to this file (offline; Python range requirements kept as guessed versions).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from helpers.context.cancellation import run_tool
from rich.console import Console

console = Console()

SYFT_CONFIG = Path(__file__).with_name("syft.yaml")
CDX_FORMAT = "cyclonedx-json@1.6"


def native_path(cdx_path: Path | str) -> Path:
    """Where ``run_syft`` writes Syft's native JSON for the CycloneDX file at ``cdx_path``."""
    return Path(str(cdx_path) + ".native.json")


def syft_command(directory: Path | str, cdx_out: Path | str) -> list[str]:
    return [
        "syft",
        f"dir:{directory}",
        "-c",
        str(SYFT_CONFIG),
        "-o",
        f"{CDX_FORMAT}={cdx_out}",
        "-o",
        f"syft-json={native_path(cdx_out)}",
        "-q",
    ]


def syft_env() -> dict[str, str]:
    # the config says the same; the variables also hold for a Syft that reads an older config schema
    return {
        **os.environ,
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        "SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS": "true",
    }


def run_syft(directory: Path | str) -> Path | None:
    """Generate a CycloneDX 1.6 JSON SBOM via Syft. Returns its path, or None if Syft is unavailable or failed."""
    if not shutil.which("syft"):
        console.print("Syft not on PATH — inventory tool skipped", style="bold yellow")
        return None
    out = Path(tempfile.mkstemp(suffix=".syft.cdx.json")[1])
    try:
        result = run_tool(syft_command(directory, out), capture_output=True, text=True, timeout=600, env=syft_env())
        if result.returncode != 0 or not out.is_file() or out.stat().st_size == 0:
            console.print(
                f"Syft failed: {result.stderr[:400] if result.stderr else 'empty output'}",
                style="bold red",
            )
            out.unlink(missing_ok=True)
            native_path(out).unlink(missing_ok=True)
            return None
        json.loads(out.read_text(encoding="utf-8", errors="ignore"))
        console.print(f"Syft CycloneDX written → {out}", style="bold green")
        return out
    except Exception as e:
        console.print(f"Syft error: {e}", style="bold red")
        out.unlink(missing_ok=True)
        native_path(out).unlink(missing_ok=True)
        return None


def _pinned(constraint: str) -> bool:
    c = constraint.strip()
    return c.startswith("==") and not any(ch in c[2:] for ch in "*,<>!~")


def _native_doc(cdx_path: Path | str | None) -> dict[str, Any]:
    if cdx_path is None:
        return {}
    path = native_path(cdx_path)
    if not path.is_file():
        return {}
    try:
        doc: Any = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}
    return doc if isinstance(doc, dict) else {}


_ACTION_REF = re.compile(r"^(?P<path>[^@\s]+)@(?P<sha>[0-9a-f]{40})$", re.I)


def action_pins(cdx_path: Path | str | None) -> dict[str, dict[str, str]]:
    """``tag purl -> {purl, version, tag}`` for every GitHub Action a workflow pins by commit SHA.

    Syft 1.5x names ``uses: actions/checkout@<sha> # v5`` after the comment (``pkg:github/actions/checkout@v5``)
    while cdxgen uses the SHA, so the same action was listed twice (review 6028132826 M3). The SHA is what runs.
    """
    out: dict[str, dict[str, str]] = {}
    for art in _native_doc(cdx_path).get("artifacts") or []:
        if not isinstance(art, dict) or not str(art.get("type") or "").startswith("github-action"):
            continue
        meta = art.get("metadata") if isinstance(art.get("metadata"), dict) else {}
        m = _ACTION_REF.match(str(meta.get("value") or "").strip())
        purl = str(art.get("purl") or "").split("?", 1)[0]
        if not m or not purl or "@" not in purl:
            continue
        sha = m.group("sha").lower()
        tag = str(art.get("version") or "").strip()
        if tag.lower() == sha:
            continue
        out[purl] = {"purl": f"{purl.rsplit('@', 1)[0]}@{sha}", "version": sha, "tag": tag}
    return out


_GO_MODULE = re.compile(r"^\s*module\s+(\S+)\s*$", re.M)


def own_go_modules(directory: Path | str | None) -> set[str]:
    """``pkg:golang/<module>`` of every ``go.mod`` in the scanned tree: the project itself, not a dependency
    (Syft 1.57 lists go-test-bench's own module as a component; review 6028132826 n3)."""
    if not directory:
        return set()
    out: set[str] = set()
    root = Path(directory)
    for here, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", "vendor", "node_modules"}]
        if "go.mod" in files:
            try:
                text = (Path(here) / "go.mod").read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            m = _GO_MODULE.search(text)
            if m:
                out.add(f"pkg:golang/{m.group(1).strip()}")
    return out


def version_constraints(cdx_path: Path | str | None) -> dict[str, str]:
    """``purl -> constraint`` for every package whose version Syft guessed from a range (python.guess-unpinned)."""
    doc = _native_doc(cdx_path)
    out: dict[str, str] = {}
    for art in doc.get("artifacts") or []:
        if not isinstance(art, dict):
            continue
        meta = art.get("metadata") if isinstance(art.get("metadata"), dict) else {}
        constraint = str(meta.get("versionConstraint") or "").strip()
        purl = str(art.get("purl") or "").split("?", 1)[0]
        if constraint and purl and not _pinned(constraint):
            out[purl] = constraint
    return out
