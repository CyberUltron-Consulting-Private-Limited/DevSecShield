import json
from pathlib import Path
import subprocess
import tempfile
import shutil
from git import Repo, GitCommandError
from rich.console import Console
from helpers.tools.sca_sbom_agent.grype_errors import grype_failure_reason
from helpers.context.scan_context import clone_repo, is_github_url, GithubContext, GitlabContext, BitbucketContext

def run_sbom_scan(
    directory: Path | str | None = None,
    sbom_file: Path | str | None = None,
) -> dict | str:
    """
    Run Grype vuln assessment on a directory or existing SBOM file.

    Prefer ``sbom:<path>`` when ``sbom_file`` is set (Syft/cdxgen inventory);
    fall back to ``dir:<directory>``.

    Supported SBOM formats for ``sbom_file``:
    - CycloneDX
    - SPDX
    - Syft

    Args:
        directory: The directory to scan (fallback / required if no sbom_file).
        sbom_file: Optional inventory SBOM path for ``grype sbom:<path>``.
    Returns:
        A dictionary containing the scan results.
    """
    try:
        json_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        target: str | None = None

        if sbom_file:
            p = Path(sbom_file)
            if p.is_file():
                target = f"sbom:{p}"
        if target is None:
            if not directory:
                raise ValueError("Directory not provided")
            target = f"dir:{directory}"

        cmd = [
            "grype",
            target,
            "--output",
            "json",
            "--file",
            json_temp.name,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            # Prefer SBOM target; if it fails and we have a directory, retry dir:.
            if target.startswith("sbom:") and directory:
                Console().print(
                    f"Grype sbom: target failed ({(result.stderr or '')[:200]}); "
                    "falling back to dir:",
                    style="bold yellow",
                )
                cmd = [
                    "grype",
                    f"dir:{directory}",
                    "--output",
                    "json",
                    "--file",
                    json_temp.name,
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                # the cause, not grype's first (harmless) warning line: the scan's failure reason keeps one line
                raise RuntimeError(f"SBOM scan failed: {grype_failure_reason(result.stderr)}")

        with open(json_temp.name, "r", errors="ignore") as f:
            sbom_json = json.load(f)
        json_temp.close()

        matches = sbom_json.get("matches") if isinstance(sbom_json, dict) else None
        n = len(matches) if isinstance(matches, list) else 0
        Console().print(
            f"Scan completed 🟩 ✅ Vulnerabilities found: {n}",
            style="bold green",
        )
        return sbom_json
    except Exception as e:
        Console().print(f"Scan failed 🟥 ❌ with error: {e}", style="bold red")
        raise e