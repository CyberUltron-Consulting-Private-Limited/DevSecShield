import json
from pathlib import Path
import subprocess
import tempfile
import shutil
from git import Repo, GitCommandError
from rich.console import Console
from helpers.context.scan_context import clone_repo, is_github_url, GithubContext, GitlabContext, BitbucketContext

def run_sbom_scan(
    directory: Path | str |None = None,
    ) -> dict | str:
    """
    Run a SBOM scan on a given directory.
    Or
    Run a SBOM scan on a given SBOM JSON file.
    If both directory and sbom_json_file are provided, the directory will be scanned.
    Supported SBOM formats:
    - CycloneDX
    - SPDX
    - Syft

    Args:
        directory: The directory to scan.
    Returns:
        A dictionary containing the scan results.
        A string containing the error message if the scan fails.
    """
    try:
        cmd = None
        
    
        json_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")

        if directory:
            cmd =[
                "grype", 
                f"dir:{directory}",
                "--output",
                "json", 
                "--file", 
                json_temp.name
            ]
        else:
            raise ValueError(f"Directory not provided")

        if cmd:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                raise RuntimeError(f"SBOM scan failed: {result.stderr}")
        else:
            raise ValueError("No Command to run")
        

        with open(json_temp.name, "r",errors="ignore") as f:
            sbom_json = json.load(f)
        json_temp.close()

        # for testing
        # with open("sbom_test.json", "w+") as f:
        #     json.dump(sbom_json, f, indent=2)


        Console().print(f"Scan completed 🟩 ✅ Vulnerabilities found: {len(sbom_json['matches'])}",style="bold green")
        return sbom_json
    except Exception as e:
        Console().print(f"Scan failed 🟥 ❌ with error: {e}",style="bold red")
        raise e