import json
from pathlib import Path
import subprocess
import tempfile
import shutil
from git import Repo, GitCommandError
from rich.console import Console

def is_github_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and "github.com" in url

def clone_repo(url: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="repo_"))
    Console().print(f":package: Cloning [blue]{url}[/] → {tmp}")
    try:
        Repo.clone_from(url, tmp, depth=1)
    except GitCommandError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"Clone failed: {e}") from e
    return tmp

def run_sbom_scan(repo_url: str | None = None, PAT: str | None = None, sbom_json_file: str | None = None) -> dict | str:
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
        repo_url: The URL of the GitHub repository to scan.
        github_token: The GitHub token to use for authentication.
        sbom_json_file: The SBOM JSON file to scan.
    Returns:
        A dictionary containing the scan results.
        A string containing the error message if the scan fails.
    """
    try:
        cmd = None
        json_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")

        if sbom_json_file:
            Console().print(f"Starting scan 🟨 🔍 SBOM JSON file getting scanned for vulnerabilities",style="bold yellow")
            cmd =[
                "grype", 
                f"sbom:{sbom_json_file}", 
                "--output", 
                "json", 
                "--file", 
                json_temp.name
            ]

        if repo_url and is_github_url(repo_url):
            Console().print(f"Starting scan 🟨 🔍 Repo getting scanned for SBOM vulnerabilities",style="bold yellow")
            ind = repo_url.find("github.com")
            repo = repo_url[ind:]
            repo = f"https://{PAT}@{repo}"
            directory = clone_repo(repo)

            cmd =[
            "grype", 
            f"dir:{directory}",
            "--output",
            "json", 
            "--file", 
            json_temp.name
            ]

        
        if cmd:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"SBOM scan failed: {result.stderr}")
        else:
            raise ValueError("No Command to run")
        

        with open(json_temp.name, "r") as f:
            sbom_json = json.load(f)
        json_temp.close()

        # for testing
        with open("test.json", "w+") as f:
            json.dump(sbom_json, f, indent=2)

        Console().print(f"Scan completed 🟩 ✅ Vulnerabilities found: {len(sbom_json['matches'])}",style="bold green")
        return sbom_json
    except Exception as e:
        Console().print(f"Error: {e}",style="bold red")
        Console().print(f"Scan failed 🟥 ❌ with error: {e}",style="bold red")
        return str(e)


if __name__ == "__main__":
    result = run_sbom_scan(
        repo_url="https://github.com/CyberUltron-Nikhil/RiskPilot",
        PAT="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",
    )
    result = run_sbom_scan(
        sbom_json_file=("C:\\Users\\HP\\Desktop\\DevSecShield\\tools\\sbom_sca_utils\\test_cDX_sbom.json"),
    )
    # print(result)