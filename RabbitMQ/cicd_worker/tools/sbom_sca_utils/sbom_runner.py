import json
from pathlib import Path
import subprocess
import tempfile
import shutil
from git import Repo, GitCommandError
from rich.console import Console
from tools.context.scan_context import clone_repo, is_github_url, GithubContext, GitlabContext, BitbucketContext

def run_sbom_scan(
    context : GithubContext | GitlabContext | BitbucketContext , 
    sbom_json_file: str | None = None) -> dict | str:
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

        # old method of cloning the repository
        # if repo_url and is_github_url(repo_url):
        #     Console().print(f"Starting scan 🟨 🔍 Repo getting scanned for SBOM vulnerabilities",style="bold yellow")
        #     ind = repo_url.find("github.com")
        #     repo = repo_url[ind:]
        #     repo = f"https://{PAT}@{repo}"
        #     directory = clone_repo(repo)

        #     cmd =[
        #     "grype", 
        #     f"dir:{directory}",
        #     "--output",
        #     "json", 
        #     "--file", 
        #     json_temp.name
        #     ]
        directory = None
        if context and isinstance(context, GithubContext):
            directory = clone_repo(context.repo_url)
        elif context and isinstance(context, GitlabContext):
            directory = clone_repo(context.repo_url)
        elif context and isinstance(context, BitbucketContext):
            directory = clone_repo(context.repo_url)
        else : 
            raise ValueError(f"Unsupported context: {context}")
        

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
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"SBOM scan failed: {result.stderr}")
        else:
            raise ValueError("No Command to run")
        

        with open(json_temp.name, "r") as f:
            sbom_json = json.load(f)
        json_temp.close()

        # for testing
        # with open("sbom_test.json", "w+") as f:
        #     json.dump(sbom_json, f, indent=2)

        try:
            Console().print("Cleaning up temp directory",style="dim yellow")
            shutil.rmtree(directory)
        except Exception as e:
            Console().print(f"Error: {e}",style="dim red")
            pass

        Console().print(f"Scan completed 🟩 ✅ Vulnerabilities found: {len(sbom_json['matches'])}",style="bold green")
        return sbom_json
    except Exception as e:
        Console().print(f"Scan failed 🟥 ❌ with error: {e}",style="bold red")
        raise e


if __name__ == "__main__":
    result = run_sbom_scan(
        repo_url="https://github.com/CyberUltron-Nikhil/RiskPilot",
        PAT="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",
    )
    result = run_sbom_scan(
        sbom_json_file=("C:\\Users\\HP\\Desktop\\DevSecShield\\tools\\sbom_sca_utils\\test_cDX_sbom.json"),
    )
    # print(result)