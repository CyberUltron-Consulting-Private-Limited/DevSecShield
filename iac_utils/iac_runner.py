import json
from pathlib import Path
import subprocess
import tempfile
import shutil
from typing import Literal
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


def run_iac_scan(repo_url: str | None = None, PAT: str | None = None , mode : Literal["tfsec", "trivy"] = "tfsec") -> dict | str:
    try:
        if repo_url and is_github_url(repo_url):
            Console().print(f"Starting scan 🟨 🔍 Repo getting scanned for IAC vulnerabilities using {mode} mode",style="bold yellow")
            ind = repo_url.find("github.com")
            repo = repo_url[ind:]
            repo = f"https://{PAT}@{repo}"
            directory = clone_repo(repo)
        else:
            raise ValueError("Invalid repository URL")
        

        json_temp = tempfile.NamedTemporaryFile(delete=False,suffix=".json")
        
        if mode == "tfsec":
            cmd =[
                "tfsec",
                f"{directory}",
                "--format",
                "json",
                "--out",
                f"{json_temp.name}",
            ]
        elif mode == "trivy":
            cmd =[
            "trivy",
            "config",
            "--output",
            f"{json_temp.name}",
            "--format",
            "json",
            f"{directory}",
        ]

        # Use for trivy  🟩 Tested and working
        # cmd =[
        #     "trivy",
        #     "config",
        #     "--output",
        #     f"{json_temp.name}",
        #     "--format",
        #     "json",
        #     f"{directory}",
        # ]

        result = subprocess.run(cmd)
        # if result.returncode != 0:
        #     Console().print(f"subprocess retruned code : {result.returncode} 🔴",style="bold red")
        #     raise Exception(f"Error: {result.stderr.decode('utf-8') if result.stderr else 'No error message'}")
        
        with open(json_temp.name, "r") as f:
            results = json.load(f)
        json_temp.close()
        
        #for testing
        with open("iac_results.json", "w+") as f:
            json.dump(results, f)
        
        Console().print(f"IAC scan completed successfully 🟢",style="bold green")
        return results
    except Exception as e:
        Console().print(f"Error: {e} 🔴",style="bold red")
        return str(e)


if __name__ == "__main__":
    result = run_iac_scan(
        repo_url="https://github.com/CyberUltron-Nikhil/DevSecShield",
        PAT="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",
        mode="trivy",
    )
    result = run_iac_scan(
        repo_url="https://github.com/CyberUltron-Nikhil/DevSecShield",
        PAT="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",
    )
    # print(result)