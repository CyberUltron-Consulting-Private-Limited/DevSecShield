import json
import os
from pathlib import Path
import subprocess
import tempfile
import shutil
from git import Repo, GitCommandError
from rich.console import Console
from tools.context.Context import clone_repo, is_github_url, GithubContext, GitlabContext, BitbucketContext , snippet_with_numbers


def run_gitleaks_scan(context : GithubContext | GitlabContext | BitbucketContext ) -> dict | str:
    """
    Run a Gitleaks scan on a given directory.
    Args:
        repo_url: The URL of the GitHub repository to scan.
        PAT: The GitHub token to use for authentication.
    Returns:
        A dictionary containing the scan results.
        A string containing the error message if the scan fails.
    """
    try:
        json_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        Console().print(f"Starting Gitleaks scan 🟨 🔍",style="bold yellow")
        if context and isinstance(context, GithubContext):
            directory = clone_repo(context.repo_url)
        elif context and isinstance(context, GitlabContext):
            directory = clone_repo(context.repo_url)
        elif context and isinstance(context, BitbucketContext):
            directory = clone_repo(context.repo_url)
        else : 
            raise ValueError(f"Unsupported context: {context}")

        print(os.listdir(os.path.dirname(__file__)))
        gitleaks = os.path.join(os.path.dirname(__file__), "gitleaks.exe")
        linux_gitleaks = os.getenv("LINUX_GITLEAKS")
        
        print(f"Linux Gitleaks: {linux_gitleaks} of type {type(linux_gitleaks)}")
        if linux_gitleaks and linux_gitleaks == "True":
            print("Linux Gitleaks detected")
            gitleaks = os.path.join(os.path.dirname(__file__), "linux_gitleaks")


        if not os.path.exists(gitleaks):
            raise FileNotFoundError(f"Gitleaks binary not found at {gitleaks}")
        else:
            print(f"Gitleaks binary found at {gitleaks}")


        if directory:
            cmd = [gitleaks, "dir", directory, "--report-format", "json", "--report-path", json_temp.name]
            print(f"Command: {cmd}")
        else:
            raise ValueError(f"Directory not provided")

        print(f" Current working directory: {os.getcwd()}")
        result = subprocess.run(cmd)


        # if result.returncode != 0:
        #     raise RuntimeError(f"Gitleaks scan failed: {result.stderr}")

        Console().print(f"Gitleaks scan ran successfully, reading results now .. 🟨",style="bold yellow")
        
        with open(json_temp.name, "r", encoding="utf-8") as f:
            gitleaks_json = json.load(f)

            # for testing
            # with open("gitleaks_test.json", "w+", encoding="utf-8") as f:
            #     json.dump(gitleaks_json, f, indent=2)

            for i in range(len(gitleaks_json)):
                result = gitleaks_json[i]
                path = result["File"]
                start = result["StartLine"]
                end = result["EndLine"]
                snippet = snippet_with_numbers(Path(path), start, end)
                gitleaks_json[i]["snippet"] = snippet
            

        json_temp.close()

        # for testing
        # with open("gitleaks_test.json", "w+", encoding="utf-8") as f:
        #     json.dump(gitleaks_json, f, indent=2)


        try:
            Console().print("Cleaning up temp directory",style="dim yellow")
            shutil.rmtree(directory)
        except Exception as e:
            Console().print(f"Error: {e}",style="dim red")
            pass

        Console().print(f"Scan completed 🟩 ✅ Vulnerabilities found: {len(gitleaks_json)}",style="bold green")
        return gitleaks_json
    except Exception as e:
        Console().print(f"Scan failed 🟥 ❌ with error: {e}",style="bold red")
        raise e


if __name__ == "__main__":
    result = run_gitleaks_scan(
        repo_url="https://github.com/CyberUltron-Nikhil/RiskPilot",
        PAT="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",
    )
    print(result)
