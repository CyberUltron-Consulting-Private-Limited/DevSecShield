import json
from pathlib import Path
import subprocess
import tempfile
import shutil
from typing import Literal
from git import Repo, GitCommandError
from rich.console import Console
from tools.context.Context import clone_repo, is_github_url, GithubContext, GitlabContext, BitbucketContext




def run_iac_scan(
    context : GithubContext | GitlabContext | BitbucketContext , 
    mode : Literal["tfsec", "trivy"] = "tfsec") -> dict | str:
    try:
        if context and isinstance(context, GithubContext):
            directory = clone_repo(context.repo_url)
        elif context and isinstance(context, GitlabContext):
            directory = clone_repo(context.repo_url)
        elif context and isinstance(context, BitbucketContext):
            directory = clone_repo(context.repo_url)
        else : 
            raise ValueError(f"Unsupported context: {context}")
        

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
        # this is useless because return code is always 1 and doesnt indicate any thing specifically 
        # if result.returncode != 0:
        #     Console().print(f"subprocess retruned code : {result.returncode} 🔴",style="bold red")
        #     raise Exception(f"Error: {result.stderr.decode('utf-8') if result.stderr else 'No error message'}")
        
        with open(json_temp.name, "r") as f:
            results = json.load(f)
        json_temp.close()
        
        #for testing
        # with open("iac_results.json", "w+") as f:
        #     json.dump(results, f)
        
        Console().print(f"IAC scan completed successfully 🟢",style="bold green")
        return results
    except Exception as e:
        Console().print(f"Error: {e} 🔴",style="bold red")
        raise e


if __name__ == "__main__":
    result = run_iac_scan(
        repo_url="https://github.com/CyberUltron-Nikhil/DevSecShield",
        PAT="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",
        mode="trivy",
    )
    # result = run_iac_scan(
    #     repo_url="https://github.com/CyberUltron-Nikhil/DevSecShield",
    #     PAT="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",
    # )
    # print(result)