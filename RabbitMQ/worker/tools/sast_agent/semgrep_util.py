import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from rich.console import Console
from tools.context.scan_context import clone_repo, snippet_with_numbers , GithubContext, GitlabContext, BitbucketContext, validate_dict_with_context, clone_repo_from_context



def run_sast_scan_on_directory(
    directory : str | Path ,
    app_lang : str = "python") -> dict | str:
    """
    Run a SAST scan on a given directory.
    Args:
        directory: The directory to scan.
        app_lang: The language of the application to scan.
    Returns:
        A dictionary containing the scan results.
        A string containing the error message if the scan fails.
    """
    try:
        json_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        Console().print(f"Starting SAST scan 🟨 🔍 for {app_lang} application",style="bold yellow")

        if not directory or not isinstance(directory, (str, Path)):
            raise ValueError(f"Directory is required")     

        if app_lang not in ["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]:
            raise ValueError(f"Unsupported language: {app_lang}")
        app_config = f"p/{app_lang}"


        if directory:
            cmd =[
                "semgrep",
                "--config",
                app_config,
                "--verbose",
                "--json",
                "--output",
                json_temp.name,
                directory
            ]
        else:
            raise ValueError(f"Directory not provided")

        result = subprocess.run(cmd)


        if result.returncode != 0:
            raise RuntimeError(f"SAST scan failed: {result.stderr}")

        Console().print(f"SAST scan ran successfully, reading results now .. 🟨",style="bold yellow")
        
        with open(json_temp.name, "r", encoding="utf-8") as f:
            sast_json = json.load(f)
            
            for i in range(len(sast_json["results"])):
                result = sast_json["results"][i]
                path = result["path"]
                start = result["start"]["line"]
                end = result["end"]["line"]
                snippet = snippet_with_numbers(Path(path), start, end)
                sast_json["results"][i]["snippet"] = snippet
            

        json_temp.close()
        
        Console().print(f"Scan completed 🟩 ✅ Vulnerabilities found: {len(sast_json['results'])}",style="bold green")

        return sast_json
    except Exception as e:
        Console().print(f"Scan failed 🟥 ❌ with error: {e}",style="bold red")
        raise e


if __name__ == "__main__":
    # bitbucket_result = run_sast_scan(
    #     repo_url="https://sirniksalot-admin@bitbucket.org/sirniksalot/pedro-duarte.git",
    #     PAT="ATCTT3xFfGN04kvG8anKPSzfd2E6FW5TfC-9kCKLgAbu_n8clCz0rYBmUNt6BdCQa1mPCEzYWPZt86mN5OCGoJ0oyXz2qYj_9TI739-L5Ik30bhmwimX1kT-tR9s3Us-jC8Zf4GNDJ-K0mF7VZxHQiOFuAbH3waoIaXGq6yYkQ2-SupjYJGLKLE=01DD659F",
    #     app_lang="javascript",
    # )
    # gitlab_result = run_sast_scan(
    #     repo_url="https://gitlab.com/sirniksalot-group/SirNiksALot-project.git",
    #     PAT="glpat-j-kWHdSBppL5jfw-cMcWnm86MQp1OmowcnF2Cw.01.1207m75uw",
    #     app_lang="javascript",
    # )
    dict_context = {
    "mode":"github",
    "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot.git",
    "PAT":"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",
    }
    sast_kwargs = {
        "dict_context":dict_context,
        "app_lang":"javascript",
    }
    context = validate_dict_with_context(dict_context)
    directory = clone_repo_from_context(context)
    github_result = run_sast_scan_on_directory(
        directory=directory ,
        app_lang="javascript",
    )
