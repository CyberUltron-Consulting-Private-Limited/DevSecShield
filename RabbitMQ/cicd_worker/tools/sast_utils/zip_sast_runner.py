import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from rich.console import Console
from utils.s3_utils import download_file
from utils.general_utils import snippet_with_numbers
import zipfile
from rich.console import Console

console = Console()

def run_sast_scan(
    bucket_name: str,
    object_name: str,
    app_lang : str = "python") -> dict | str:
    """
    Run a SAST scan on a given zip file of the project.
    Args:
        bucket_name: The name of the bucket with zip file of the project to scan.
        object_name: The name of the object with zip file of the project to scan.
        app_lang: The language of the application to scan.
    Returns:
        A dictionary containing the scan results.
        A string containing the error message if the scan fails.
    """
    try:
        json_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        Console().print(f"Starting SAST scan 🟨 🔍 for {app_lang} application",style="bold yellow")

        # Download the zip file from the s3 bucket 
        zip_file_path = download_file(bucket_name, object_name)

        
        # create a temporary directory
        directory = tempfile.mkdtemp(prefix="repo_")
        
        # extract the zip file to a temporary directory
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(directory)


        if app_lang not in ["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]:
            raise ValueError(f"Unsupported language: {app_lang}")
        app_config = f"p/{app_lang}"
    
        console.print(f"Temp directory: {directory}")

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
            # for testing
            # with open("sast_test.json", "w+", encoding="utf-8") as f:
            #     json.dump(sast_json, f, indent=2)
            for i in range(len(sast_json["results"])):
                result = sast_json["results"][i]
                path = result["path"]
                start = result["start"]["line"]
                end = result["end"]["line"]
                snippet = snippet_with_numbers(Path(path), start, end)
                sast_json["results"][i]["snippet"] = snippet
            
            # No need for parsing errors as they are not vulnerabilities
            # for i in range(len(sast_json["errors"])):
            #     for j in range(len(sast_json["errors"][i]["type"][1])):
            #         if sast_json["errors"][i]["type"][1][j]["type"] != "Internal matching error":
            #             result = sast_json["errors"][i]["type"][1][j]
            #             path = result["path"]
            #             start = result["start"]["line"]
            #             end = result["end"]["line"]
            #             snippet = snippet_with_numbers(Path(path), start, end)
            #             sast_json["errors"][i]["type"][1][j]["snippet"] = snippet

        json_temp.close()

        # for testing
        # with open("sast_test.json", "w+", encoding="utf-8") as f:
        #     json.dump(sast_json, f, indent=2)

        try:
            Console().print("Cleaning up temp directory",style="dim yellow")
            shutil.rmtree(directory)
        except Exception as e:
            Console().print(f"Error: {e}",style="dim red")
            pass
        
        Console().print(f"Scan completed 🟩 ✅ Vulnerabilities found: {len(sast_json['results'])}",style="bold green")

        # sast_json = parse_scan_results(sast_json, scan_type="sast")
        return sast_json
    except Exception as e:
        Console().print(f"Scan failed 🟥 ❌ with error: {e}",style="bold red")
        raise e


if __name__ == "__main__":
    results = run_sast_scan(
        bucket_name="devsecshield-storage",
        object_name="file-20251223192405850802-af04afa6.zip",
        app_lang="python",
    )
    print(results)
