import json
import sys
from pathlib import Path
import subprocess
import tempfile
import shutil
import os
from typing import Optional, Dict, Any, List

from git import Repo, GitCommandError
from rich.console import Console

console = Console()


def is_github_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and "github.com" in url


def validate_github_token(token: str) -> bool:
    """Validate GitHub Personal Access Token format"""
    if not token:
        return False
    # Valid format: ghp_ followed by exactly 36 characters (total 40 characters)
    return token.startswith('ghp_') and len(token) == 400 and len(token[4:]) == 360


def clone_repo(url: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="repo_"))
    console.print(f"Cloning {url} -> {tmp}", style="blue")
    try:
        # depth=1 gives a shallow clone; GitLeaks can still scan working tree.
        # Set depth=None for full history if you intend to scan all commits thoroughly.
        Repo.clone_from(url, tmp, depth=1)
    except GitCommandError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"Clone failed: {e}") from e
    return tmp


def ensure_gitleaks() -> str:
    """Ensure GitLeaks is available, download if necessary."""
    exe = shutil.which("gitleaks")
    if exe:
        return exe
    
    # Try to find in common locations
    # Get the script's directory to find tools relative to it (always use script location, not cwd)
    script_dir = Path(__file__).parent.parent
    common_paths = [
        script_dir / "tools" / "gitleaks.exe",  # Primary location
        script_dir / "gitleaks.exe",
        Path.cwd() / "gitleaks.exe",
        Path.cwd() / "bin" / "gitleaks.exe",
        Path.cwd() / "tools" / "gitleaks.exe",
        Path.home() / ".local" / "bin" / "gitleaks.exe",
    ]
    
    for path in common_paths:
        if path.exists() and path.is_file():
            return str(path)
    
    # If not found, try to download it (will create in script_dir/tools)
    return download_gitleaks()

def download_gitleaks() -> str:
    """Download GitLeaks binary for Windows."""
    import urllib.request
    import zipfile
    import platform
    
    if platform.system() != "Windows":
        raise RuntimeError("Auto-download only supported on Windows. Please install GitLeaks manually.")
    
    console.print("GitLeaks not found. Attempting to download...", style="yellow")
    
    # Create tools directory (always relative to script location, never current working directory)
    script_dir = Path(__file__).parent.parent
    tools_dir = script_dir / "tools"
    tools_dir.mkdir(exist_ok=True)
    
    gitleaks_exe = tools_dir / "gitleaks.exe"
    
    if gitleaks_exe.exists():
        console.print(f"Found existing GitLeaks: {gitleaks_exe}", style="green")
        return str(gitleaks_exe)
    
    try:
        # Get latest release info
        import json
        import urllib.request
        
        console.print("Fetching latest GitLeaks release...", style="dim")
        
        # Get latest release
        with urllib.request.urlopen("https://api.github.com/repos/gitleaks/gitleaks/releases/latest") as response:
            release_data = json.loads(response.read().decode())
        
        # Find Windows binary (prefer x64 over ARM)
        windows_asset = None
        for asset in release_data["assets"]:
            if "windows" in asset["name"].lower() and asset["name"].endswith(".zip"):
                # Prefer x64 over ARM
                if "x64" in asset["name"].lower() or "amd64" in asset["name"].lower():
                    windows_asset = asset
                    break
                elif windows_asset is None:  # Fallback to any Windows binary
                    windows_asset = asset
        
        if not windows_asset:
            raise RuntimeError("Could not find Windows binary in latest release")
        
        download_url = windows_asset["browser_download_url"]
        zip_path = tools_dir / "gitleaks.zip"
        
        console.print(f"Downloading {windows_asset['name']}...", style="dim")
        
        # Download the zip file
        with urllib.request.urlopen(download_url) as response:
            with open(zip_path, 'wb') as f:
                f.write(response.read())
        
        # Extract the zip file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(tools_dir)
        
        # Find the extracted exe file
        for file in tools_dir.iterdir():
            if file.name.startswith("gitleaks") and file.suffix == ".exe":
                file.rename(gitleaks_exe)
                break
        
        # Clean up
        zip_path.unlink(missing_ok=True)
        
        # Make sure it's present
        if gitleaks_exe.exists():
            console.print(f"GitLeaks downloaded successfully: {gitleaks_exe}", style="green")
            return str(gitleaks_exe)
        else:
            raise RuntimeError("Failed to extract GitLeaks executable")
            
    except Exception as e:
        console.print(f"Failed to download GitLeaks: {e}", style="red")
        console.print("Please download manually from: https://github.com/gitleaks/gitleaks/releases", style="yellow")
        raise RuntimeError(f"GitLeaks not found and download failed: {e}")


def snippet_with_numbers(fp: Path, start: int, end: int) -> str:
    try:
        lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
        start = max(1, int(start))
        end = min(len(lines), int(end) if end else start)
        return "\n".join(
            f"{i+1:>5}| {lines[i]}" for i in range(start - 1, end)
        )
    except Exception as exc:
        console.print(
            f"Failed to read code snippet {fp}:{start}-{end} — {exc}",
            style="bold red",
        )
        return ""


def parse_gitleaks_output(stdout: str) -> List[Dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    # GitLeaks may print an array or an object with 'findings'
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    return []


def run_gitleaks_scan(
    repo_url: Optional[str] = None,
    PAT: Optional[str] = None,
    redact: bool = True,
    scan_history: bool = False,
    gitleaks_path: Optional[str] = None,
    config_file: Optional[str] = None,
    timeout_sec: int = 600,
    report_format: str = "json",
    report_path: Optional[str] = None,
) -> Dict[str, Any] | str:
    """
    Run a GitLeaks scan on a given repository/dir.

    Args:
        repo_url: GitHub repository URL to scan (required).
        PAT: GitHub token for private repos; prefer using env var (e.g., GITHUB_TOKEN).
        redact: Whether to redact secrets in output.
        scan_history: If True, scan full git history. Requires a non-shallow clone.

    Returns:
        Dict with results including enriched 'snippet' for each finding, or error string.
    """
    directory: Optional[Path] = None
    try:
        console.print("Starting GitLeaks scan...", style="bold yellow")

        if repo_url and is_github_url(repo_url):
            # Safely inject PAT for authenticated cloning (avoid printing PAT)
            if PAT:
                ind = repo_url.find("github.com")
                repo_suffix = repo_url[ind:]
                safe_url = f"https://{PAT}@{repo_suffix}"
            else:
                safe_url = repo_url

            directory = clone_repo(safe_url)

            if scan_history:
                # Re-clone without depth for full history scan
                shutil.rmtree(directory, ignore_errors=True)
                directory = Path(tempfile.mkdtemp(prefix="repo_full_"))
                console.print("Full clone for history scan...", style="yellow")
                Repo.clone_from(safe_url, directory)  # full clone
        else:
            raise ValueError("A valid GitHub repository URL is required.")

        gitleaks = gitleaks_path or ensure_gitleaks()
        # quick validation of binary
        try:
            _ver = subprocess.run([gitleaks, "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, timeout=15)
            if _ver.returncode != 0:
                raise RuntimeError("GitLeaks binary is not executable or returned non-zero from version command")
        except FileNotFoundError:
            raise RuntimeError("GitLeaks binary not found. Ensure it is installed and accessible.")

        # Determine report format and destination
        ext_map = {"json": "json", "sarif": "sarif", "csv": "csv", "junit": "xml"}
        fmt = (report_format or "json").lower()
        if fmt not in ext_map:
            fmt = "json"

        # If report_path is provided, always write to that path.
        # Otherwise, only JSON goes to stdout for enrichment; non-JSON writes to default file.
        default_report_file: Optional[Path] = None
        if report_path:
            default_report_file = Path(report_path)
        else:
            if fmt != "json":
                default_report_file = Path(f"gitleaks_report.{ext_map[fmt]}")

        # Build GitLeaks command
        cmd = [
            gitleaks,
            "detect",
            "-s",
            str(directory),
            "--report-format",
            fmt,
        ]

        if default_report_file is None:
            cmd.extend(["--report-path", "-"])  # emit to stdout
        else:
            cmd.extend(["--report-path", str(default_report_file.resolve())])

        if redact:
            cmd.append("--redact")

        # include config file when supplied and exists
        if config_file:
            cfg_path = Path(config_file)
            if cfg_path.exists():
                cmd.extend(["--config", str(cfg_path.resolve())])

        # To scan only the working tree (not git history), uncomment the next line
        # cmd.append("--no-git")

        console.print(f"Running: {' '.join(cmd)}", style="dim")

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"GitLeaks scan timed out after {timeout_sec}s")
        except FileNotFoundError:
            raise RuntimeError("Failed to execute GitLeaks binary. File not found.")

        # GitLeaks exit codes: 0=no leaks, 1=leaks found, >1=error
        if proc.stderr.strip():
            # GitLeaks logs to stderr; not all are errors
            console.print(proc.stderr.strip(), style="dim")

        findings: List[Dict[str, Any]] = []

        if fmt == "json" and default_report_file is None:
            # JSON via stdout: parse and enrich
            findings = parse_gitleaks_output(proc.stdout)

            # Enrich findings with snippets (guard against invalid paths)
            for f in findings:
                rel_file = (f.get("file") or f.get("path") or "").strip()
                line = f.get("line") or f.get("startLine") or 0
                start_line = int(line) if isinstance(line, int) or (isinstance(line, str) and line.isdigit()) else 0
                end_line = int(f.get("endLine") or start_line or 0)

                snippet_text = ""
                if rel_file:
                    snippet_path = (directory / rel_file).resolve()
                    if snippet_path.exists() and snippet_path.is_file():
                        snippet_text = snippet_with_numbers(snippet_path, start_line or 1, end_line or start_line or 1)
                f["snippet"] = snippet_text

            # Save raw JSON for debugging/CI artifacts
            with open("gitleaks_results_raw.json", "w", encoding="utf-8") as dbg:
                try:
                    raw = json.loads(proc.stdout) if proc.stdout.strip() else []
                except json.JSONDecodeError:
                    raw = []
                json.dump(raw, dbg, indent=2)

            # Build final JSON
            result_json: Dict[str, Any] = {
                "target": str(directory),
                "redact": redact,
                "exit_code": proc.returncode,
                "format": fmt,
                "findings_count": len(findings),
                "findings": findings,
            }

            # Also save enriched results
            with open("gitleaks_results_enriched.json", "w", encoding="utf-8") as outf:
                json.dump(result_json, outf, indent=2)
        else:
            # Non-JSON (or JSON to file) — do not parse/enrich; just summarize
            if proc.stdout.strip():
                with open("gitleaks_cli_stdout.log", "w", encoding="utf-8") as lf:
                    lf.write(proc.stdout)

            # Extract secret count from gitleaks stderr output for non-JSON formats
            findings_count = 0
            if proc.stderr.strip():
                # Look for "leaks found: X" pattern in stderr
                import re
                match = re.search(r'leaks found:\s*(\d+)', proc.stderr)
                if match:
                    findings_count = int(match.group(1))

            result_json = {
                "target": str(directory),
                "redact": redact,
                "exit_code": proc.returncode,
                "format": fmt,
                "report_file": str(default_report_file.resolve()) if default_report_file else None,
                "findings_count": findings_count,
            }

        if proc.returncode > 1:
            raise RuntimeError("GitLeaks encountered an error (exit code > 1).")

        if proc.returncode == 1:
            # Use findings_count from result_json for consistent reporting
            count = result_json.get("findings_count", 0) or 0
            console.print(
                f"Scan completed - WARNING: Secrets detected: {count}",
                style="bold yellow",
            )
        else:
            console.print("Scan completed - SUCCESS: No secrets detected", style="bold green")

        return result_json

    except Exception as e:
        console.print(f"Scan failed - ERROR: {e}", style="bold red")
        return str(e)
    finally:
        # cleanup cloned repository
        if directory and directory.exists():
            shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="GitLeaks Production Scanner")
    parser.add_argument("--repo-url", required=True, help="GitHub repository URL to scan")
    parser.add_argument("--token", help="GitHub Personal Access Token (required - provide via --token or GITHUB_TOKEN env var)")
    parser.add_argument("--output-dir", default="reports", help="Output directory for results")
    parser.add_argument("--config", help="Path to GitLeaks config file")
    parser.add_argument("--scan-history", action="store_true", help="Scan full git history")
    parser.add_argument("--no-redact", action="store_true", help="Don't redact secrets in output")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--report-format",
        default="json",
        choices=["json", "sarif", "csv", "junit"],
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--report-file",
        help="Write report to this path. For non-json without this, a default file is created.",
    )
    
    args = parser.parse_args()
    
    # Get token from args or environment - at least one must be provided
    token = args.token or os.getenv("GITHUB_TOKEN")
    if not token:
        console.print("ERROR: GitHub token is required. Provide --token or set GITHUB_TOKEN environment variable.", style="red")
        console.print("Example: --token ghp_1234567890abcdef", style="yellow")
        console.print("Or set: $env:GITHUB_TOKEN='ghp_1234567890abcdef'", style="yellow")
        sys.exit(1)
    
    # Validate token format
    # if not validate_github_token(token):
    #     console.print("ERROR: Invalid GitHub token format. Expected: ghp_ + 36 characters", style="red")
    #     console.print(f"Your token: {token} (length: {len(token)})", style="yellow")
    #     console.print("Example: ghp_1234567890abcdef1234567890abcdef", style="yellow")
    #     console.print("Note: GitHub Personal Access Tokens must be exactly 40 characters long", style="yellow")
    #     sys.exit(1)
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    console.print(f"Starting GitLeaks scan for: {args.repo_url}", style="bold blue")
    console.print(f"Output directory: {output_dir.absolute()}", style="cyan")
    
    # Ensure GitLeaks is available and get absolute path before changing directories
    gitleaks_path = ensure_gitleaks()
    gitleaks_abs_path = str(Path(gitleaks_path).resolve())
    console.print(f"Using GitLeaks: {gitleaks_abs_path}", style="dim")
    
    # Change to output directory for file operations
    original_cwd = Path.cwd()
    os.chdir(output_dir)
    
    try:
        res = run_gitleaks_scan(
            repo_url=args.repo_url,
            PAT=token,
            redact=not args.no_redact,
            scan_history=args.scan_history,
            gitleaks_path=gitleaks_abs_path,
            config_file=args.config,
            report_format=args.report_format,
            report_path=args.report_file,
        )
        
        if isinstance(res, dict):
            count = res.get('findings_count', 0) or 0
            console.print(f"Scan completed successfully. Found {count} secrets.", style="green")
            if args.verbose:
                console.print(json.dumps(res, indent=2))
        else:
            console.print(f"Scan failed: {res}", style="red")
            sys.exit(1)
            
    finally:
        # Return to original directory
        os.chdir(original_cwd)


