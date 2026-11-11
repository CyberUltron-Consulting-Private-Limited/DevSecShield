import hashlib
import json
import os
from pathlib import Path
import subprocess

from helpers.context.cancellation import run_tool
import tempfile
from rich.console import Console
from helpers.context.scan_context import snippet_with_numbers
from helpers.tools.sast_agent.semgrep_resources import (
    semgrep_job_count,
    semgrep_max_memory_mb,
    semgrep_rule_timeout_seconds,
    semgrep_subprocess_env,
    semgrep_subprocess_timeout,
    semgrep_timeout_threshold,
)

console = Console()


def _build_semgrep_cmd(json_output: str, directory: str | Path, app_config: str) -> list[str]:
    cmd: list[str] = [
        "semgrep",
        "scan",
        "--config",
        app_config,
        "--json",
        "--output",
        json_output,
        "-j",
        semgrep_job_count(),
        "--timeout",
        semgrep_rule_timeout_seconds(),
        "--timeout-threshold",
        semgrep_timeout_threshold(),
    ]
    max_mem = semgrep_max_memory_mb()
    if max_mem:
        cmd.extend(["--max-memory", max_mem])
    cmd.append(str(directory))
    return cmd


def run_sast_scan_on_directory(
    directory: str | Path,
    app_lang: str = "python",
) -> dict | str:
    """Run Semgrep SAST on a directory; no subprocess cap unless SEMGREP_SUBPROCESS_TIMEOUT_SECONDS is set."""
    json_path = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
    try:
        console.print(
            f"Starting SAST scan for {app_lang} (-j {semgrep_job_count()}, "
            f"rule-timeout {semgrep_rule_timeout_seconds()}s)",
            style="bold yellow",
        )

        if not directory or not isinstance(directory, (str, Path)):
            raise ValueError("Directory is required")

        if app_lang not in [
            "python", "javascript", "java", "php", "c", "ruby",
            "rust", "swift", "csharp", "kotlin",
        ]:
            raise ValueError(f"Unsupported language: {app_lang}")

        cmd = _build_semgrep_cmd(json_path, directory, f"p/{app_lang}")
        proc = run_tool(
            cmd,
            capture_output=True,
            text=True,
            timeout=semgrep_subprocess_timeout(),
            env=semgrep_subprocess_env(),
        )

        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"SAST scan failed (exit {proc.returncode}): {proc.stderr}"
            )

        with open(json_path, encoding="utf-8") as f:
            sast_json = json.load(f)

        for i in range(len(sast_json["results"])):
            item = sast_json["results"][i]
            path = item["path"]
            start = item["start"]["line"]
            end = item["end"]["line"]
            sast_json["results"][i]["snippet"] = snippet_with_numbers(
                Path(path), start, end
            )

        dir_str = str(directory)
        for i in range(len(sast_json["results"])):
            sast_json["results"][i]["path"] = os.path.relpath(
                sast_json["results"][i]["path"], dir_str
            )
        if "paths" in sast_json:
            if "scanned" in sast_json["paths"]:
                sast_json["paths"]["scanned"] = sorted(
                    os.path.relpath(p, dir_str) for p in sast_json["paths"]["scanned"]
                )
            if "skipped" in sast_json["paths"]:
                for entry in sast_json["paths"]["skipped"]:
                    if isinstance(entry, dict) and "path" in entry:
                        entry["path"] = os.path.relpath(entry["path"], dir_str)
        for err in sast_json.get("errors", []):
            if isinstance(err, dict) and "message" in err:
                err["message"] = err["message"].replace(dir_str + "/", "").replace(
                    dir_str, ""
                )
            if isinstance(err, dict) and "spans" in err:
                for span in err.get("spans", []):
                    if isinstance(span, dict) and "file" in span:
                        span["file"] = os.path.relpath(span["file"], dir_str)

        def _normalise_trace_paths(obj, base_dir):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "path" and isinstance(v, str) and base_dir in v:
                        obj[k] = os.path.relpath(v, base_dir)
                    else:
                        _normalise_trace_paths(v, base_dir)
            elif isinstance(obj, list):
                for item in obj:
                    _normalise_trace_paths(item, base_dir)

        for item in sast_json["results"]:
            extra = item.get("extra", {})
            dt = extra.get("dataflow_trace")
            if dt:
                _normalise_trace_paths(dt, dir_str)
            fp_src = ":".join([
                str(item.get("check_id", "")),
                str(item.get("path", "")),
                str(item["start"]["line"]),
                str(item["start"].get("col", 0)),
                str(item["end"]["line"]),
                str(item["end"].get("col", 0)),
                str(extra.get("lines", "")),
            ])
            extra["fingerprint"] = hashlib.sha256(fp_src.encode()).hexdigest()

        sast_json.pop("profiling_results", None)
        sast_json["results"].sort(
            key=lambda r: (r["path"], r["start"]["line"], r["start"].get("col", 0))
        )

        console.print(
            f"Scan completed — findings: {len(sast_json['results'])}",
            style="bold green",
        )
        return sast_json
    except Exception as e:
        console.print(f"Scan failed: {e}", style="bold red")
        raise
    finally:
        try:
            os.unlink(json_path)
        except OSError:
            pass
