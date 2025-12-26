import subprocess
import tempfile
import json
import os
from typing import List, Optional, Dict


def run_wapiti_dast_scan(
    target_url: str,
    auth_url: str,
    username_key: str,
    password_key: str,
    username_value: str,
    password_value: str,
    auth_http_method: str = "POST",
    session_key: Optional[str] = None,
    csrf_token: Optional[str] = None,
    attacks: Optional[List[str]] = None,
) -> Dict:
    """
    Run an authenticated DAST scan using Wapiti and return results as a dict.
    """

    auth_http_method = auth_http_method.lower()
    if auth_http_method not in ("post", "get"):
        raise ValueError("auth_http_method must be POST or GET")

    # -------------------------------
    # Build authentication payload
    # -------------------------------
    auth_data_parts = [
        f"{username_key}={username_value}",
        f"{password_key}={password_value}",
    ]

    if csrf_token:
        auth_data_parts.append(f"{csrf_token}={{token}}")

    auth_data = "&".join(auth_data_parts)

    # -------------------------------
    # Create temp JSON output file
    # -------------------------------
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
        output_file = tmp_file.name

    # -------------------------------
    # Build Wapiti command
    # -------------------------------
    command = [
        "wapiti",
        "-u", target_url,
        "-f", "json",
        "-o", output_file,
        "--form-data", auth_data,
        "--form-url", auth_url,
        "--flush-session",
    ]

    # Optional: attack modules
    if attacks:
        command.extend(["-m", ",".join(attacks)])

    # Optional: session cookie
    if session_key:
        command.extend(["--cookie", session_key])

    # -------------------------------
    # Execute scan
    # -------------------------------
    try:
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        os.unlink(output_file)
        raise RuntimeError(f"Wapiti scan failed: {e.stderr}") from e

    # -------------------------------
    # Read JSON results
    # -------------------------------
    try:
        with open(output_file, "r", encoding="utf-8") as f:
            results = json.load(f)
    finally:
        os.unlink(output_file)

    return results


if __name__ == "__main__":
    results = run_wapiti_dast_scan(
        target_url="http://localhost:8090/bodgeit",
        auth_url=" http://localhost:8090/bodgeit/register.jsp",
        username_key="username",
        password_key="password",
        username_value="shivanathnikhil@gmail.com",
        password_value="Testing@123",
        auth_http_method="POST",
        # session_key="session_key",
        # csrf_token="csrf_token",
        attacks=["sql_injection", "xss", "file_upload"],
    )
    print(results)  

    """
    Example command :
    wapiti -u http://localhost:8090/bodgeit -f json -o output.json --form-data "username=shivanathnikhil@gmail.com&password=Testing@123" --form-url "http://localhost:8090/bodgeit/register.jsp" -m sql_injection,xss,file_upload --cookie session_key --csrf-token csrf_token
    """