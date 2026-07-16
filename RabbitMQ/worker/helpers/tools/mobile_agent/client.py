"""HTTP client for the internal mobile static analyzer service."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests
from rich.console import Console

console = Console()

DEFAULT_TIMEOUT = (30, 600)  # connect, read — scans can be slow


class MobileAnalyzerClient:
    """Talks to the private static analyzer REST API (upload → scan → JSON report)."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
    ):
        self.base_url = (base_url or os.getenv("MOBSF_URL") or "http://127.0.0.1:8000").rstrip("/")
        self.api_key = api_key or os.getenv("MOBSF_API_KEY") or ""
        if not self.api_key:
            raise RuntimeError("MOBSF_API_KEY is not configured")
        self._headers = {"Authorization": self.api_key}

    def upload(self, file_path: str | Path) -> dict[str, Any]:
        path = Path(file_path)
        console.print(f"Uploading mobile binary {path.name}", style="bold yellow")
        with path.open("rb") as fh:
            files = {"file": (path.name, fh, "application/octet-stream")}
            resp = requests.post(
                f"{self.base_url}/api/v1/upload",
                headers=self._headers,
                files=files,
                timeout=DEFAULT_TIMEOUT,
            )
        resp.raise_for_status()
        data = resp.json()
        if "hash" not in data:
            raise RuntimeError(f"Upload failed: {data}")
        return data

    def scan(self, file_hash: str) -> dict[str, Any]:
        console.print(f"Starting mobile static scan for hash={file_hash}", style="bold yellow")
        resp = requests.post(
            f"{self.base_url}/api/v1/scan",
            headers=self._headers,
            data={"hash": file_hash},
            timeout=DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def report_json(self, file_hash: str) -> dict[str, Any]:
        console.print(f"Fetching mobile scan report for hash={file_hash}", style="bold yellow")
        resp = requests.post(
            f"{self.base_url}/api/v1/report_json",
            headers=self._headers,
            data={"hash": file_hash},
            timeout=DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(f"Report error: {data['error']}")
        return data

    def analyze(self, file_path: str | Path) -> dict[str, Any]:
        upload_result = self.upload(file_path)
        file_hash = upload_result["hash"]
        self.scan(file_hash)
        return self.report_json(file_hash)
