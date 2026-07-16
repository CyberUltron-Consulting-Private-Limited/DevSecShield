"""Mobile App Security agent — downloads binary, runs private analyzer, normalizes findings."""

from __future__ import annotations

import os
import time
from pathlib import Path

from helpers.context.scan_context import FileContext, get_file_from_file_context
from helpers.tools.mobile_agent.client import MobileAnalyzerClient
from helpers.tools.mobile_agent.normalize import extract_summary, normalize_report
from rich.console import Console

console = Console()


class MobileAgent:
    def __init__(
        self,
        file_context: FileContext,
        state_update_writer=None,
        original_filename: str | None = None,
    ):
        self.file_context = file_context
        self.state_update_writer = state_update_writer
        self.original_filename = original_filename
        self._local_path: str | None = None

    def _progress(self, pct: float) -> None:
        if self.state_update_writer:
            try:
                self.state_update_writer.write_progress_percentage(pct)
            except Exception:
                pass

    def run(self) -> dict:
        start = time.time()
        self._progress(5)
        local_path = get_file_from_file_context(self.file_context)
        if not local_path:
            raise RuntimeError("Failed to download mobile binary from storage")
        self._local_path = local_path

        # Preserve extension for the analyzer when possible
        path = Path(local_path)
        if self.original_filename:
            preferred_ext = Path(self.original_filename).suffix
            if preferred_ext and path.suffix.lower() != preferred_ext.lower():
                renamed = path.with_suffix(preferred_ext)
                path.rename(renamed)
                path = renamed
                self._local_path = str(path)

        self._progress(15)
        client = MobileAnalyzerClient()
        report = client.analyze(path)
        self._progress(85)

        results = normalize_report(report)
        summary = extract_summary(report)
        if self.original_filename and not summary.get("file_name"):
            summary["file_name"] = self.original_filename

        self._progress(100)
        return {
            "results": results,
            "mobile_summary": summary,
            "duration_of_scan": time.time() - start,
        }

    def cleanup(self) -> None:
        if self._local_path and os.path.exists(self._local_path):
            try:
                os.remove(self._local_path)
            except OSError as e:
                console.print(f"Failed to remove temp mobile binary: {e}", style="bold red")
