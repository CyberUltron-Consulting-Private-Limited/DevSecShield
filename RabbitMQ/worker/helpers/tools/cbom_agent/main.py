"""CBOM scan inputs and credit estimates.

Every CBOM path is deterministic and offline: repository and zip scans run the aibom crypto engine over the checked-out
files, and an uploaded CycloneDX CBOM is judged by the same engine (aibom.cbom.ingest). No language model, no NVD or
other network lookups; CVE / CWE / OWASP / remediation come from the bundled crypto knowledge base.
"""
import os
import shutil
from helpers.context.scan_context import *
from helpers.context.base_agent import BaseAgent
from rich.console import Console
from helpers.context.progress_writer import StateUpdateWriter

console = Console()

# File types the crypto engine never reads (binaries, media, archives); everything else under the engine's
# skip-list is counted for the size-based credit estimate.
_NOT_SCANNED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".pdf", ".mp3", ".mp4", ".mov", ".avi",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".ear", ".whl",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".class", ".pyc", ".woff", ".woff2", ".ttf", ".otf", ".eot",
}
_MAX_SCANNED_FILE_BYTES = 2_000_000  # the engine skips larger source files
_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024  # with scan_binaries: the engine's limit for one image / binary / blob
MIN_CODE_SCAN_CREDITS = 1.0  # D3: a repository or zip CBOM scan costs at least 1 credit (backend credit_estimate.py)
# With the scan option "scan binaries": container images, binaries and firmware are read too, priced per 5 MB (they
# are streamed and mostly skipped, so a byte costs a tenth of a source byte). Backend formula "cbom-2026.11-min1-bin5".
SOURCE_MB_PER_CREDIT = 0.5
BINARY_MB_PER_CREDIT = 5.0


class CBOMAgent(BaseAgent):
    def __init__(
        self,
        context: GithubContext | GitlabContext | BitbucketContext | None = None,
        zip_context: ZipContext | None = None,
        cbom_file_context: FileContext | None = None,
        scan_binaries: bool = False,
        state_update_writer: StateUpdateWriter | None = None,
        include_vendored: bool = False,
    ):
        try:
            directory = None
            file = None
            if context:
                directory = clone_repo_from_context(context)
            elif zip_context:
                directory = get_directory_from_zip_context(zip_context)
            elif cbom_file_context:
                file = get_file_from_file_context(cbom_file_context)

            if not directory and not file:
                raise ValueError("Invalid Input, either directory or CBOM file is required")

            self.directory = directory
            self.cbom_json_file = file
            # scan option: also read container images, compiled binaries and firmware (the engine's artifact lane)
            self.scan_binaries = bool(scan_binaries)
            # scan option: also read vendor/, dist/, build/ and node_modules/ (third-party / build output)
            self.include_vendored = include_vendored
            self.state_update_writer: StateUpdateWriter | None = state_update_writer

            # Store the ORIGINAL repo url (only present for a repo context).
            # None for zip / CBOM-file scans. Used to make the generated
            # CycloneDX CBOM content-deterministic (metadata.component.name must
            # derive from the real repo, not the random temp dir basename).
            self.repo_url = getattr(context, "repo_url", None) if context else None

            # initialized later
            self.vulnerabilities: list[type[CryptographicAssetVulnerability]] | None = None
            self.raw_detections: list[dict] = []
            self.cyclonedx_cbom: dict | None = None

        except Exception as e:
            raise ValueError(f"Error in initializing CBOMAgent: {e}")

    # -----------------------------------------------------------------
    # Scanning (aibom engine; deterministic and offline)
    # -----------------------------------------------------------------

    def _progress(self, pct: float, _message: str = "") -> None:
        if self.state_update_writer:
            self.state_update_writer.write_progress_percentage(pct)

    def scan(self) -> dict:
        """Run the crypto engine on the resolved input and return the CBOM run-object."""
        from aibom.integrations.cbom_devsecshield import (
            analyze_cbom_file_to_devsecshield,
            scan_crypto_to_devsecshield,
        )

        if self.directory:
            return scan_crypto_to_devsecshield(
                str(self.directory), level=4, progress=self._progress, include_vendored=self.include_vendored,
                scan_binaries=self.scan_binaries,
            )
        if self.cbom_json_file:
            return analyze_cbom_file_to_devsecshield(self.cbom_json_file, progress=self._progress)
        raise ValueError("Invalid Input, either directory or cbom_json_file is required")

    def clean_up(self):
        """Remove temporary directory or CBOM file after scan completes."""
        try:
            try:
                if self.directory:
                    if os.path.exists(self.directory):
                        console.print("Temp Dir does Exist", style="dim bright_cyan")
                    else:
                        console.print("Temp Dir does NOT Exist", style="dim bright_cyan")

                    console.print("Removing temporary directory ...", style="dim red")
                    shutil.rmtree(self.directory)
                    console.print("Temporary directory removed successfully", style="bold green")
                elif self.cbom_json_file:
                    if os.path.exists(self.cbom_json_file):
                        console.print("CBOM file does Exist", style="dim bright_cyan")

                    console.print("Removing CBOM file ...", style="dim red")
                    os.remove(self.cbom_json_file)
                    console.print("CBOM file removed successfully", style="bold green")
            except Exception as e:
                console.print(f"Error while deleting temp directory: {str(e)}", style="dim red")

        except Exception as e:
            raise ValueError(f"Error in cleaning up: {e}")

    # -----------------------------------------------------------------
    # Main entry points
    # -----------------------------------------------------------------

    def run_agent(self) -> dict:
        """Scan, then always remove the checked-out directory or uploaded file."""
        try:
            return self.scan()
        except Exception as e:
            console.print(f"Error occurred in run_agent: {str(e)}", style="bold red")
            raise
        finally:
            console.print("Performing cleanup .... 🧹", style="dim bright_cyan")
            self.clean_up()

    def _measure_directory_size(self) -> tuple[int, float, float]:
        """Size of the files the crypto engine reads (same skip-list and per-file limit), for the credit estimate."""
        return self._measure()[:3]

    def _measure(self) -> tuple[int, float, float, float]:
        """(source bytes, source MB, source GB, binary MB): source files as the engine's text lanes read them, and,
        with scan_binaries, the images / binaries / archives / firmware the artifact lane reads."""
        from aibom.cbom.files import skipped_dirs

        skip = skipped_dirs(self.include_vendored)  # the engine's own walk rule
        total_bytes = 0
        binary_bytes = 0
        file_count = 0
        for root, dirs, files in os.walk(self.directory):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in files:
                fpath = os.path.join(root, fname)
                if os.path.islink(fpath):
                    continue
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    continue
                if os.path.splitext(fname)[1].lower() in _NOT_SCANNED_EXTENSIONS or size > _MAX_SCANNED_FILE_BYTES:
                    if self.scan_binaries and size <= _MAX_ARTIFACT_BYTES:
                        binary_bytes += size
                    continue
                total_bytes += size
                file_count += 1
        size_mb = total_bytes / (1024 * 1024)
        binary_mb = binary_bytes / (1024 * 1024)
        console.print(f"CBOM estimation: {file_count} files, {size_mb:.2f} MB, binaries {binary_mb:.2f} MB",
                      style="bold yellow")
        return total_bytes, size_mb, size_mb / 1024, binary_mb

    def estimate_credits_required(self) -> float:
        """Credits for the scan: 1 credit per 0.5 MB of scanned source files and, with the scan option "scan
        binaries", 1 credit per 5 MB of images / binaries / firmware; at least MIN_CODE_SCAN_CREDITS for a repository
        or zip scan (decision D3; the API applies the same minimum at start). There is no language-model charge (the
        engine is deterministic). Analysing an uploaded CBOM file is a flat 0.01 credit."""
        try:
            if self.directory:
                _size_b, codebase_size_in_mb, _size_gb, binary_mb = self._measure()
                return max(MIN_CODE_SCAN_CREDITS, codebase_size_in_mb / SOURCE_MB_PER_CREDIT
                           + binary_mb / BINARY_MB_PER_CREDIT)
            return 0.01
        finally:
            console.print("Performing cleanup .... 🧹", style="dim bright_cyan")
            self.clean_up()
