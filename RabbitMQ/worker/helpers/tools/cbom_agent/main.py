import os
import json
import shutil
from langchain_core.documents import Document
from helpers.context.scan_context import *
from helpers.context.base_agent import BaseAgent
from helpers.context.codebase_context import CodebaseContext
from rich.console import Console
from helpers.context.schema import CryptographicAssetVulnerability
from helpers.context.open_source_context import OpenSourceContext
from helpers.tools.cbom_agent.source_scanner import scan_directory, CryptoAssetDetection
from helpers.tools.cbom_agent.binary_scanner import run_cbomkit_theia, parse_theia_components, is_cbomkit_theia_available
from helpers.tools.cbom_agent.summary_manager import CBOMSummaryManager, FinalCryptographicAssetVulnerabilities
from helpers.tools.cbom_agent.parser import parse_detections_to_strings, generate_cyclonedx_cbom, cbom_json_to_string
from helpers.tools.cbom_agent.crypto_rules import WEAK_ALGORITHMS, STANDARD_ALGORITHMS
from helpers.context.progress_writer import StateUpdateWriter
from langchain.text_splitter import RecursiveCharacterTextSplitter

console = Console()


class CBOMAgent(BaseAgent):
    def __init__(
        self,
        context: GithubContext | GitlabContext | BitbucketContext | None = None,
        zip_context: ZipContext | None = None,
        cbom_file_context: FileContext | None = None,
        scan_binaries: bool = False,
        state_update_writer: StateUpdateWriter | None = None,
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
            self.scan_binaries = scan_binaries
            self.state_update_writer: StateUpdateWriter | None = state_update_writer

            # initialized later
            self.vulnerabilities: list[type[CryptographicAssetVulnerability]] | None = None
            self.raw_detections: list[dict] = []
            self.cyclonedx_cbom: dict | None = None

        except Exception as e:
            raise ValueError(f"Error in initializing CBOMAgent: {e}")

    # -----------------------------------------------------------------
    # Core scanning flow
    # -----------------------------------------------------------------

    def scan_source_code(self) -> list[dict]:
        """Run the custom regex/AST source scanner on the directory."""
        try:
            console.print("Running CBOM source code scanner ...", style="bold yellow")
            if not self.directory:
                raise ValueError("Directory not found")

            detections: list[CryptoAssetDetection] = scan_directory(str(self.directory))
            console.print(f"Source scanner found {len(detections)} crypto asset detections", style="bold yellow")

            # Convert dataclass instances to dicts
            results = []
            for d in detections:
                results.append({
                    "algorithm_name": d.algorithm_name,
                    "algorithm_type": d.algorithm_type,
                    "crypto_strength": d.crypto_strength,
                    "key_size": d.key_size,
                    "quantum_safe": d.quantum_safe,
                    "location": d.location,
                    "snippet": d.snippet,
                    "language": d.language,
                    "source": "source_scanner",
                })
            return results

        except Exception as e:
            raise ValueError(f"Error scanning source code: {e}")

    def run_binary_scan(self) -> list[dict]:
        """Run cbomkit-theia binary scanner on the directory."""
        try:
            console.print("Running cbomkit-theia binary scanner ...", style="bold yellow")
            if not self.directory:
                raise ValueError("Directory not found")

            theia_output = run_cbomkit_theia(str(self.directory))
            if not theia_output:
                console.print("cbomkit-theia returned no results", style="dim yellow")
                return []

            assets = parse_theia_components(theia_output)
            console.print(f"Binary scanner found {len(assets)} crypto assets", style="bold yellow")
            return assets

        except Exception as e:
            console.print(f"Error in binary scanning (non-fatal): {e}", style="bold yellow")
            return []

    def analyze_cbom_file(self) -> None:
        """Analyze a pre-existing CBOM JSON file using LLM map-reduce."""
        try:
            console.print("Analyzing CBOM file ...", style="bold yellow")
            if not self.cbom_json_file:
                raise ValueError("CBOM file not found")

            with open(self.cbom_json_file, "r", errors="ignore") as f:
                cbom_json = json.load(f)

            # Store the raw CBOM for later
            self.cyclonedx_cbom = cbom_json

            # Split into documents for LLM processing
            splitter = RecursiveCharacterTextSplitter(chunk_size=10000)
            split_docs = splitter.create_documents(texts=[json.dumps(cbom_json)])
            if not split_docs:
                raise ValueError("No split documents found from CBOM file")

            # Use mock open source context for map-reduce (following SCA/SBOM pattern)
            mock_context = OpenSourceContext(
                open_source_tool=lambda *a, **kw: None,
                argument="mock",
            )
            mock_context.documents = split_docs

            summary = mock_context.generate_map_reduce_summary(
                summary_manager=CBOMSummaryManager()
            )
            output: type[FinalCryptographicAssetVulnerabilities] = summary
            vulnerabilities = output.vulnerabilities

            console.print(f"Vulnerabilities from CBOM file: {len(vulnerabilities)}", style="bold yellow")
            for i, v in enumerate(vulnerabilities):
                console.print(f" 🔐 Vulnerability #{i + 1}: {v.title}", style="bold yellow")

            self.vulnerabilities = vulnerabilities

        except Exception as e:
            raise ValueError(f"Error analyzing CBOM file: {e}")

    def run_source_scan_with_llm(self) -> None:
        """Run source/binary scanning, then LLM enrichment via map-reduce."""
        try:
            # STEP 1: Source code scanning
            detections = self.scan_source_code()
            self.raw_detections.extend(detections)

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(30)

            # STEP 2: Binary scanning (optional)
            if self.scan_binaries and is_cbomkit_theia_available():
                binary_detections = self.run_binary_scan()
                self.raw_detections.extend(binary_detections)

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(50)

            # Sort raw detections for deterministic downstream processing
            # (LLM chunking order and CycloneDX component order)
            self.raw_detections.sort(
                key=lambda d: (
                    d.get("algorithm_name", ""),
                    d.get("location", ""),
                    d.get("algorithm_type", ""),
                )
            )

            # STEP 3: Generate CycloneDX CBOM JSON from raw detections
            repo_url = None
            if hasattr(self, "directory") and self.directory:
                repo_url = str(self.directory)
            self.cyclonedx_cbom = generate_cyclonedx_cbom(self.raw_detections, repo_url=repo_url)

            console.print(f"Generated CycloneDX CBOM with {len(self.cyclonedx_cbom.get('components', []))} components", style="bold cyan")

            # STEP 4: LLM enrichment via map-reduce
            parsed_strings = parse_detections_to_strings(self.raw_detections)
            if not parsed_strings:
                console.print("No crypto detections found, returning empty results", style="bold yellow")
                self.vulnerabilities = []
                return

            # Combine 10 detections per document for map-reduce
            docs = []
            for i in range(0, len(parsed_strings), 10):
                concatenated = "\n".join(parsed_strings[i:i + 10])
                docs.append(Document(page_content=concatenated))

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(60)

            # Use OpenSourceContext for map-reduce (following SCA/SBOM pattern)
            mock_context = OpenSourceContext(
                open_source_tool=lambda *a, **kw: None,
                argument="mock",
            )
            mock_context.documents = docs

            summary = mock_context.generate_map_reduce_summary(
                summary_manager=CBOMSummaryManager()
            )
            output: type[FinalCryptographicAssetVulnerabilities] = summary
            vulnerabilities = output.vulnerabilities

            console.print(f"Vulnerabilities from LLM enrichment: {len(vulnerabilities)}", style="bold yellow")
            for i, v in enumerate(vulnerabilities):
                console.print(f" 🔐 Vulnerability #{i + 1}: {v.title}", style="bold yellow")

            self.vulnerabilities = vulnerabilities

        except Exception as e:
            raise ValueError(f"Error in source scan with LLM: {e}")

    @property
    def _should_scan_binaries(self) -> bool:
        """Check if binary scanning should be performed."""
        # scan_binaries is also an instance attribute; use the flag stored during init
        return object.__getattribute__(self, "__dict__").get("scan_binaries", False)

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

    def run_agent(self):
        """Runs the CBOM agent and returns the vulnerabilities + CycloneDX CBOM."""
        try:
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(10)

            if self.directory:
                self.run_source_scan_with_llm()
            elif self.cbom_json_file:
                self.analyze_cbom_file()
            else:
                raise ValueError("Invalid Input, either directory or cbom_json_file is required")

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(90)

            # Cleanup
            console.print("Performing cleanup .... 🧹", style="dim bright_cyan")
            self.clean_up()

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(100)

            # Return vulnerabilities
            return self.vulnerabilities

        except Exception as e:
            console.print(f"Error occurred in run_agent: {str(e)}", style="bold red")
            self.clean_up()
            raise Exception(f"Error occurred while running CBOM agent: {str(e)}")

    def get_cyclonedx_cbom(self) -> dict | None:
        """Return the generated CycloneDX CBOM JSON dict."""
        return self.cyclonedx_cbom

    # File extensions relevant to CBOM crypto scanning (mirrors LANGUAGE_EXTENSIONS from crypto_rules)
    CBOM_FILE_EXTENSIONS = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".java", ".go", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
        ".rb", ".rs",
    }

    def _measure_directory_size(self) -> tuple[int, float, float]:
        """Walk self.directory and sum file sizes for CBOM-relevant extensions.

        Returns (size_bytes, size_mb, size_gb).  This is a lightweight alternative
        to CodebaseContext.estimate_size_of_documents() — no LangChain document
        loading/splitting, no vector-DB dependency.
        """
        total_bytes = 0
        file_count = 0
        for root, _dirs, files in os.walk(self.directory):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in self.CBOM_FILE_EXTENSIONS:
                    fpath = os.path.join(root, fname)
                    if os.path.islink(fpath):
                        continue
                    try:
                        total_bytes += os.path.getsize(fpath)
                        file_count += 1
                    except OSError:
                        pass
        size_mb = total_bytes / (1024 * 1024)
        size_gb = size_mb / 1024
        console.print(
            f"CBOM estimation: {file_count} files, {size_mb:.2f} MB across "
            f"{len(self.CBOM_FILE_EXTENSIONS)} extension types",
            style="bold yellow",
        )
        return total_bytes, size_mb, size_gb

    def estimate_credits_required(self) -> float:
        """Estimates the credits required for the CBOM scan based on codebase size."""
        try:
            total_credits = 0.0

            if self.directory:
                # Lightweight directory walk — no CodebaseContext / LangChain overhead
                _size_b, codebase_size_in_mb, _size_gb = self._measure_directory_size()
                credits_from_scanning = codebase_size_in_mb / 0.5  # 1 credit ~ 0.5 MB
                credits_from_llm_enrichment = 0.04 / 0.836  # LLM enrichment constant cost (1 credit ~ $0.836)
                total_credits = credits_from_scanning + credits_from_llm_enrichment
                # Binary scanning via cbomkit-theia adds ~40% overhead for large repos
                if self.scan_binaries:
                    total_credits *= 1.4
            else:
                # CBOM file analysis only — flat cost for LLM enrichment
                credits_from_llm_enrichment = 0.01 / 0.836
                total_credits = credits_from_llm_enrichment
                if self.scan_binaries:
                    total_credits *= 1.4

            return total_credits

        except Exception as e:
            raise e

        finally:
            console.print("Performing cleanup .... 🧹", style="dim bright_cyan")
            self.clean_up()
