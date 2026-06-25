import os
import json
import hashlib
import shutil
from langchain_core.documents import Document
from helpers.context.scan_context import *
from helpers.context.base_agent import BaseAgent
from helpers.context.codebase_context import CodebaseContext
from rich.console import Console
from helpers.context.schema import AIComponentVulnerability
from helpers.context.open_source_context import OpenSourceContext
from helpers.tools.ai_bom_agent.source_scanner import scan_directory, AIComponentDetection
from helpers.tools.ai_bom_agent.binary_scanner import run_aibom_binary_scan, parse_ai_binary_components, is_aibom_scanner_available
from helpers.tools.ai_bom_agent.summary_manager import AIBOMSummaryManager, FinalAIComponentVulnerabilities
from helpers.tools.ai_bom_agent.parser import parse_detections_to_strings, generate_cyclonedx_aibom, ai_bom_json_to_string
from helpers.tools.ai_bom_agent.ai_rules import MODEL_FILE_EXTENSIONS, LANGUAGE_EXTENSIONS
from helpers.context.progress_writer import StateUpdateWriter
from langchain.text_splitter import RecursiveCharacterTextSplitter

console = Console()


class AIBOMAgent(BaseAgent):
    def __init__(
        self,
        context: GithubContext | GitlabContext | BitbucketContext | None = None,
        zip_context: ZipContext | None = None,
        aibom_file_context: FileContext | None = None,
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
            elif aibom_file_context:
                file = get_file_from_file_context(aibom_file_context)

            if not directory and not file:
                raise ValueError("Invalid Input, either directory or AI-BOM file is required")

            self.directory = directory
            self.ai_bom_json_file = file
            self.scan_binaries = scan_binaries
            self.state_update_writer: StateUpdateWriter | None = state_update_writer

            # Store the ORIGINAL repo url (only present for a repo context).
            # None for zip / AI-BOM-file scans. Used to make the generated
            # CycloneDX BOM content-deterministic (metadata.component.name must
            # derive from the real repo, not the random temp dir basename).
            self.repo_url = getattr(context, "repo_url", None) if context else None

            # initialized later
            self.vulnerabilities: list[type[AIComponentVulnerability]] | None = None
            self.raw_detections: list[dict] = []
            self.cyclonedx_aibom: dict | None = None

        except Exception as e:
            raise ValueError(f"Error in initializing AIBOMAgent: {e}")

    # -----------------------------------------------------------------
    # Core scanning flow
    # -----------------------------------------------------------------

    def scan_source_code(self) -> list[dict]:
        """Run the custom regex source scanner on the directory."""
        try:
            console.print("Running AI-BOM source code scanner ...", style="bold yellow")
            if not self.directory:
                raise ValueError("Directory not found")

            detections: list[AIComponentDetection] = scan_directory(str(self.directory))
            console.print(f"Source scanner found {len(detections)} AI component detections", style="bold yellow")

            # Convert dataclass instances to dicts.
            # NOTE: 'source' here carries the ModelProvider value (used by the
            # schema field of the same name). The scanner origin is recorded
            # separately under 'detector' to avoid colliding with it.
            results = []
            for d in detections:
                results.append({
                    "component_name": d.component_name,
                    "component_type": d.component_type,
                    "framework": d.framework,
                    "version": d.version,
                    "source": d.source,
                    "license": d.license,
                    "location": d.location,
                    "snippet": d.snippet,
                    "language": d.language,
                    "risk_category": d.risk_category,
                    "detector": "source_scanner",
                })
            return results

        except Exception as e:
            raise ValueError(f"Error scanning source code: {e}")

    def run_binary_scan(self) -> list[dict]:
        """Run the optional AI-BOM artifact binary scanner on the directory."""
        try:
            console.print("Running AI-BOM binary scanner ...", style="bold yellow")
            if not self.directory:
                raise ValueError("Directory not found")

            output = run_aibom_binary_scan(str(self.directory))
            if not output:
                console.print("AI-BOM binary scanner returned no results", style="dim yellow")
                return []

            assets = parse_ai_binary_components(output)
            console.print(f"Binary scanner found {len(assets)} AI components", style="bold yellow")
            return assets

        except Exception as e:
            console.print(f"Error in binary scanning (non-fatal): {e}", style="bold yellow")
            return []

    def analyze_ai_bom_file(self) -> None:
        """Analyze a pre-existing AI-BOM JSON file using LLM map-reduce."""
        try:
            console.print("Analyzing AI-BOM file ...", style="bold yellow")
            if not self.ai_bom_json_file:
                raise ValueError("AI-BOM file not found")

            with open(self.ai_bom_json_file, "r", errors="ignore") as f:
                aibom_json = json.load(f)

            # Store the raw AI-BOM for later
            self.cyclonedx_aibom = aibom_json

            # Split into documents for LLM processing
            splitter = RecursiveCharacterTextSplitter(chunk_size=10000)
            split_docs = splitter.create_documents(texts=[json.dumps(aibom_json)])
            if not split_docs:
                raise ValueError("No split documents found from AI-BOM file")

            # Use mock open source context for map-reduce (following SCA/SBOM pattern)
            mock_context = OpenSourceContext(
                open_source_tool=lambda *a, **kw: None,
                argument="mock",
            )
            mock_context.documents = split_docs

            summary = mock_context.generate_map_reduce_summary(
                summary_manager=AIBOMSummaryManager()
            )
            # generate_map_reduce_summary may return a raw str (e.g. on a cache
            # hit that only stored raw_text) instead of a model. Guard against
            # AttributeError so a missing structured result degrades to empty
            # rather than failing the whole scan.
            if hasattr(summary, "vulnerabilities"):
                vulnerabilities = summary.vulnerabilities
            else:
                console.print("AI-BOM file map-reduce returned no structured vulnerabilities (raw/empty result); treating as empty", style="bold yellow")
                vulnerabilities = []

            console.print(f"Vulnerabilities from AI-BOM file: {len(vulnerabilities)}", style="bold yellow")
            for i, v in enumerate(vulnerabilities):
                console.print(f" 🤖 Vulnerability #{i + 1}: {v.title}", style="bold yellow")

            self.vulnerabilities = vulnerabilities

        except Exception as e:
            raise ValueError(f"Error analyzing AI-BOM file: {e}")

    @staticmethod
    def _compute_deterministic_scan_id(detections: list[dict]) -> str:
        """Derive a content-deterministic id from the raw detections.

        Identical repo content (same set of AI components) must produce a
        byte-identical id so the generated CycloneDX BOM (serialNumber +
        timestamp) is reproducible across runs. We hash the sorted tuples of
        (component_name, component_type, location) — the stable identity of
        each detection, independent of scan-run-specific fields like temp
        paths or detector ordering.
        """
        identity = sorted(
            (
                str(d.get("component_name", "")),
                str(d.get("component_type", "")),
                str(d.get("location", "")),
            )
            for d in detections
        )
        digest = hashlib.sha256(
            json.dumps(identity, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return digest

    def run_source_scan_with_llm(self) -> None:
        """Run source/binary scanning, then LLM enrichment via map-reduce."""
        try:
            # STEP 1: Source code scanning
            detections = self.scan_source_code()
            self.raw_detections.extend(detections)

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(30)

            # STEP 2: Binary scanning (optional)
            if self.scan_binaries and is_aibom_scanner_available():
                binary_detections = self.run_binary_scan()
                self.raw_detections.extend(binary_detections)

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(50)

            # Sort raw detections for deterministic downstream processing
            # (LLM chunking order and CycloneDX component order)
            self.raw_detections.sort(
                key=lambda d: (
                    d.get("component_name", ""),
                    d.get("location", ""),
                    d.get("component_type", ""),
                    d.get("source", ""),
                )
            )

            # STEP 3: Generate CycloneDX AI-BOM JSON from raw detections.
            # Compute a CONTENT-DETERMINISTIC scan_id from the sorted detections so
            # that identical repo content yields a byte-identical serialNumber +
            # timestamp (routes through the deterministic branch in the parser).
            scan_id = self._compute_deterministic_scan_id(self.raw_detections)
            # Prefer the ORIGINAL repo url over the random temp dir path so that
            # metadata.component.name is stable across runs of the same repo.
            repo_url = self.repo_url or (str(self.directory) if self.directory else None)
            self.cyclonedx_aibom = generate_cyclonedx_aibom(
                self.raw_detections, scan_id=scan_id, repo_url=repo_url
            )

            console.print(f"Generated CycloneDX AI-BOM with {len(self.cyclonedx_aibom.get('components', []))} components", style="bold cyan")

            # STEP 4: LLM enrichment via map-reduce
            parsed_strings = parse_detections_to_strings(self.raw_detections)
            if not parsed_strings:
                console.print("No AI component detections found, returning empty results", style="bold yellow")
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
                summary_manager=AIBOMSummaryManager()
            )
            # generate_map_reduce_summary may return a raw str (e.g. on a cache
            # hit that only stored raw_text) instead of a model. Guard against
            # AttributeError so a missing structured result degrades to empty
            # rather than failing the whole scan.
            if hasattr(summary, "vulnerabilities"):
                vulnerabilities = summary.vulnerabilities
            else:
                console.print("LLM enrichment map-reduce returned no structured vulnerabilities (raw/empty result); treating as empty", style="bold yellow")
                vulnerabilities = []

            console.print(f"Vulnerabilities from LLM enrichment: {len(vulnerabilities)}", style="bold yellow")
            for i, v in enumerate(vulnerabilities):
                console.print(f" 🤖 Vulnerability #{i + 1}: {v.title}", style="bold yellow")

            self.vulnerabilities = vulnerabilities

        except Exception as e:
            raise ValueError(f"Error in source scan with LLM: {e}")

    @property
    def _should_scan_binaries(self) -> bool:
        """Check if binary scanning should be performed."""
        return object.__getattribute__(self, "__dict__").get("scan_binaries", False)

    def clean_up(self):
        """Remove temporary directory or AI-BOM file after scan completes."""
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
                elif self.ai_bom_json_file:
                    if os.path.exists(self.ai_bom_json_file):
                        console.print("AI-BOM file does Exist", style="dim bright_cyan")

                    console.print("Removing AI-BOM file ...", style="dim red")
                    os.remove(self.ai_bom_json_file)
                    console.print("AI-BOM file removed successfully", style="bold green")
            except Exception as e:
                console.print(f"Error while deleting temp directory: {str(e)}", style="dim red")

        except Exception as e:
            raise ValueError(f"Error in cleaning up: {e}")

    # -----------------------------------------------------------------
    # Main entry points
    # -----------------------------------------------------------------

    def run_agent(self):
        """Runs the AI-BOM agent and returns the vulnerabilities + CycloneDX AI-BOM."""
        try:
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(10)

            if self.directory:
                self.run_source_scan_with_llm()
            elif self.ai_bom_json_file:
                self.analyze_ai_bom_file()
            else:
                raise ValueError("Invalid Input, either directory or ai_bom_json_file is required")

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
            raise Exception(f"Error occurred while running AI-BOM agent: {str(e)}")

    def get_aibom_json(self) -> dict | None:
        """Return the generated CycloneDX AI-BOM JSON dict."""
        return self.cyclonedx_aibom

    def _vulnerabilities_as_findings(self) -> list[dict]:
        """Normalize the enriched vulnerability objects into plain finding dicts
        (risk_category / severity) for the compliance engine. Defensive: handles
        pydantic models, dataclasses, dicts, and arbitrary objects."""
        findings: list[dict] = []
        for v in (self.vulnerabilities or []):
            if isinstance(v, dict):
                findings.append(v)
                continue
            dump = getattr(v, "model_dump", None)
            if callable(dump):
                try:
                    findings.append(dump())
                    continue
                except Exception:
                    pass
            findings.append(getattr(v, "__dict__", {}) or {})
        return findings

    def get_compliance_report(self) -> dict | None:
        """Advisory healthcare regulatory-readiness mapping for the generated
        AI-BOM (FDA §524B/SaMD/PCCP, EU AI Act Annex IV, GMLP, HIPAA, NIST AI RMF).

        ADVISORY ONLY — the report carries a disclaimer; it supports but does not
        satisfy regulatory obligations. Returns None when no BOM was produced.
        """
        if not self.cyclonedx_aibom:
            return None
        try:
            from helpers.tools.ai_bom_agent.compliance import evaluate_compliance_dict
            return evaluate_compliance_dict(
                self.cyclonedx_aibom, self._vulnerabilities_as_findings()
            )
        except Exception as e:
            console.print(f"Compliance mapping skipped (non-fatal): {e}", style="bold yellow")
            return None

    # File extensions relevant to AI-BOM scanning: model weight files +
    # source files + manifest files (mirrors ai_rules detection scope).
    AIBOM_FILE_EXTENSIONS = (
        set(MODEL_FILE_EXTENSIONS.keys())
        | set(LANGUAGE_EXTENSIONS.keys())
    )

    def _measure_directory_size(self) -> tuple[int, float, float]:
        """Walk self.directory and sum file sizes for AI-BOM-relevant extensions.

        Model weight files are summed by extension WITHOUT the 2MB cap (weights
        are large); source/manifest files are summed the same way. This is a
        lightweight alternative to CodebaseContext.estimate_size_of_documents().
        """
        total_bytes = 0
        file_count = 0
        for root, _dirs, files in os.walk(self.directory):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in self.AIBOM_FILE_EXTENSIONS:
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
            f"AI-BOM estimation: {file_count} files, {size_mb:.2f} MB across "
            f"{len(self.AIBOM_FILE_EXTENSIONS)} extension types",
            style="bold yellow",
        )
        return total_bytes, size_mb, size_gb

    def estimate_credits_required(self) -> float:
        """Estimates the credits required for the AI-BOM scan based on codebase size."""
        try:
            total_credits = 0.0

            if self.directory:
                # Lightweight directory walk — no CodebaseContext / LangChain overhead
                _size_b, codebase_size_in_mb, _size_gb = self._measure_directory_size()
                credits_from_scanning = codebase_size_in_mb / 0.5  # 1 credit ~ 0.5 MB
                credits_from_llm_enrichment = 0.04 / 0.836  # LLM enrichment constant cost (1 credit ~ $0.836)
                total_credits = credits_from_scanning + credits_from_llm_enrichment
                # Binary scanning adds ~40% overhead for large repos
                if self.scan_binaries:
                    total_credits *= 1.4
            else:
                # AI-BOM file analysis only — flat cost for LLM enrichment
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
