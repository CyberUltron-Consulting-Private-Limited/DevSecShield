import json
import os
import re
from pathlib import Path
import shutil
from langchain_core.documents import Document
from helpers.context.codebase_context import CodebaseContext
from helpers.context.open_source_context import OpenSourceContext
from helpers.context.scan_context import *
from helpers.context.base_agent import BaseAgent
from typing import Literal
from rich.console import Console
from helpers.tools.sca_sbom_agent.grype import run_sbom_scan
from helpers.context.schema import * 
from helpers.tools.iac_agent.summary_manager import IACSummaryManager , FinalIACVulnerabilities
from helpers.tools.iac_agent.context import IACTypeContext
from helpers.tools.sca_sbom_agent.summary_manager import SBOMSCASummaryManager
from helpers.context.progress_writer import StateUpdateWriter
from langchain.text_splitter import CharacterTextSplitter
from helpers.tools.sca_sbom_agent.parser import parse_sbom_results_to_strings
from helpers.tools.sca_sbom_agent.syft import run_syft
from helpers.tools.sca_sbom_agent.cdxgen_run import run_cdxgen
from helpers.tools.sca_sbom_agent.syft import version_constraints
from helpers.tools.sca_sbom_agent.grype_findings import finding_rows, merge_llm_enrichment
from helpers.tools.sca_sbom_agent.merge_inventory import (
    assemble_cyclonedx,
    inventory_to_finding_rows,
    load_cdx_json,
    merge_cdx_components,
    subject_from_repo,
)
import tempfile


console = Console()

_OFF = {"0", "false", "no", "off"}


def llm_enrichment_enabled() -> bool:
    """``SBOM_LLM_ENRICHMENT`` (default on): the optional LLM pass that adds OWASP / compliance mappings and a summary
    to the Grype findings. Off, failing or slow, the findings are the same (SOW D4: deterministic, air-gappable)."""
    return (os.environ.get("SBOM_LLM_ENRICHMENT") or "1").strip().lower() not in _OFF


def combine_rows(inventory: list[dict], vuln_rows: list[dict]) -> list[dict]:
    """The scan's result rows: every vulnerability row (one per advisory, package and version), then the inventory
    rows of packages that have no vulnerability. Keying by package (the old ``_finalize_sbom``) kept only one
    advisory per package."""
    vulnerable = {str(r.get("dependency") or "").strip().lower() for r in vuln_rows if isinstance(r, dict)}
    out = [r for r in vuln_rows if isinstance(r, dict)]
    seen: set[str] = set()
    for row in inventory:
        dep = str((row or {}).get("dependency") or "").strip().lower()
        if not dep or dep in vulnerable or dep in seen:
            continue
        seen.add(dep)
        out.append(row)
    return out


def _license_index(inventory: list[dict]) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for row in inventory:
        lic = (str(row.get("license") or ""), str(row.get("license_type") or "not_declared"))
        purl = str(row.get("purl") or "").split("?", 1)[0]
        if purl:
            out[purl] = lic
        dep = str(row.get("dependency") or "")
        if "==" in dep:
            name, _, ver = dep.partition("==")
            out[f"{re.sub(r'[-_.]+', '-', name.strip().lower())}@{ver.strip()}"] = lic
    return out



class SCASBOMAgent(BaseAgent):
    def __init__(
        self,
        context: GithubContext | GitlabContext | BitbucketContext | None = None,
        zip_context: ZipContext | None = None,
        sbom_json_file_context: FileContext = None,
        state_update_writer: StateUpdateWriter | None = None,  
        ):
        try:
            directory = None
            file = None
            if context:
                directory = clone_repo_from_context(context)
            elif zip_context:
                directory = get_directory_from_zip_context(zip_context)
            elif sbom_json_file_context:
                file = get_file_from_file_context(sbom_json_file_context)
            
            if not directory and not file:
                raise ValueError(f"Invalid Input , either directory or file is required")
            
            self.directory = directory # SET directory ⭐
            self.sbom_json_file = file  # SET sbom_json_file ⭐
            # the SBOM subject (metadata.component): repository and branch; the clone URL's credentials are dropped
            self.repo_info = {"repo_url": getattr(context, "repo_url", None), "branch": getattr(context, "branch", None)}

            self.state_update_writer : StateUpdateWriter | None = state_update_writer

            #initializing
            self.vulnerabilities : list[dict] | None = None
            self.vulnerability_rows: list[dict] = []
            self.inventory_rows: list[dict] = []
            self.bom_properties: dict[str, str] = {}
            self.sbom_json: dict | None = None

        except Exception as e:
            raise ValueError(f"Error in initializing SCASBOMAgent: {e}")
    
    def _set_findings(self, grype_document, constraints: dict[str, str] | None = None) -> None:
        """Findings from Grype (deterministic), then the optional LLM enrichment (never fatal)."""
        self.grype_document = grype_document if isinstance(grype_document, dict) else None
        direct = None
        if isinstance(self.sbom_json, dict):
            deps = self.sbom_json.get("dependencies") or []
            if len(deps) > 1:  # the source tools gave a graph: the subject's own edges are the direct dependencies
                root = str(((self.sbom_json.get("metadata") or {}).get("component") or {}).get("bom-ref") or "")
                direct = {k for d in deps if d.get("ref") == root for k in d.get("dependsOn") or []}
        rows = finding_rows(
            self.grype_document,
            licenses=_license_index(self.inventory_rows),
            guessed_versions=constraints,
            direct=direct,
        )
        self.vulnerability_rows = rows
        self.vulnerabilities = rows
        self.bom_properties["sbom:vuln_source"] = "grype"
        self.bom_properties["sbom:llm_enrichment"] = self._enrich(rows)
        descriptor = (self.grype_document or {}).get("descriptor") or {}
        if isinstance(self.sbom_json, dict) and descriptor.get("version"):
            tools = ((self.sbom_json.get("metadata") or {}).get("tools") or {}).get("components")
            if isinstance(tools, list) and not any(str(t.get("name")).lower() == "grype" for t in tools):
                tools.append({"type": "application", "name": "grype", "version": str(descriptor["version"]),
                              "publisher": "anchore"})
        console.print(f"Vulnerabilities (Grype): {len(rows)}", style="bold yellow")

    def _enrich(self, rows: list[dict]) -> str:
        """LLM map-reduce over the Grype matches: adds mappings to ``rows`` and returns applied / failed / disabled /
        skipped. Any error (an invalid Bedrock token on staging scan #14) is logged and the scan goes on."""
        if not llm_enrichment_enabled():
            return "disabled"
        parsed = parse_sbom_results_to_strings(self.grype_document)
        if not rows or not parsed:
            return "skipped"
        try:
            ctx = OpenSourceContext(open_source_tool=run_sbom_scan, argument="enrichment")
            ctx.documents = [Document(page_content=" ".join(parsed[i : i + 10])) for i in range(0, len(parsed), 10)]
            summary = ctx.generate_map_reduce_summary(summary_manager=SBOMSCASummaryManager())
            vulns = summary.vulnerabilities if hasattr(summary, "vulnerabilities") else []
            enriched = self.to_dict_list(list(vulns or []))
            touched = merge_llm_enrichment(rows, enriched)
            console.print(f"LLM enrichment applied to {touched} finding(s)", style="bold green")
            return "applied"
        except Exception as e:  # enrichment only: the Grype findings stand on their own
            console.print(f"LLM enrichment skipped ({e.__class__.__name__}): {str(e)[:300]}", style="bold yellow")
            return "failed"

    def populate_opensource_context(self)->None:
        """
        Multi-engine SBOM path: Syft + cdxgen inventory → one CycloneDX 1.6 document → Grype matches → findings.
        """
        try:
            console.print(f"Populating open source context ...",style="bold yellow")
            if not self.directory :
                raise ValueError(f"Directory not found")

            # --- Inventory engines (best-effort; missing binaries degrade) ---
            syft_path = run_syft(self.directory)
            cdxgen_path = run_cdxgen(self.directory)
            tools: list[str] = []
            if syft_path is not None:
                tools.append("syft")
            if cdxgen_path is not None:
                tools.append("cdxgen")

            merged_comps = merge_cdx_components(syft_path, cdxgen_path)
            source_docs = [d for d in (load_cdx_json(syft_path), load_cdx_json(cdxgen_path)) if d]
            constraints = version_constraints(syft_path)
            info = getattr(self, "repo_info", None) or {}
            subject = subject_from_repo(
                info.get("repo_url"), info.get("branch"), self.directory,
                fallback_name="uploaded-archive",  # never the temp directory's name (audit G-D4-4)
            )
            self.sbom_json = assemble_cyclonedx(
                merged_comps,
                tools=tools,
                subject=subject,
                source_docs=source_docs,
                constraints=constraints,
            ) if (merged_comps or source_docs) else None

            bom_props: dict[str, str] = {
                "sbom:author": "DevSecShield",
                "sbom:vuln_scanner": "grype",
            }
            if tools:
                bom_props["sbom:inventory_tools"] = ",".join(tools)
            if self.sbom_json is not None:
                bom_props["sbom:automation_cyclonedx"] = "true"
                bom_props["sbom:multi_format_emit"] = "true"
                bom_props["sbom:timestamp"] = str(self.sbom_json["metadata"]["timestamp"])
            if constraints:
                bom_props["sbom:versions_from_ranges"] = str(len(constraints))
            self.bom_properties = bom_props

            # --- Grype on the merged inventory (both tools' packages), dir: when there is none ---
            grype_input = None
            if self.sbom_json is not None and self.sbom_json.get("components"):
                handle = tempfile.NamedTemporaryFile("w", suffix=".merged.cdx.json", delete=False)
                with handle:
                    json.dump(self.sbom_json, handle)
                grype_input = handle.name

            def _grype_tool(directory):
                return run_sbom_scan(directory=directory, sbom_file=grype_input)

            open_source_context = OpenSourceContext(
                open_source_tool=_grype_tool,
                directory=self.directory,
            )
            try:
                open_source_context.run_open_source_tool()
            finally:
                if grype_input:
                    os.unlink(grype_input)

            # Inventory rows: Grype ran → mark assessed even when match count is 0.
            self.inventory_rows = inventory_to_finding_rows(
                merged_comps, vuln_assessed=True
            )
            console.print(
                f"Inventory components: {len(self.inventory_rows)} "
                f"(tools={tools or ['none']}, versions from ranges={len(constraints)})",
                style="bold yellow",
            )
            self._set_findings(open_source_context.results, constraints)

        except Exception as e:
            raise ValueError(f"Error in populating open source context: {e}")
    

    def analyze_sbom_file(self)->None:
        """
        An uploaded SBOM (CycloneDX or SPDX JSON): Grype matches its packages (deterministic, no LLM needed); a
        CycloneDX upload is normalised to CycloneDX 1.6 with the same metadata as a repository scan.
        """
        try:
            console.print(f"Analyzing SBOM file ...",style="bold yellow")
            if not self.sbom_json_file:
                raise ValueError(f"SBOM file not found")
            with open(self.sbom_json_file, "r",errors="ignore") as f:
                uploaded = json.load(f)
            if not isinstance(uploaded, dict):
                raise ValueError("The uploaded SBOM is not a JSON object")
            self.bom_properties = {
                "sbom:author": "DevSecShield",
                "sbom:vuln_scanner": "grype",
                "sbom:automation_cyclonedx": "true",
                "sbom:multi_format_emit": "true",
                "sbom:inventory_tools": "uploaded-sbom",
            }
            components = []
            if uploaded.get("bomFormat") == "CycloneDX":
                components = merge_cdx_components(Path(self.sbom_json_file))
                meta = uploaded.get("metadata") if isinstance(uploaded.get("metadata"), dict) else {}
                subject = meta.get("component") if isinstance(meta.get("component"), dict) else None
                self.sbom_json = assemble_cyclonedx(
                    components,
                    tools=["uploaded-sbom"],
                    subject=dict(subject) if subject and subject.get("name") else None,
                    subject_name="uploaded-sbom",
                    source_docs=[uploaded],
                )
                self.bom_properties["sbom:timestamp"] = str(self.sbom_json["metadata"]["timestamp"])
            else:
                self.sbom_json = uploaded  # SPDX: kept as uploaded; Grype reads it directly
            self.inventory_rows = inventory_to_finding_rows(components, vuln_assessed=True)
            grype_document = run_sbom_scan(sbom_file=self.sbom_json_file)
            self._set_findings(grype_document)

        except Exception as e:
            raise ValueError(f"Error in analyzing SBOM file: {e}")
    
    def clean_up(self)->None:
        """
        Removes the temporary directory
        """
        try:
            try:
                if self.directory:
                    if os.path.exists(self.directory):
                        console.print("Temp Dir does Exist",style="dim bright_cyan")
                    else:
                        console.print("Temp Dir does NOT Exist",style="dim bright_cyan")
                    
                    console.print(f"Removing temporary directory ...",style="dim red")
                    shutil.rmtree(self.directory)
                    console.print(f"Temporary directory removed successfully",style="bold green")

                    if os.path.exists(self.directory):
                        console.print("Temp Dir does Exist",style="dim bright_cyan")
                    else:
                        console.print("Temp Dir does NOT Exist",style="dim bright_cyan")
                elif self.sbom_json_file:
                    if os.path.exists(self.sbom_json_file):
                        console.print("SBOM file does Exist",style="dim bright_cyan")
                    else:
                        console.print("SBOM file does NOT Exist",style="dim bright_cyan")
                    
                    console.print(f"Removing SBOM file ...",style="dim red")
                    os.remove(self.sbom_json_file)
                    console.print(f"SBOM file removed successfully",style="bold green")
            except Exception as e:
                console.print(f"Error while deleting temp directory : {str(e)}", style = "dim red")


        except Exception as e:
            raise ValueError(f"Error in cleaning up: {e}")

    

    def run_agent(self):
        """
        Runs the agent and returns the vulnerabilities
        """
        try:
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(20)


            if self.directory:
                self.populate_opensource_context()
            elif self.sbom_json_file:
                self.analyze_sbom_file()
            else:
                raise ValueError(f"Invalid Input , either directory or sbom_json_file_context is required")
            

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(80)

            # STEP [ 5 ] ================================ Final checks and cleanup =====================================================================

            console.print("Performing cleanup .... 🧹",style = "dim bright_cyan")
            self.clean_up()

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(100)

            # STEP [ 6 ] ================================ Return the finding rows (dicts) =================================================================
            return self.vulnerability_rows


        except Exception as e:
            console.print(f"Error occured in run_agent : {str(e)}",style="bold red")
            self.clean_up()
            raise Exception(f"Error occured while running agent : {str(e)}")
    

    def estimate_credits_required(self)->int:
        """
        Estimates the credits required for the sbom sca scan
        """
        try:
            total_credits = 0

            # credits from open source context
            credits_from_open_source_context = 0.01 / 0.836 # 1 credit ~ 0.836 $ ( note : 0.01 $ is a constant cost for the sbom sca scan )
            
            # calculate total credits
            total_credits = credits_from_open_source_context
            return total_credits
            
        except Exception as e:
            raise e
        
        finally:
            console.print("Performing cleanup .... 🧹",style = "dim bright_cyan")
            self.clean_up()
    
