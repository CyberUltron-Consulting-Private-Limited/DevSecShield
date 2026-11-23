import json
import os
import re
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
from helpers.tools.sca_sbom_agent.syft import action_pins, own_go_modules, version_constraints
from helpers.tools.sca_sbom_agent.grype_findings import grype_db_info, finding_rows, merge_llm_enrichment
from helpers.tools.sca_sbom_agent.merge_inventory import (
    assemble_cyclonedx,
    dependency_types,
    drop_own_modules,
    inventory_to_finding_rows,
    load_cdx_json,
    merge_cdx_components,
    pin_actions,
    prefer_pinned,
    subject_from_repo,
)
from helpers.tools.sca_sbom_agent.pip_lock import lock_document
from helpers.tools.sca_sbom_agent.registry_enrich import licence_fields, resolve_components, stamp_rows
from helpers.tools.sca_sbom_agent.spdx_convert import is_spdx, spdx_to_cyclonedx
import tempfile
import threading


console = Console()

_ON = {"1", "true", "yes", "on"}
GO_STDLIB_NOTE = ("Go standard library advisories (the toolchain named by a go.mod 'go' directive) are not matched: "
                  "Grype reads module dependencies only")


def llm_enrichment_enabled() -> bool:
    """``SBOM_LLM_ENRICHMENT`` (default OFF, review 6028132826 m4): the optional LLM pass (AWS Bedrock only) that adds
    OWASP / compliance mappings and a summary to the Grype findings. It also needs AWS credentials; off, failing or
    slow, the findings are the same (SOW D4: deterministic, air-gappable)."""
    if (os.environ.get("SBOM_LLM_ENRICHMENT") or "0").strip().lower() not in _ON:
        return False
    return bool(os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"))


def llm_enrichment_timeout() -> float:
    """Wall-clock budget of the LLM pass (``SBOM_LLM_ENRICHMENT_TIMEOUT_S``, default 60 s)."""
    try:
        return max(1.0, float(os.environ.get("SBOM_LLM_ENRICHMENT_TIMEOUT_S") or 60))
    except ValueError:
        return 60.0


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


def _license_index(components: list[dict]) -> dict[str, tuple[str, str]]:
    """``purl`` and ``name@version`` -> (licence, category) of the resolved SBOM components (the one resolution)."""
    out: dict[str, tuple[str, str]] = {}
    for comp in components:
        lic = licence_fields(comp)
        purl = str(comp.get("purl") or "").split("?", 1)[0]
        if purl:
            out[purl] = lic
        name, ver = str(comp.get("name") or ""), str(comp.get("version") or "")
        if name and ver:
            out[f"{re.sub(r'[-_.]+', '-', name.strip().lower())}@{ver.strip()}"] = lic
    return out


def _set_prop(doc: dict, name: str, value: str) -> None:
    meta = doc.setdefault("metadata", {})
    props = [p for p in meta.get("properties") or [] if isinstance(p, dict) and p.get("name") != name]
    props.append({"name": name, "value": value})
    meta["properties"] = props



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
        comps = list((self.sbom_json or {}).get("components") or []) if isinstance(self.sbom_json, dict) else []
        rows = finding_rows(
            self.grype_document,
            licenses=_license_index(comps),
            guessed_versions=constraints,
            dependency_types=dependency_types(self.sbom_json),
        )
        self.vulnerability_rows = rows
        self.vulnerabilities = rows
        self.bom_properties["sbom:vuln_source"] = "grype"
        self.bom_properties["sbom:llm_enrichment"] = self._enrich(rows)
        descriptor = (self.grype_document or {}).get("descriptor") or {}
        db = grype_db_info(self.grype_document)
        if isinstance(self.sbom_json, dict) and descriptor.get("version"):
            tools = ((self.sbom_json.get("metadata") or {}).get("tools") or {}).get("components")
            if isinstance(tools, list) and not any(str(t.get("name")).lower() == "grype" for t in tools):
                entry = {"type": "application", "name": "grype", "version": str(descriptor["version"]),
                         "publisher": "anchore"}
                if db.get("built"):
                    entry["description"] = f"vulnerability database built {db['built']}"
                tools.append(entry)
        if isinstance(self.sbom_json, dict):
            # review m3: the database build time makes a scan's findings reproducible; Go stdlib is not covered
            if db.get("built"):
                _set_prop(self.sbom_json, "dss:grype_db_built", db["built"])
                self.bom_properties["sbom:grype_db_built"] = db["built"]
            if db.get("schema"):
                _set_prop(self.sbom_json, "dss:grype_db_schema", db["schema"])
            _set_prop(self.sbom_json, "dss:coverage_note", GO_STDLIB_NOTE)
        console.print(f"Vulnerabilities (Grype): {len(rows)}", style="bold yellow")

    def _enrich(self, rows: list[dict]) -> str:
        """LLM map-reduce over the Grype matches (AWS Bedrock), within ``llm_enrichment_timeout()``; adds mappings to
        ``rows`` only once it finished in time. Returns applied / failed / timeout / disabled / skipped. Any error
        (an invalid Bedrock token on staging scan #14) is logged and the scan goes on."""
        if not llm_enrichment_enabled():
            return "disabled"
        parsed = parse_sbom_results_to_strings(self.grype_document)
        if not rows or not parsed:
            return "skipped"
        box: dict = {}

        def _run() -> None:
            try:
                try:  # no LangSmith trace upload: Bedrock is the only egress this pass may use
                    from langsmith.run_helpers import tracing_context
                except Exception:  # pragma: no cover - langsmith is a langchain dependency
                    tracing_context = None
                ctx = OpenSourceContext(open_source_tool=run_sbom_scan, argument="enrichment")
                ctx.documents = [Document(page_content=" ".join(parsed[i : i + 10])) for i in range(0, len(parsed), 10)]
                if tracing_context is not None:
                    with tracing_context(enabled=False):
                        summary = ctx.generate_map_reduce_summary(summary_manager=SBOMSCASummaryManager())
                else:
                    summary = ctx.generate_map_reduce_summary(summary_manager=SBOMSCASummaryManager())
                vulns = summary.vulnerabilities if hasattr(summary, "vulnerabilities") else []
                box["enriched"] = self.to_dict_list(list(vulns or []))
            except Exception as e:  # enrichment only: the Grype findings stand on their own
                box["error"] = e

        worker = threading.Thread(target=_run, name="sbom-llm-enrichment", daemon=True)
        worker.start()
        worker.join(llm_enrichment_timeout())
        if worker.is_alive():
            console.print("LLM enrichment timed out; findings unchanged", style="bold yellow")
            return "timeout"
        if "error" in box:
            e = box["error"]
            console.print(f"LLM enrichment skipped ({e.__class__.__name__}): {str(e)[:300]}", style="bold yellow")
            return "failed"
        touched = merge_llm_enrichment(rows, box.get("enriched") or [])
        console.print(f"LLM enrichment applied to {touched} finding(s)", style="bold green")
        return "applied"

    def _finalize_inventory(self, constraints: dict[str, str]) -> None:
        """Resolve licences / authors / hashes once (registry_enrich), then the inventory rows from that document."""
        if not isinstance(self.sbom_json, dict):
            self.inventory_rows = []
            return
        comps = self.sbom_json.get("components") or []
        stats = resolve_components(comps)
        _set_prop(self.sbom_json, "dss:registry", "{registry}: {resolved}/{looked_up} resolved, {timed_out} timed out"
                  .format(**stats))
        self.bom_properties["sbom:registry"] = stats["registry"]
        self.inventory_rows = inventory_to_finding_rows(comps, vuln_assessed=True,
                                                        dependency_types=dependency_types(self.sbom_json))
        stamp_rows(self.inventory_rows, comps)

    def _run_grype(self, directory=None, fallback_file=None):
        """Grype on the assembled CycloneDX document (both tools' packages); on the directory / upload when empty."""
        grype_input = None
        if self.sbom_json is not None and self.sbom_json.get("components"):
            handle = tempfile.NamedTemporaryFile("w", suffix=".merged.cdx.json", delete=False)
            with handle:
                json.dump(self.sbom_json, handle)
            grype_input = handle.name
        try:
            if directory is not None:
                def _grype_tool(directory):  # OpenSourceContext calls it with its own kwargs (directory=...)
                    return run_sbom_scan(directory=directory, sbom_file=grype_input)

                ctx = OpenSourceContext(open_source_tool=_grype_tool, directory=directory)
                ctx.run_open_source_tool()
                return ctx.results
            return run_sbom_scan(sbom_file=grype_input or fallback_file)
        finally:
            if grype_input:
                os.unlink(grype_input)

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

            syft_doc = load_cdx_json(syft_path)
            pinned_actions = pin_actions(syft_doc, action_pins(syft_path))  # tag -> the SHA the workflow runs
            cdxgen_doc = load_cdx_json(cdxgen_path)
            locks = lock_document(self.directory)  # pip-format *.lock files neither tool reads (review M2)
            if locks is not None:
                tools.append("pip-lock")
            source_docs = [d for d in (syft_doc, cdxgen_doc, locks) if d]
            merged_comps = merge_cdx_components(*source_docs)
            merged_comps, constraints, dropped = prefer_pinned(merged_comps, version_constraints(syft_path))
            merged_comps = drop_own_modules(merged_comps, own_go_modules(self.directory))
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
            console.print(f"Range guesses replaced by a lock / pin: {len(dropped)}; actions pinned by SHA: "
                          f"{pinned_actions}", style="dim")

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

            # --- licences / authors / hashes resolved once; inventory rows from the same document ---
            self._finalize_inventory(constraints)
            # --- Grype on the merged inventory (both tools' packages), dir: when there is none ---
            grype_document = self._run_grype(directory=self.directory)
            console.print(
                f"Inventory components: {len(self.inventory_rows)} "
                f"(tools={tools or ['none']}, versions from ranges={len(constraints)})",
                style="bold yellow",
            )
            self._set_findings(grype_document, constraints)

        except Exception as e:
            raise ValueError(f"Error in populating open source context: {e}")
    

    def analyze_sbom_file(self)->None:
        """
        An uploaded SBOM (CycloneDX, or SPDX 2.x / 3.0 JSON converted offline first, review 6028132826 M5): the same
        CycloneDX 1.6 assembly as a repository scan, then Grype on that document (deterministic, no LLM needed).
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
            if is_spdx(uploaded):
                source = spdx_to_cyclonedx(uploaded)
                self.bom_properties["sbom:automation_spdx"] = "true"
                self.bom_properties["sbom:uploaded_format"] = str(
                    uploaded.get("spdxVersion") or "SPDX-3.0")
            elif uploaded.get("bomFormat") == "CycloneDX":
                source = uploaded
            else:
                raise ValueError("The uploaded file is neither a CycloneDX nor an SPDX JSON SBOM")
            components = merge_cdx_components(source)
            meta = source.get("metadata") if isinstance(source.get("metadata"), dict) else {}
            subject = meta.get("component") if isinstance(meta.get("component"), dict) else None
            self.sbom_json = assemble_cyclonedx(
                components,
                tools=["uploaded-sbom"],
                subject=dict(subject) if subject and subject.get("name") else None,
                subject_name="uploaded-sbom",
                source_docs=[source],
            )
            for prop in meta.get("properties") or []:  # dss:converted_from, dss:spdx_relationships_unmapped
                if isinstance(prop, dict) and str(prop.get("name") or "").startswith("dss:"):
                    _set_prop(self.sbom_json, str(prop["name"]), str(prop.get("value") or ""))
            self.bom_properties["sbom:timestamp"] = str(self.sbom_json["metadata"]["timestamp"])
            self._finalize_inventory({})
            grype_document = self._run_grype(fallback_file=self.sbom_json_file)
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
    
