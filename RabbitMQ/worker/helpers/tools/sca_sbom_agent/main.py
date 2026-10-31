import json
import os
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
from helpers.tools.sca_sbom_agent.summary_manager import FinalDependencyVulnerabilities, SBOMSCASummaryManager , SBOMSCASummaryManagerForSBOMFile
from helpers.context.progress_writer import StateUpdateWriter
from langchain.text_splitter import CharacterTextSplitter
from helpers.tools.sca_sbom_agent.parser import parse_sbom_results_to_strings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from helpers.tools.sca_sbom_agent.syft import run_syft
from helpers.tools.sca_sbom_agent.cdxgen_run import run_cdxgen
from helpers.tools.sca_sbom_agent.merge_inventory import (
    assemble_cyclonedx,
    inventory_to_finding_rows,
    load_cdx_json,
    merge_cdx_components,
)


console = Console()




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

            self.state_update_writer : StateUpdateWriter | None = state_update_writer

            #initializing
            self.vulnerabilities : list[type[DependencyVulnerability]] | None = None
            self.inventory_rows: list[dict] = []
            self.bom_properties: dict[str, str] = {}
            self.sbom_json: dict | None = None

        except Exception as e:
            raise ValueError(f"Error in initializing SCASBOMAgent: {e}")
    
    
    
    def populate_opensource_context(self)->None:
        """
        Multi-engine SBOM path: Syft + cdxgen inventory → merge → Grype vulns.
        Map-reduce runs only over Grype matches; inventory rows are projected separately.
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
            preferred_sbom = cdxgen_path or syft_path
            base_sbom = load_cdx_json(preferred_sbom)
            if merged_comps:
                self.sbom_json = assemble_cyclonedx(
                    merged_comps,
                    base=base_sbom,
                    tools=tools,
                    subject_name=os.path.basename(str(self.directory).rstrip("/")),
                )
            else:
                self.sbom_json = base_sbom

            bom_props: dict[str, str] = {
                "sbom:author": "DevSecShield",
                "sbom:vuln_scanner": "grype",
            }
            if tools:
                bom_props["sbom:inventory_tools"] = ",".join(tools)
            if self.sbom_json is not None:
                bom_props["sbom:automation_cyclonedx"] = "true"
                bom_props["sbom:multi_format_emit"] = "true"
            self.bom_properties = bom_props

            # --- Grype vuln lane (prefer inventory SBOM) ---
            def _grype_tool(directory):
                return run_sbom_scan(directory=directory, sbom_file=preferred_sbom)

            open_source_context = OpenSourceContext(
                open_source_tool=_grype_tool,
                directory=self.directory,
            )
            open_source_context.run_open_source_tool()
            results = open_source_context.results
            self.grype_document = results if isinstance(results, dict) else None

            # Inventory rows: Grype ran → mark assessed even when match count is 0.
            self.inventory_rows = inventory_to_finding_rows(
                merged_comps, vuln_assessed=True
            )
            console.print(
                f"Inventory components: {len(self.inventory_rows)} "
                f"(tools={tools or ['none']})",
                style="bold yellow",
            )

            parsed_results = parse_sbom_results_to_strings(results)

            # Zero Grype matches → empty docs → base_context raises "Documents are not set".
            # Mirror AIBOM: skip map-reduce and return empty vuln findings.
            if not parsed_results:
                console.print(
                    "No SBOM/SCA matches found, skipping map-reduce",
                    style="bold yellow",
                )
                self.vulnerabilities = []
                return

            docs = []
            for i in range(0, len(parsed_results), 10):
                concatenated_strings = " ".join(parsed_results[i : i + 10])
                document = Document(page_content=concatenated_strings)
                docs.append(document)

            open_source_context.documents = docs
            summary = open_source_context.generate_map_reduce_summary(
                summary_manager=SBOMSCASummaryManager()
            )

            if hasattr(summary, "vulnerabilities"):
                vulnerabilities = summary.vulnerabilities
            else:
                console.print(
                    "SBOM map-reduce returned no structured vulnerabilities "
                    "(raw/empty result); treating as empty",
                    style="bold yellow",
                )
                vulnerabilities = []

            console.print(
                f"Vulnerabilities length : {len(vulnerabilities)}", style="bold yellow"
            )
            for index, vulnerability in enumerate(vulnerabilities):
                console.print(
                    f" 🔧 Vulnerability # {index + 1} : {vulnerability.title}",
                    style="bold yellow",
                )

            self.vulnerabilities = vulnerabilities

        except Exception as e:
            raise ValueError(f"Error in populating open source context: {e}")
    

    def analyze_sbom_file(self)->None: #TODO : Implement this
        """
        Analyzes the SBOM file and sets self.vulnerabilities
        """
        try:
            # STEP [ 1 ] ================================ Load SBOM file =====================================================================
            console.print(f"Analyzing SBOM file ...",style="bold yellow")
            if not self.sbom_json_file:
                raise ValueError(f"SBOM file not found")
            with open(self.sbom_json_file, "r",errors="ignore") as f:
                sbom_json = json.load(f)
            self.sbom_json = sbom_json if isinstance(sbom_json, dict) else None
            self.bom_properties = {
                "sbom:author": "DevSecShield",
                "sbom:vuln_scanner": "grype",
                "sbom:automation_cyclonedx": "true",
                "sbom:multi_format_emit": "true",
                "sbom:inventory_tools": "uploaded-sbom",
            }
            
            # STEP [ 2 ] ================================ Parse SBOM file  to documents =====================================================================
            splitter = RecursiveCharacterTextSplitter(chunk_size=10000)
            split_json_documents = splitter.create_documents(texts=[str(sbom_json)])
            if not split_json_documents:
                raise ValueError(f"No split json documents found")
            docs = split_json_documents # SET documents ⭐
            
            # STEP [ 3 ] ================================ Generate Map Reduce Summary =====================================================================
            mock_open_source_context = OpenSourceContext(
                open_source_tool=run_sbom_scan,
                argument="mock"
            )
            mock_open_source_context.documents = docs # SET documents ⭐    
            summary = mock_open_source_context.generate_map_reduce_summary(
                summary_manager=SBOMSCASummaryManagerForSBOMFile()
            )
            output : type[FinalDependencyVulnerabilities] = summary 



            vulnerabilities = output.vulnerabilities # GET vulnerabilities ⭐

            console.print(f"Vulnerabilities length : {len(vulnerabilities)}",style="bold yellow")
            for index , vulnerability in enumerate(vulnerabilities):
                console.print(f" 🔧 Vulnerability # {index + 1} : {vulnerability.title}",style="bold yellow")

            self.vulnerabilities = vulnerabilities # SET vulnerabilities ⭐            


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

            # STEP [ 6 ] ================================ Return Vulnerabilities model =================================================================
            return self.vulnerabilities


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
    
