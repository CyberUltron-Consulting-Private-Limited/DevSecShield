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
from langchain.text_splitter import CharacterTextSplitter
from helpers.tools.sca_sbom_agent.parser import parse_sbom_results_to_strings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from helpers.tools.llm_agent.context import LLMBenchmarkingContext
from helpers.tools.llm_agent.llm_runner import run_garak_scan
from helpers.tools.llm_agent.summary_manager import LLMBenchmarkingSummaryManager
from helpers.tools.llm_agent.summary_manager import FinalLLMBenchmarkingVulnerabilities


console = Console()




class LLMBenchmarkingAgent(BaseAgent):
    def __init__(
        self,
        llm_benchmarking_context: LLMBenchmarkingContext
        ):
        try:
            self.llm_benchmarking_context = llm_benchmarking_context

            #initializing
            self.vulnerabilities : list[type[LLMBenchmarkingVulnerability]] | None = None

        except Exception as e:
            raise ValueError(f"Error in initializing LLMBenchmarkingAgent: {e}")
    
    
    
    def populate_opensource_context(self)->None:
        """
        Populates the open source context and sets self.vulnerabilities
        """
        try:
            console.print(f"Populating open source context ...",style="bold yellow")
            if not self.directory :
                raise ValueError(f"Directory not found")
            
            open_source_context = OpenSourceContext(
                open_source_tool=run_garak_scan,
                model_type = self.llm_benchmarking_context.model_type,
                model_name = self.llm_benchmarking_context.model_name,
                probes = self.llm_benchmarking_context.probes,
                api_key = self.llm_benchmarking_context.api_key,
                headers = self.llm_benchmarking_context.headers,
                request_template = self.llm_benchmarking_context.request_template,
                response_json_field = self.llm_benchmarking_context.response_json_field,
                generations = self.llm_benchmarking_context.generations,
                method = self.llm_benchmarking_context.method,
                model_uri = self.llm_benchmarking_context.model_uri,
            )

            summary = open_source_context.prepare_context(
                load_results_into_vector_store=False,
                summary_manager=LLMBenchmarkingSummaryManager()
            )

            output : type[FinalLLMBenchmarkingVulnerabilities] = summary 
            vulnerabilities = output.vulnerabilities # GET vulnerabilities ⭐
    
            console.print(f"Vulnerabilities length : {len(vulnerabilities)}",style="bold yellow")
            for index , vulnerability in enumerate(vulnerabilities):
                console.print(f" 🔧 Vulnerability # {index + 1} : {vulnerability.title}",style="bold yellow")



            self.vulnerabilities = vulnerabilities # SET vulnerabilities ⭐


        except Exception as e:
            raise ValueError(f"Error in populating open source context: {e}")
    


    

    def run_agent(self):
        """
        Runs the agent and returns the vulnerabilities
        """
        try:

            self.populate_opensource_context()

            # STEP [ 5 ] ================================ Final checks and cleanup =====================================================================

            console.print("Performing cleanup .... 🧹",style = "dim bright_cyan")
            self.clean_up()

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
    
