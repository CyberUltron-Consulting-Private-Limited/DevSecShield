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
from helpers.context.progress_writer import StateUpdateWriter


console = Console()




class LLMBenchmarkingAgent(BaseAgent):
    def __init__(
        self,
        llm_benchmarking_context: LLMBenchmarkingContext,
        state_update_writer: StateUpdateWriter | None = None,   
        ):
        try:
            self.llm_benchmarking_context : LLMBenchmarkingContext = llm_benchmarking_context
            self.state_update_writer : StateUpdateWriter | None = state_update_writer

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
            
            
            open_source_context = OpenSourceContext(
                open_source_tool=run_garak_scan,
                model_type = self.llm_benchmarking_context.model_type,
                model_name = self.llm_benchmarking_context.model_name,
                probes = ",".join(self.llm_benchmarking_context.probes),
                api_key = self.llm_benchmarking_context.api_key,
                headers = self.llm_benchmarking_context.headers,
                request_template = self.llm_benchmarking_context.request_template,
                response_json_field = self.llm_benchmarking_context.response_json_field,
                generations = self.llm_benchmarking_context.generations,
                method = self.llm_benchmarking_context.method,
                model_uri = self.llm_benchmarking_context.model_uri,
            )

            opensource_results = open_source_context.prepare_context(
                load_results_into_vector_store=False,
                summary_manager=LLMBenchmarkingSummaryManager()
            )

            output : type[FinalLLMBenchmarkingVulnerabilities] = opensource_results.summary 
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
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(30)
            self.populate_opensource_context()
        

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(100)

            
            parsed_output = self.to_dict_list(self.vulnerabilities)
            return parsed_output


        except Exception as e:
            console.print(f"Error occured in run_agent : {str(e)}",style="bold red")
            raise Exception(f"Error occured while running agent : {str(e)}")
    

    def estimate_credits_required(self)->int:
        """
        Estimates the credits required for the sbom sca scan

        each probe costs 0.002 Credits 
        return number_of_probes * 0.002
        """
        try:
            number_of_probes = len(self.llm_benchmarking_context.probes)

            return number_of_probes * 0.002
            
        except Exception as e:
            raise e
        
    
