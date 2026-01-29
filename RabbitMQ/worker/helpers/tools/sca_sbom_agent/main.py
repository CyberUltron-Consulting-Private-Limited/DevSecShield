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


console = Console()




class SCASBOMAgent(BaseAgent):
    def __init__(
        self,
        context: GithubContext | GitlabContext | BitbucketContext | None = None,
        zip_context: ZipContext | None = None,
        sbom_json_file_context: FileContext = None,
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

            #initializing
            self.vulnerabilities : list[type[DependencyVulnerability]] | None = None

        except Exception as e:
            raise ValueError(f"Error in initializing SCASBOMAgent: {e}")
    
    
    
    def populate_opensource_context(self)->None:
        """
        Populates the open source context and sets self.vulnerabilities
        """
        try:
            console.print(f"Populating open source context ...",style="bold yellow")
            if not self.directory :
                raise ValueError(f"Directory not found")
            
            open_source_context = OpenSourceContext(
                open_source_tool=run_sbom_scan,
                directory=self.directory,
            )

            open_source_context.run_open_source_tool()  # this step will set self.results ⭐

            results = open_source_context.results # GET results ⭐


            # process each finding one by one to get documents for each finding ( to be passed to map reduce summary )
            parsed_results = parse_sbom_results_to_strings(results)

            #combining 10 findings into a single string and append ad document to the docs list
            docs = []
            for i in range(0,len(parsed_results),10):
                concatenated_strings = " ".join(parsed_results[i:i+10])
                document = Document(page_content=concatenated_strings)
                docs.append(document)

            # set documents to the open source context
            open_source_context.documents = docs # SET documents ⭐

            # generate map reduce summary
            summary = open_source_context.generate_map_reduce_summary(
                summary_manager=SBOMSCASummaryManager()
            )

            output : type[FinalDependencyVulnerabilities] = summary 
            vulnerabilities = output.vulnerabilities # GET vulnerabilities ⭐
    
            console.print(f"Vulnerabilities length : {len(vulnerabilities)}",style="bold yellow")
            for index , vulnerability in enumerate(vulnerabilities):
                console.print(f" 🔧 Vulnerability # {index + 1} : {vulnerability.title}",style="bold yellow")



            self.vulnerabilities = vulnerabilities # SET vulnerabilities ⭐


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

            if self.directory:
                self.populate_opensource_context()
            elif self.sbom_json_file:
                self.analyze_sbom_file()
            else:
                raise ValueError(f"Invalid Input , either directory or sbom_json_file_context is required")

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
    
