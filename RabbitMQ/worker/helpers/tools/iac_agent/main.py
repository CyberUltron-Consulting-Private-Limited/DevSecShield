import os
import shutil
from langchain_core.documents import Document
from helpers.context.codebase_context import CodebaseContext
from helpers.context.open_source_context import OpenSourceContext
from helpers.context.scan_context import *
from helpers.context.base_agent import BaseAgent
from typing import Literal
from rich.console import Console
from helpers.tools.sast_agent.semgrep_util import run_sast_scan_on_directory
from helpers.context.schema import * 
from helpers.tools.iac_agent.summary_manager import IACSummaryManager , FinalIACVulnerabilities
from helpers.tools.iac_agent.context import IACTypeContext



console = Console()




class IACAgent(BaseAgent):
    def __init__(
        self,
        context: GithubContext | GitlabContext | BitbucketContext | None = None,
        zip_context: ZipContext | None = None,
        iac_contexts: list[IACTypeContext] = None,
        ):
        try:
            if context:
                directory = clone_repo_from_context(context)
            elif zip_context:
                directory = get_directory_from_zip_context(zip_context)
            
            if not directory:
                raise ValueError(f"Directory not found")
            if not iac_contexts or len(iac_contexts) == 0:
                raise ValueError(f"IAC contexts not found")


            self.iac_contexts = iac_contexts # SET iac_contexts ⭐
            self.directory = directory # SET directory ⭐


            self.iac_types : list[str] = []
            for iac_context in self.iac_contexts:
                self.iac_types.append(iac_context.mode)
            


            include_files_extensions : list[str] = []
            include_path_arrays : list[list[str]] = []
            
            for iac_context in self.iac_contexts:
                if iac_context.mode == "terraform":
                    include_files_extensions.extend([".tf" , ".tfvars" , ".tfstate" , ".tf.json"])
                    include_path_arrays.extend([[".tf"] , [".tfvars"] , [".tfstate"] , [".tf.json"]])
                elif iac_context.mode == "k8s":
                    include_files_extensions.extend([".yaml" , ".yml"])
                    include_path_arrays.extend(iac_context.include_path_arrays)
                elif iac_context.mode == "pulumi":
                    include_files_extensions.extend([".py",".ts",".go",".cs"])
                    include_path_arrays.extend(iac_context.include_path_arrays)
                elif iac_context.mode == "ansible":
                    include_files_extensions.extend([".yml",".yaml",".ini"])
                    include_path_arrays.extend(iac_context.include_path_arrays)
                elif iac_context.mode == "helm":
                    include_files_extensions.extend([".yaml" , ".yml"])
                    include_path_arrays.extend(iac_context.include_path_arrays)
                elif iac_context.mode == "aws_cloudformation":
                    include_files_extensions.extend([".yaml" , ".yml" , ".json"])
                    include_path_arrays.extend(iac_context.include_path_arrays)
                elif iac_context.mode == "aws_cdk":
                    include_files_extensions.extend([".py",".ts",".go",".cs",".java"])
                    include_path_arrays.extend(iac_context.include_path_arrays)
                else:
                    raise ValueError(f"Invalid IAC mode: {iac_context.mode}")
            
            

            # setting include_files_extensions and include_path_arrays
            self.include_files_extensions = include_files_extensions # SET include_files_extensions ⭐
            self.include_path_arrays = include_path_arrays # SET include_path_arrays ⭐


            #initializing
            self.vulnerabilities : list[type[CodebaseVulnerability]] | None = None

        except Exception as e:
            raise ValueError(f"Error in initializing IACAgent: {e}")
    
    
    def populate_codebase_context(self)->None:
        """
        Populates the codebase context
        """
        try:
            console.print(f"Populating codebase context ...",style="bold yellow")
            codebase_context = CodebaseContext(
                directory=self.directory , 
                include_files_extensions=self.include_files_extensions, 
                include_path_arrays=self.include_path_arrays,
            )
            output = codebase_context.prepare_context(
                load_documents_to_vector_store=False,
                summary_manager=IACSummaryManager(iac_types=self.iac_types)
            )


            summary : type[FinalIACVulnerabilities] = output.summary

            console.print(f"Vulnerabilities length : {len(summary.vulnerabilities)}",style="bold yellow")
            for index , vulnerability in enumerate(summary.vulnerabilities):
                console.print(f" 🔧 Vulnerability # {index + 1} : {vulnerability.title}",style="bold yellow")

            self.vulnerabilities = summary.vulnerabilities # SET vulnerabilities ⭐

        except Exception as e:
            raise ValueError(f"Error in populating codebase context: {e}")
    

    def clean_up(self)->None:
        """
        Removes the temporary directory
        """
        try:
            try:
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
            except Exception as e:
                console.print(f"Error while deleting temp directory : {str(e)}", style = "dim red")


        except Exception as e:
            raise ValueError(f"Error in cleaning up: {e}")

    

    def run_agent(self):
        """
        Runs the IAC agent
        Requires :
        - __init__ to have run 
        Returns:
        - list[type[CodebaseVulnerability]] : list of vulnerabilities
        """
        try:

            # STEP [  ] ============================ Populate codebase context ==========================================================
            self.populate_codebase_context()
            

            # STEP [ 5 ] ================================ Final checks and cleanup =====================================================================
            console.print("Performing cleanup .... 🧹",style = "dim bright_cyan")
            self.clean_up()

            # STEP [ 6 ] ================================ Return Vulnerabilities model =================================================================
            return self.vulnerabilities


        except Exception as e:
            console.print(f"Error occured in run_agent : {str(e)}",style="bold red")
            self.clean_up()
            return None
    

    def estimate_credits_required(self)->int:
        """
        Estimates the credits required for the iac scan
        """
        try:
            total_credits = 0
            credits_from_codebase_context = 0

            # calculate credits from codebase context
            console.print(f"Populating codebase context for estimation ...",style="bold yellow")
            codebase_context = CodebaseContext(
                directory=self.directory , 
                include_files_extensions=self.include_files_extensions, 
                include_path_arrays=self.include_path_arrays,
            )
            _ , codebase_size_in_mb , _ = codebase_context.estimate_size_of_documents()
            credits_from_codebase_context_summary = codebase_size_in_mb / 0.5 # 1 credit ~ 0.5 MB 

            # calculate total credits
            total_credits = credits_from_codebase_context_summary
            return total_credits
            
        except Exception as e:
            raise e
        
        finally:
            console.print("Performing cleanup .... 🧹",style = "dim bright_cyan")
            self.clean_up()
    
