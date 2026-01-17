import shutil
from context.codebase_context import CodebaseContext
from context.open_source_context import OpenSourceContext
from context.scan_context import *
from context.base_agent import BaseAgent
from typing import Literal
from rich.console import Console
from tools.sast_agent.semgrep_util import run_sast_scan_on_directory
from context.schema import *
from context.base_summary_manager import BaseSummaryManager


console = Console()

class SASTSummaryManager(BaseSummaryManager):
    def __init__(self):
        super().__init__(
            summary_output_model=LogicalComponents,
            refine_prompt_string="Refine the following summary:",
            map_prompt_string="Create a detailed, descriptive and brief summary of this code:",
            combine_prompt_string="Combine these codebase summaries into a coherent summary:",
            summary_starting_string="Logical Components Identified in the codebase are as follows : \n\n",
        )
    
        
    def format_to_string(self, input:type[LogicalComponents] )->str:
        """
        Responsible for formatting the summary output model to a string
        Returns:
            str
        """
        try:

            output_model_string = ""
            for logical_component in input.logical_components:
                temp = f"""
                \n\n
                =======================================================================================
                Title: {logical_component.title} \n
                Description: {logical_component.description} \n
                Dependencies: {logical_component.dependencies} \n
                Business Logic: {logical_component.business_logic} \n
                =======================================================================================
                \n\n
                """
                output_model_string += temp
            
            final_string = self.summary_starting_string + output_model_string
            return final_string
        except Exception as e:
            raise ValueError(f"Error in formatting summary output model to string: {e}")




class SASTAgent(BaseAgent):
    def __init__(
        self,
        context: GithubContext | GitlabContext | BitbucketContext | None = None,
        zip_context: ZipContext | None = None,
        app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] = None,
        exclude_path_arrays: list[list[str]] = None,
        technical_stack: list[str] = None,
        ):
        try:
            if context:
                directory = clone_repo_from_context(context)
            elif zip_context:
                directory = get_directory_from_zip_context(zip_context)
            
            if not directory:
                raise ValueError(f"Directory not found")
            if not app_lang:
                raise ValueError(f"App language not found")
            if not technical_stack:
                raise ValueError(f"Technical stack not found")
            
            self.directory = directory # SET directory ⭐
            self.app_lang = app_lang # SET app_lang ⭐
            self.technical_stack = technical_stack # SET technical_stack ⭐


            include_files_extensions = None
            match app_lang:
                case "python":
                    include_files_extensions = [".py"]
                    default_exclude_path_arrays = [["__pycache__"], [".venv"], ["venv"], ["env"], [".env"], ["dist"], ["build"], [".egg-info"]]
                case "javascript":
                    include_files_extensions = [".js"]
                    default_exclude_path_arrays = [["node_modules"], [".next"], ["dist"], ["build"], [".cache"], [".nuxt"], [".output"]]
                case "java":
                    include_files_extensions = [".java"]
                    default_exclude_path_arrays = [["target"], ["build"], [".gradle"], [".m2"], ["out"], [".idea"]]
                case "php":
                    include_files_extensions = [".php"]
                    default_exclude_path_arrays = [["vendor"], ["node_modules"], [".composer"]]
                case "c":
                    include_files_extensions = [".c"]
                    default_exclude_path_arrays = [["build"], ["bin"], ["obj"], ["cmake-build-"]]
                case "ruby":
                    include_files_extensions = [".rb"]
                    default_exclude_path_arrays = [["vendor"], ["tmp"], [".bundle"], ["node_modules"]]
                case "rust":
                    include_files_extensions = [".rs"]
                    default_exclude_path_arrays = [["target"], [".cargo"]]
                case "swift":
                    include_files_extensions = [".swift"]
                    default_exclude_path_arrays = [["build"], [".build"], ["DerivedData"], ["Pods"]]  
                case "csharp":
                    include_files_extensions = [".cs"]
                    default_exclude_path_arrays = [["bin"], ["obj"], ["packages"], [".vs"], ["node_modules"]]
                case "kotlin":
                    include_files_extensions = [".kt"]
                    default_exclude_path_arrays = [["build"], [".gradle"], [".idea"], ["out"], ["node_modules"]]
                case _:
                    raise ValueError(f"Unsupported application language: {app_lang}")
            
            if not default_exclude_path_arrays or include_files_extensions:
                raise ValueError(f"Default exclude path arrays or include files extensions not found, Invalid Language: {app_lang}")
            
            self.include_files_extensions = include_files_extensions if include_files_extensions else []
            self.exclude_path_arrays = default_exclude_path_arrays.extend(exclude_path_arrays) if exclude_path_arrays else default_exclude_path_arrays

            #initializing
            self.codebase_context_id = None
            self.opensource_context_id = None
            self.codebase_context = None
            self.open_source_context = None
            self.logical_components : list[IndividualLogicalComponent] = []
            self.vulnerabilities : list[CodebaseVulnerability] = []
            self.codebase_context_summary = None

        except Exception as e:
            raise ValueError(f"Error in initializing SASTAgent: {e}")
    
    
    def populate_codebase_context(self)->None:
        """
        Populates the codebase context
        """
        try:
            console.print(f"Populating codebase context ...",style="bold yellow")
            codebase_context = CodebaseContext(
                directory=self.directory , 
                include_files_extensions=self.include_files_extensions, 
                exclude_path_arrays=self.exclude_path_arrays,
            )
            combine_prompt_string = "Combine these codebase summaries into a coherent summary:"
            map_prompt_string = "Create a detailed , descriptive and brief summary of this code:"
            output = codebase_context.prepare_context(
                combine_prompt_string=combine_prompt_string,
                map_prompt_string=map_prompt_string,
            )

            self.codebase_context = codebase_context # SET codebase_context ⭐
            self.codebase_context_id = output.context_id # SET codebase_context_id ⭐
            self.codebase_context_summary = output.summary # SET codebase_context_summary ⭐
            console.print(f"Codebase context id set successfully",style="bold bue1")

        except Exception as e:
            raise ValueError(f"Error in populating codebase context: {e}")
    
    def populate_opensource_context(self)->None:
        """
        Populates the open source context
        """
        try:
            console.print(f"Populating open source context ...",style="bold yellow")
            open_source_context = OpenSourceContext(
                open_source_tool=run_sast_scan_on_directory,
                directory=self.directory,
                app_lang=self.app_lang,
            )
            combine_prompt_string = "Combine these summaries into a coherent summary:"
            map_prompt_string = "Summarize the content of the results of this tool run :"
            output = open_source_context.prepare_context(
                combine_prompt_string=combine_prompt_string,
                map_prompt_string=map_prompt_string,
            )
            self.open_source_context = open_source_context # SET open_source_context ⭐
            self.opensource_context_id = output.context_id # SET open_source_context_id ⭐

            console.print(f"Open source context id set successfully",style="bold bue1")
        except Exception as e:
            raise ValueError(f"Error in populating open source context: {e}")
    
    def clean_up(self)->None:
        """
        Removes the temporary directory
        """
        try:
            console.print(f"Removing temporary directory ...",style="bold yellow")
            shutil.rmtree(self.directory)
            console.print(f"Temporary directory removed successfully",style="bold green")


            # Deleting codebase context
            console.print(f"Deleting codebase context ...",style="bold yellow")
            if self.codebase_context_id:
                if self.codebase_context.delete_context():
                    console.print(f"Codebase context deleted successfully",style="bold green")
                else:
                    console.print(f"Failed to delete codebase context",style="bold red")
            else:
                console.print(f"Codebase context id not found",style="bold red")


            # Deleting open source context
            console.print(f"Deleting open source context ...",style="bold yellow")
            if self.opensource_context_id:
                if self.open_source_context.delete_context():
                    console.print(f"Open source context deleted successfully",style="bold green")
                else:
                    console.print(f"Failed to delete open source context",style="bold red")
            else:
                console.print(f"Open source context id not found",style="bold red")



        except Exception as e:
            raise ValueError(f"Error in cleaning up: {e}")
    
    def extract_logical_components(self)->None:
        """
        Extracts the logical components of the codebase
        """
        try:

            # Generating logical components from codebase context summary
            system_prompt = f"""
            You are a cybersecurity expert and you are given a summary of a codebase.
            You need to generate the logical components of the codebase.
            The logical components are the main components of the codebase that are used to build the codebase. """


            prompt = f"""
            # Here is the technical stack of the codebase :
            {self.technical_stack}


            # Here is a detailed summary of the codebase :
            {self.codebase_context_summary}

            ### Important Note :
            - Logical components should be extracted in a way that helps a cybersecurity expert understand the codebase and its components for further vulnerability identification.
            """
            response_model = self.generate_structured_response(
                prompt=prompt,
                system_prompt=system_prompt,
                output_model=LogicalComponents,
            )
            logical_components : list[IndividualLogicalComponent] = response_model.logical_components # GET logical_components ⭐

            self.logical_components : list[IndividualLogicalComponent] = logical_components # SET logical_components ⭐
            console.print(f"Logical components extracted successfully and set successfully",style="bold green")


        except Exception as e:
            raise ValueError(f"Error in extracting logical components: {e}")

    
    def analyze_logical_component_and_append_vulnerabilities(
        self,
        logical_component: IndividualLogicalComponent,
        relevant_code_snippets: str,
        relevant_open_source_results: str,
        )->None:
        """
        Analyzes the logical component and finds the vulnerabilities to append to the existing list
        Args:
            logical_component: IndividualLogicalComponent
        Returns:
            None
        """
        try:
            console.print(f"Analyzing Logical Component and finding vulnerabilities ...",style="bold yellow")
            

            system_prompt = f"""
            You are a cybersecurity expert and you are given a logical component of a codebase.
            You need to find the vulnerabilities in the logical component of the application.
            You will be provided relevant information about the logical component to evaluate and anaylze the vulnerabilities in the logical component.
            """
            
            
            prompt = f"""
            # Here is the logical component :
            Title: {logical_component.title}
            Description: {logical_component.description}
            Dependencies: {logical_component.dependencies}
            Business Logic: {logical_component.business_logic}
            

            ## Relavant Code Snippets : 
            {relevant_code_snippets}

            ## Relevant Results from an open source tool that looks for vulnerable patterns in the code:
            {relevant_open_source_results}
            """

            output_model = self.get_output_model(CodebaseVulnerability)
            
            response_model = self.generate_structured_response(
                prompt=prompt,
                system_prompt=system_prompt,
                output_model=output_model,
            )
            vulnerabilities : list[CodebaseVulnerability] = response_model.vulnerabilities 
            self.vulnerabilities.extend(vulnerabilities) # APPEND ⭐ vulnerabilities to the existing list


            console.print(f"Vulnerabilities found successfully and set successfully",style="bold green")

        except Exception as e:
            raise ValueError(f"Error in analyzing input and finding vulnerabilities: {e}")
    
    

    def run_agent(self):
        """
        Cycles through each Logical Component of the codebase performing the ...

        SAST Agent Logical Workflow for each Logical Component:
        
        1. Vector search of open source context
                  +
        2. Vector search of codebase context
                  +
        3. Logical Component Prompt
                  |
                  V
        4. Structure vulnerabilities (append new vulnerabilities to the existing list)
                  |
                  V
        5. Repeat until all Logical Components are processed
                  |
                  V
        6. Return the list of vulnerabilities
        

        """
        pass
