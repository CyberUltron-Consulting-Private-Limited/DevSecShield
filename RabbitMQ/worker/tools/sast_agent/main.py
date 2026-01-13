import shutil
from context.codebase_context import CodebaseContext
from context.open_source_context import OpenSourceContext
from context.scan_context import GithubContext, GitlabContext, BitbucketContext, ZipContext, clone_repo_from_context, get_directory_from_zip_context
from context.base_agent import BaseAgent
from typing import Literal
from pydantic import BaseModel, Field
from rich.console import Console
from semgrep_util import run_sast_scan_on_directory
from tools.context.schema import CodebaseVulnerability, BaseVulnerability

class LogicalComponentsOutputModel(BaseModel):
    title: str = Field(..., description="The title of the logical component")
    description: str = Field(..., description="The description of the logical component")
    dependencies: list[str] = Field(..., description="A List of Dependencies of the logical component")
    business_logic: str = Field(..., description="A Detailed summary of the business logic of the logical component")

class LogicalComponents(BaseModel):
    logical_components : list[LogicalComponentsOutputModel] = Field(..., description="A List of Logical Components of the Codebase")

console = Console()

class SASTAgent(BaseAgent):
    def __init__(
        self,
        context: GithubContext | GitlabContext | BitbucketContext | None = None,
        zip_context: ZipContext | None = None,
        app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] = None,
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


            #initializing
            self.codebase_context_id = None
            self.opensource_context_id = None

            #important
            self.logical_components : list[LogicalComponentsOutputModel] = []
            self.vulnerabilities : list[CodebaseVulnerability] | list[BaseVulnerability] = []
            self.codebase_context_summary = None
            self.opensource_context_summary = None

        except Exception as e:
            raise ValueError(f"Error in initializing SASTAgent: {e}")
    
    
    def populate_codebase_context(self)->None:
        """
        Populates the codebase context
        """
        try:
            console.print(f"Populating codebase context ...",style="bold yellow")
            codebase_context = CodebaseContext(directory=self.directory , app_lang=self.app_lang)
            combine_prompt_string = "Combine these codebase summaries into a coherent summary:"
            map_prompt_string = "Create a detailed , descriptive and brief summary of this code:"
            codebase_context_object = codebase_context.prepare_context(
                combine_prompt_string=combine_prompt_string,
                map_prompt_string=map_prompt_string,
            )
            codebase_context_id = codebase_context_object.context_id

            self.codebase_context_id = codebase_context_id # SET codebase_context_id ⭐
            self.codebase_context_summary = codebase_context_object.summary # SET codebase_context_summary ⭐
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
            open_source_context_object = open_source_context.prepare_context(
                combine_prompt_string=combine_prompt_string,
                map_prompt_string=map_prompt_string,
            )
            open_source_context_id = open_source_context_object.context_id

            self.opensource_context_id = open_source_context_id # SET open_source_context_id ⭐
            console.print(f"Open source context id set successfully",style="bold bue1")
        except Exception as e:
            raise ValueError(f"Error in populating open source context: {e}")
    
    def remove_temp_directory(self)->None:
        """
        Removes the temporary directory
        """
        try:
            console.print(f"Removing temporary directory ...",style="bold yellow")
            shutil.rmtree(self.directory)
            console.print(f"Temporary directory removed successfully",style="bold green")
        except Exception as e:
            raise ValueError(f"Error in removing temporary directory: {e}")
    
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
                output_model=LogicalComponentsOutputModel,
            )
            logical_components : list[LogicalComponentsOutputModel] = response_model.logical_components # GET logical_components ⭐

            self.logical_components : list[LogicalComponentsOutputModel] = logical_components # SET logical_components ⭐
            console.print(f"Logical components extracted successfully and set successfully",style="bold green")


        except Exception as e:
            raise ValueError(f"Error in extracting logical components: {e}")

    
    def analyze_logical_component_and_append_vulnerabilities(
        self,
        logical_component: LogicalComponentsOutputModel,
        relevant_code_snippets: str,
        relevant_open_source_results: str,
        )->None:
        """
        Analyzes the logical component and finds the vulnerabilities to append to the existing list
        Args:
            logical_component: LogicalComponentsOutputModel
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
