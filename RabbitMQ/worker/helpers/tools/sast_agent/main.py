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
from helpers.tools.sast_agent.summary_manager import SASTSummaryManager



console = Console()




class SASTAgent(BaseAgent):
    def __init__(
        self,
        context: GithubContext | GitlabContext | BitbucketContext | None = None,
        zip_context: ZipContext | None = None,
        app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] = None,
        exclude_path_arrays: list[list[str]] = None,
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
            
            self.directory = directory # SET directory ⭐
            self.app_lang = app_lang # SET app_lang ⭐


            include_files_extensions = None
            match app_lang:
                case "python":
                    include_files_extensions = [".py"]
                    default_exclude_path_arrays = [["__pycache__"], [".venv"], ["venv"], ["env"], [".env"], ["dist"], ["build"], [".egg-info"] , ["node_modules"]]
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
            
            if not default_exclude_path_arrays or not include_files_extensions:
                raise ValueError(f"Default exclude path arrays or include files extensions not found, Invalid Language: {app_lang}")
            
            self.include_files_extensions = include_files_extensions 

            if exclude_path_arrays:
                self.exclude_path_arrays = default_exclude_path_arrays + exclude_path_arrays
            else:
                self.exclude_path_arrays = default_exclude_path_arrays


            #initializing
            self.codebase_context_id = None
            self.opensource_context_id = None
            self.codebase_doc_ids = None
            self.open_source_doc_ids = None
            self.codebase_collection_name = None
            self.open_source_collection_name = None
            self.codebase_context = None
            self.open_source_context = None
            self.logical_components : type[LogicalComponents] = []
            self.vulnerabilities : list[dict[str,list[type[CodebaseVulnerability]]]] = []

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
            output = codebase_context.prepare_context(
                summary_manager=SASTSummaryManager()
            )


            self.codebase_doc_ids = codebase_context.doc_ids # SET codebase_context ⭐
            self.codebase_context_id = output.context_id # SET codebase_context_id ⭐
            self.codebase_collection_name = codebase_context.collection_name # SET codebase_collection_name ⭐

            self.codebase_context = codebase_context # SET codebase_context ⭐

            summary : type[LogicalComponents] = output.summary
            console.print(f"Summary {summary}",style="dim yellow")
            self.logical_components = summary # SET logical_components ⭐

            console.print(f"Codebase context id set successfully",style="bold blue1")
            console.print(f"Logical Components length : {len(self.logical_components.logical_components)}",style="bold yellow")
            for index , logical_component in enumerate(self.logical_components.logical_components):
                console.print(f" 🔧 Logical Component # {index + 1} : {logical_component.title}",style="bold yellow")

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
            output = open_source_context.prepare_context()
            self.open_source_doc_ids = open_source_context.doc_ids # SET open_source_context ⭐
            self.opensource_context_id = output.context_id # SET open_source_context_id ⭐
            self.open_source_collection_name = open_source_context.collection_name # SET open_source_collection_name 
            
            self.open_source_context = open_source_context # SET open_source_context ⭐

            console.print(f"Open source context id set successfully",style="bold blue1")
        except Exception as e:
            raise ValueError(f"Error in populating open source context: {e}")
    
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
            

            ## Relavant Code Snippets: 
            {relevant_code_snippets}

            ## Relevant Results from an open source tool that looks for vulnerable patterns in the code:
            {relevant_open_source_results}
            """

            
            response_model = self.generate_structured_response(
                prompt=prompt,
                system_prompt=system_prompt,
                output_model=self.output_model,
            )
            vulnerabilities : list[type[CodebaseVulnerability]] = response_model.vulnerabilities 
            logical_comp_vulnerability = {"logical_component_title":logical_component.title, "vulnerabilities":vulnerabilities} # this is what the output will look like ⭐⭐⭐⭐
            self.vulnerabilities.append(logical_comp_vulnerability) # APPEND ⭐ logical_comp_vulnerability to the existing list


            console.print(f"Vulnerabilities length : {len(vulnerabilities)}",style="bold green")

        except Exception as e:
            raise ValueError(f"Error in analyzing input and finding vulnerabilities: {e}")
    

    def format_codebase_rag_result(self,documents : list[Document])->str:
        try:
            formatted_string = ""
            for document in documents:
                temp = f"""
                ===========================================================
                # Content : 
                {document.page_content} 
                \n\n
                ## Metadata 
                {document.metadata}
                ===========================================================
                \n\n
                """
                formatted_string +=temp
            
            return formatted_string
        except Exception as e:
            raise e 


    def format_opensource_rag_result(self, documents : list[Document])->str:
        try:
            formatted_string = ""
            for document in documents:
                temp = f"""
                ===========================================================
                # Content : 
                {document.page_content} 
                \n\n
                ## Metadata 
                {document.metadata}
                ===========================================================
                \n\n
                """
                formatted_string +=temp
            
            return formatted_string
        except Exception as e:
            raise e
    
    def format_logical_component_to_query(self,logical_component:type[IndividualLogicalComponent])->str:
        try:
            formatted_string = f"""
            Find the code snippets corresponding to the logical component given below : 
            \n\n
            Title: {logical_component.title} \n
            Description: {logical_component.description} \n
            Dependencies: {logical_component.dependencies} \n
            Business Logic: {logical_component.business_logic} \n
            """
            return formatted_string
        except Exception as e:
            raise e 
    

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
        try:
            # STEP [ 1 ] ============================ Populate open source context ==========================================================
            self.populate_opensource_context() 

            # STEP [ 2 ] ============================ Populate codebase context ==========================================================
            self.populate_codebase_context()

            # STEP [ 3 ] ============================ Set output model ==========================================================
            self.output_model = self.get_codebase_output_model()

            # STEP [ 4 ] ============================ Cycle through logical components ==========================================================
            if not self.logical_components or not isinstance(self.logical_components,LogicalComponents):
                raise Exception(f"Logical Components == None ? : {self.logical_components == None } and Logical component isinstance ? : {isinstance(self.logical_components,LogicalComponents)}")
            

            
            console.print("---"*10 , style = "bold orange1 ")
            for index, logical_component in enumerate(self.logical_components.logical_components[:10]):

                console.print(f"⏩ Analyzing Logical Component # {index + 1} : {logical_component.title} ... 🔃 " , style = "bold orange1 ")
                
                # running checks 
                if not self.open_source_collection_name or not self.codebase_collection_name:
                    raise Exception(f"Opensource collection name :{self.open_source_collection_name} , Codebase collection name : {self.codebase_collection_name}")
                
                # get codebase context documents for RAG 
                codebase_rag_documents = self.query_vector_store(
                    query=self.format_logical_component_to_query(logical_component = logical_component),
                    vector_store=self.get_vector_store(collection_name=self.codebase_collection_name),
                    k=10,
                    metadata_filter={"context_id":self.codebase_context_id}
                )
                codebase_rag_formatted_string = self.format_codebase_rag_result(documents = codebase_rag_documents)
                console.print(f"codebase rag context fetched ✔️ . Content length : {len(codebase_rag_formatted_string)}",style="bright_cyan")

                # get open source context documents for RAG 
                opensource_rag_documents = self.query_vector_store(
                    query=self.format_logical_component_to_query(logical_component = logical_component),
                    vector_store=self.get_vector_store(collection_name=self.open_source_collection_name),
                    k=10,
                    metadata_filter={"context_id":self.opensource_context_id}

                )
                opensource_rag_formatted_string = self.format_opensource_rag_result(documents = opensource_rag_documents)
                console.print(f"opensource rag context fetched ✔️ . Content length : {len(opensource_rag_formatted_string)}",style="bright_cyan")

                # extract vulnerabilties and append to self.vulnerabilities 
                self.analyze_logical_component_and_append_vulnerabilities(
                    logical_component=logical_component,
                    relevant_code_snippets=codebase_rag_formatted_string,
                    relevant_open_source_results=opensource_rag_formatted_string
                )

                console.print("---"*10 , style = "bold orange1 ")
            

            # STEP [ 5 ] ================================ Final checks and cleanup =====================================================================
            console.print("Performing cleanup .... 🧹",style = "dim bright_cyan")
            self.clean_up()

            # STEP [ 6 ] ================================ Return Vulnerabilities model =================================================================
            return self.vulnerabilities
        


        except Exception as e:
            console.print(f"Error occured in run_agent : {str(e)}",style="bold red")
            self.clean_up()
            raise Exception(f"Error occured while running agent : {str(e)}")
    

    def to_dict_list(self,output:list[type[CodebaseVulnerability]]) -> list[dict]:
        """
        Parse the output of the agent into a list of dictionaries ( customized for SAST Agent )
        """
        try:
            parsed_output = []
            for item in output:
                logical_component_title = item["logical_component_title"]
                vulnerabilities = item["vulnerabilities"]
                parsed_output.append({"logical_component_title":logical_component_title,"vulnerabilities":super().to_dict_list(vulnerabilities)})
            return parsed_output
        except Exception as e:
            raise e