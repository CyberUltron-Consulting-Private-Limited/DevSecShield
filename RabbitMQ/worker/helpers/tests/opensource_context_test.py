from pathlib import Path

from langchain.schema import Document
from helpers.context import OpenSourceContext , BaseSummaryManager
from helpers.context.scan_context import get_directory_from_zip_context , ZipContext
from helpers.tools.sast_agent.semgrep_util import run_sast_scan_on_directory
from pydantic import BaseModel
from rich.console import Console
console = Console()
import json

class Vulnerabilities(BaseModel):
    risk: str
    description: str
class OpenSourceSummary(BaseModel):
    vulnerabilities: list[Vulnerabilities]

class OpenSourceSummaryManager(BaseSummaryManager):
    def __init__(self):
        super().__init__(
            summary_output_model=OpenSourceSummary,
            refine_prompt_string="Refine the given OpenSourceSummary to make it more coherent and detailed:\n\nThe existing OpenSourceSummary that needs to be refined is  :\n {summary} \n\n\nHere is the new content that must be used to refine the existing OpenSourceSummary : {text}",
            map_prompt_string="Summarize this code into OpenSourceSummary where potential Vulnerabilities usually exist:\n\n{text}",
            combine_prompt_string="Create a coherent summary of the vulnerabilities of the codebase from the given OpenSourceSummary lists {text}",
            summary_starting_string="OpenSourceSummary of the vulnerabilities of the codebase are as follows : \n\n",
        )
    
    def format_to_string(
        self, 
        input:type[OpenSourceSummary] )->str:
        """
        Responsible for formatting the summary output model to a string
        Returns:
            str
        """
        try:

            output_model_string = ""
            for vulnerability in input.vulnerabilities:
                temp = f"""
                \n\n
                =======================================================================================
                Title: {vulnerability.risk} \n
                Description: {vulnerability.description} \n
                =======================================================================================
                \n\n
                """
                output_model_string += temp
            
            final_string = self.summary_starting_string + output_model_string

            # console.print(f"Formatted string length {len(final_string)} and content is {final_string[:300]}...",style="dim yellow")
            return final_string
        except Exception as e:
            raise ValueError(f"Error in formatting summary output model to string: {e}")
    

    def format_documents_to_string(
        self,
        documents:list[Document],
        )->str:
        """
        Responsible for formatting the documents into a string
        """
        try:
            documents_data = ""
            for document in documents:
                documents_data += f"""
                Document Content : {document.page_content}\n
                """
            return documents_data
        except Exception as e:
            raise ValueError(f"Error in formatting documents to string: {e}")

if __name__ == "__main__":
    # zip_context = ZipContext(
    #         bucket_name="devsecshield-storage",
    #         object_name="transformers-main.zip",
    #         # object_name="RiskPilot-main (1).zip",
    #     )

    # directory = get_directory_from_zip_context(zip_context)
    
    open_source_context = OpenSourceContext(
        open_source_tool=run_sast_scan_on_directory,
        # directory=directory,
        app_lang="python" ,
        ) 
    
    
    # to test really big results json file
    with open("C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\worker\\opensource_context_result.json", "r") as f:
        results = json.load(f)
    
    console.print(f"Results type: {type(results)}",style="dim yellow")

    open_source_context.results = results
    
    result = open_source_context.save_results_into_vector_store_and_return_context_id()
    # console.print(f"OpenSourceSummary: {result.summary}",style="dim yellow")
    # console.print(f"Opensource context_id : {result.context_id}")
    # with open("opensource_context_result.json", "w+") as f:
    #     data = open_source_context.results
    #     json.dump(data, f, indent=4)
