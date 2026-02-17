from pathlib import Path

from langchain.schema import Document
from helpers.context import OpenSourceContext , BaseSummaryManager
from helpers.context.scan_context import get_directory_from_zip_context , ZipContext
from helpers.tools.llm_agent.llm_runner import run_garak_scan
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
    model_type="custom"
    model_name="gpt-4o"
    headers:dict = {
            "Authorization": "Bearer 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",
            "Content-Type": "application/json"
            }
    request_template={
        "model": "gpt-4o",
        "input": "$INPUT"
        }
    response_json_field="$.output[0].content[0].text"
    probes=["malwaregen.Evasion" , "malwaregen.TopLevel"]
    model_uri="https://api.openai.com/v1/responses"
    
    open_source_context = OpenSourceContext(
        open_source_tool=run_garak_scan,
        model_type=model_type,
        model_name=model_name,
        headers=headers,
        request_template=request_template,
        response_json_field=response_json_field,
        probes=",".join(probes),
        model_uri=model_uri,
        
        ) 
    
    open_source_context.run_open_source_tool()

    results = open_source_context.results

    with open("garak_results.json", "w+") as f:
        json.dump(results, f, indent=2)
