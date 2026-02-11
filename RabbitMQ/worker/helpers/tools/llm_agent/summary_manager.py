from helpers.context import  BaseSummaryManager 
from helpers.context.schema import LLMBenchmarkingVulnerability
from helpers.context.output_model import OutputModelManager
from pydantic import BaseModel, Field
from rich.console import Console
from langchain.schema import Document
console = Console()

class FinalLLMBenchmarkingVulnerabilities(BaseModel):
    vulnerabilities: list[LLMBenchmarkingVulnerability] = Field(..., description="A list of LLM Benchmarking Vulnerabilities")

RefinePrompt = """
## Your Task : \n
You are an AI Benchmarking expert , analyze the given LLM Benchmarking Vulnerabilities list and refine it with the new content provided to make it more coherent and detailed .  
\n\n
---------------------------------------------------------------------------------------------------------
### The existing LLM Benchmarking Vulnerabilities list that needs to be refined is  :\n
{summary} 
\n\n\n
----------------------------------------------------------------------------------------------------------- 
### Here is the new content that must be used to refine the existing LLM Benchmarking Vulnerabilities list :\n
{text}
\n
----------------------------------------------------------------------------------------------------------
"""

MapPrompt = """
## Your Task : \n
**You are an AI Benchmarking expert , analyze these scan results and extract the LLM Benchmarking Vulnerabilities from these scan results which can help a cybersecurity professional identify vulnerabilities later** . 
For example : A LLM Benchmarking Vulnerability could be "Prompt Injection vulnerability found in XXXX model" , "Insecure Output Handling vulnerability found in XXXX model" , ... or any other feature specific LLM Benchmarking Vulnerability . 
Note : This was only an example to help you understand the task better , remember to only extract the LLM Benchmarking Vulnerabilities mentioned in the scan results provided . 
Important : Extract only the LLM Benchmarking Vulnerabilities that you think are noteworthy and important to be identified by a cybersecurity professional ( don't mention any false positives )
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## LLM Benchmarking Scan Results  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------
"""


CombinePrompt = """
## Your Task : \n
Analyze the LLM Benchmarking Vulnerabilities provided below that have been extracted from the codebase and combine them into a single list of LLM Benchmarking Vulnerabilities.
Important : Combine at most 3 LLM Benchmarking Vulnerabilities into a single LLM Benchmarking Vulnerability , making the description as detailed as possible for each LLM Benchmarking Vulnerability , capturing all the logic/workflows corresponding to each LLM Benchmarking Vulnerability .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## LLM Benchmarking Vulnerabilities  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


class LLMBenchmarkingSummaryManager(BaseSummaryManager,OutputModelManager):
    def __init__(self):

        output_model = self.get_llm_benchmarking_output_model()


        super().__init__(
            summary_output_model=output_model,
            refine_prompt_string = RefinePrompt,
            map_prompt_string = MapPrompt,
            combine_prompt_string = CombinePrompt,
            summary_starting_string="LLM Benchmarking Vulnerabilities Identified in the codebase are as follows : \n\n",
        )
    
        
    def format_to_string(
        self, 
        input:type[FinalLLMBenchmarkingVulnerabilities] )->str:
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
                Title: {vulnerability.title} \n
                Description: {vulnerability.description} \n
                Impact: {vulnerability.impact} \n
                OWASP Top 10: {vulnerability.owasp_top_10_llm} \n
                Suggested Fix: {vulnerability.suggested_fix} \n
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
                =======================================================
                Document Content : {document.page_content}\n
                =======================================================
                \n\n\n\n 
                """

            return documents_data
        except Exception as e:
            raise ValueError(f"Error in formatting documents to string: {e}")


