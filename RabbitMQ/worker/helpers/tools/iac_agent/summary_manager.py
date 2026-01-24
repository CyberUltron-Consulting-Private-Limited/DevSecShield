from helpers.context import  BaseSummaryManager 
from helpers.context.schema import CodebaseVulnerability
from pydantic import BaseModel, Field
from rich.console import Console
from langchain.schema import Document
console = Console()

class FinalIACVulnerabilities(BaseModel):
    vulnerabilities: list[CodebaseVulnerability] = Field(..., description="A list of IAC Vulnerabilities")

RefinePrompt = """
## Your Task : \n
Refine the given IAC Vulnerabilities list to make it more coherent and detailed . 
\n\n
---------------------------------------------------------------------------------------------------------
### The existing IAC Vulnerabilities list that needs to be refined is  :\n
{summary} 
\n\n\n
----------------------------------------------------------------------------------------------------------- 
### Here is the new content that must be used to refine the existing IAC Vulnerabilities list :\n
{text}
\n
----------------------------------------------------------------------------------------------------------
"""

MapPrompt = """
## Your Task : \n
**You are an IAC Vulnerability expert , analyze this code and extract the IAC Vulnerabilities from this code which can help a cybersecurity professional identify vulnerabilities later** . 
For example : A IAC Vulnerability could be "Instance with unencrypted block device" , "Egress traffic not restricted" , "Ingress traffic not restricted" , ... or any other feature specific IAC Vulnerability . 
Note : This was only an example to help you understand the task better , remember to only extract the IAC Vulnerabilities mentioned in the code snippet provided . 
Important : Extract at most 2 IAC Vulnerabilities from these snippets but meake the description as detailed as possible for each IAC Vulnerability , capturing all the logic/workflows corresponding to each IAC Vulnerability .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## IAC Code Snippets :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------
"""

CombinePrompt = """
## Your Task : \n
Analyze the IAC Vulnerabilities provided below that have been extracted from the codebase and combine them into a single list of IAC Vulnerabilities.
Important : Combine at most 3 IAC Vulnerabilities into a single IAC Vulnerability , making the description as detailed as possible for each IAC Vulnerability , capturing all the logic/workflows corresponding to each IAC Vulnerability .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## IAC Vulnerabilities  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


class IACSummaryManager(BaseSummaryManager):
    def __init__(self):
        super().__init__(
            summary_output_model=FinalIACVulnerabilities,
            refine_prompt_string = RefinePrompt,
            map_prompt_string = MapPrompt,
            combine_prompt_string = CombinePrompt,
            summary_starting_string="IAC Vulnerabilities Identified in the codebase are as follows : \n\n",
        )
    
        
    def format_to_string(
        self, 
        input:type[FinalIACVulnerabilities] )->str:
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
                OWASP Top 10: {vulnerability.owasp_top_10} \n
                Compliance Controls: {vulnerability.compliance_controls} \n
                Suggested Fix: {vulnerability.suggested_fix} \n
                Location: {vulnerability.location} \n
                Snippet: {vulnerability.snippet} \n
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
                Document Path : {document.metadata['source']}\n\nDocument Content : {document.page_content}\n
                =======================================================
                \n\n\n\n 
                """

            return documents_data
        except Exception as e:
            raise ValueError(f"Error in formatting documents to string: {e}")