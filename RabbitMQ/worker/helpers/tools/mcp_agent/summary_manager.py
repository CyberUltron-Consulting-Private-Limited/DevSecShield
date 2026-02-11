from helpers.context import  BaseSummaryManager , LogicalComponents
from rich.console import Console
from langchain.schema import Document
from helpers.context.schema import MCPVulnerability
from pydantic import BaseModel, Field
console = Console()

class FinalMCPVulnerabilities(BaseModel):
    vulnerabilities: list[MCPVulnerability] = Field(..., description="A list of MCP Vulnerabilities , where each vulnerability is related to a particular tool, you can leave the array empty if no vulnerabilities are found")


RefinePrompt = """
## Your Task : \n
Refine the given MCP Vulnerabilities list to make it more coherent and detailed . Refine the MCP Vulnerabilities list at Most 10 MCP Vulnerabilities . Do not exceed the limit of 10 MCP Vulnerabilities .
\n\n
---------------------------------------------------------------------------------------------------------
### The existing MCP Vulnerabilities list that needs to be refined is  :\n
{summary} 
\n\n\n
----------------------------------------------------------------------------------------------------------- 
### Here is the new content that must be used to refine the existing MCP Vulnerabilities list :\n
{text}
\n
----------------------------------------------------------------------------------------------------------
"""

MapPrompt = """
## Your Task : \n
**Analyze this MCP Scan report and extract the MCP Vulnerabilities from this report which can help a cybersecurity professional identify vulnerabilities later** . . 
Note : This was only an example to help you understand the task better , remember to only extract the MCP Vulnerabilities mentioned in the MCP Scan report provided . 
Important : Extract at most 2 MCP Vulnerabilities from this report but meake the description as detailed as possible for each MCP Vulnerability , capturing all the logic/workflows corresponding to each MCP Vulnerability .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## MCP Scan report  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------
"""




CombinePrompt = """
## Your Task : \n
Analyze the MCP Vulnerabilities provided below that have been extracted from the MCP Scan report and combine them into a single list of MCP Vulnerabilities 
that would help a cybersecurity professional identify vulnerabilities in the code later . 
Important : Combine at most 3 MCP Vulnerabilities into a single MCP Vulnerability , making the description as detailed as possible for each MCP Vulnerability , capturing all the logic/workflows corresponding to each MCP Vulnerability .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## MCP Vulnerabilities  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


class MCPSummaryManager(BaseSummaryManager):
    def __init__(self):
        super().__init__(
            summary_output_model=FinalMCPVulnerabilities,
            refine_prompt_string = RefinePrompt,
            map_prompt_string = MapPrompt,
            combine_prompt_string = CombinePrompt,
            summary_starting_string="MCP Vulnerabilities Identified in the MCP Scan report are as follows : \n\n",
        )
    
        
    def format_to_string(
        self, 
        input:type[FinalMCPVulnerabilities] )->str:
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
                Tool Name: {vulnerability.tool_name} \n
                Tool Description: {vulnerability.tool_description} \n
                Impact: {vulnerability.impact} \n
                OWASP Top 10: {vulnerability.owasp_top_10} \n
                Compliance Controls: {vulnerability.compliance_controls} \n
                OWASP Top 10 LLM: {vulnerability.owasp_top_10_llm} \n
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
                ----------------------------------------------------------------------------------------------------------
                Document Content : {document.page_content}\n
                ----------------------------------------------------------------------------------------------------------
                \n\n\n\n 
                """

            return documents_data
        except Exception as e:
            raise ValueError(f"Error in formatting documents to string: {e}")