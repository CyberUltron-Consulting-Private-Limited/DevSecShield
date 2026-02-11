from helpers.context import  BaseSummaryManager 
from helpers.context.schema import DependencyVulnerability
from helpers.context.output_model import OutputModelManager
from pydantic import BaseModel, Field
from rich.console import Console
from langchain.schema import Document
console = Console()

class FinalDependencyVulnerabilities(BaseModel):
    vulnerabilities: list[DependencyVulnerability] = Field(..., description="A list of Dependency Vulnerabilities")

RefinePrompt = """
## Your Task : \n
You are a SCA and SBOM expert , analyze the given Dependency Vulnerabilities list and refine it with the new content provided to make it more coherent and detailed .  
\n\n
---------------------------------------------------------------------------------------------------------
### The existing SCA and SBOM Dependency Vulnerabilities list that needs to be refined is  :\n
{summary} 
\n\n\n
----------------------------------------------------------------------------------------------------------- 
### Here is the new content that must be used to refine the existing SCA and SBOM Dependency Vulnerabilities list :\n
{text}
\n
----------------------------------------------------------------------------------------------------------
"""

MapPrompt = """
## Your Task : \n
**You are a SCA and SBOM expert , analyze these scan results and extract the Dependency Vulnerabilities from these scan results which can help a cybersecurity professional identify vulnerabilities later** . 
For example : A Dependency Vulnerability could be "Denial of service vulnerability found in XXXX package" , "Serialization injection vulnerability found in XXXX package" , ... or any other feature specific Dependency Vulnerability . 
Note : This was only an example to help you understand the task better , remember to only extract the Dependency Vulnerabilities mentioned in the scan results provided . 
Important : Extract only the dependency vulnerabilities that you think are noteworthy and important to be identified by a cybersecurity professional ( don't mention any false positives )
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## SCA and SBOM Scan Results  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------
"""

MapPromptForSBOMFile = """
## Your Task : \n
**You are a SCA and SBOM expert , analyze the SBOM file content and extract the Dependency Vulnerabilities from the SBOM file content which can help a cybersecurity professional identify vulnerabilities later** . 
For example : A Dependency Vulnerability could be "Denial of service vulnerability found in XXXX package" , "Serialization injection vulnerability found in XXXX package" , ... or any other feature specific Dependency Vulnerability . 
Note : This was only an example to help you understand the task better , remember to only extract the Dependency Vulnerabilities mentioned in the SBOM file content provided . 
Important : Extract only the dependency vulnerabilities that you think are noteworthy and important to be identified by a cybersecurity professional ( don't mention any false positives )
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## SBOM File content  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------
"""

CombinePrompt = """
## Your Task : \n
Analyze the Dependency Vulnerabilities provided below that have been extracted from the codebase and combine them into a single list of Dependency Vulnerabilities.
Important : Combine at most 3 Dependency Vulnerabilities into a single Dependency Vulnerability , making the description as detailed as possible for each Dependency Vulnerability , capturing all the logic/workflows corresponding to each Dependency Vulnerability .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## Dependency Vulnerabilities  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


class SBOMSCASummaryManager(BaseSummaryManager,OutputModelManager):
    def __init__(self):

        output_model = self.get_dependency_output_model()


        super().__init__(
            summary_output_model=output_model,
            refine_prompt_string = RefinePrompt,
            map_prompt_string = MapPrompt,
            combine_prompt_string = CombinePrompt,
            summary_starting_string="Dependency Vulnerabilities Identified in the codebase are as follows : \n\n",
        )
    
        
    def format_to_string(
        self, 
        input:type[FinalDependencyVulnerabilities] )->str:
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
                Dependencies: {vulnerability.dependencies} \n
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



class SBOMSCASummaryManagerForSBOMFile(BaseSummaryManager,OutputModelManager):
    def __init__(self):

        output_model = self.get_dependency_output_model()

        super().__init__(
            summary_output_model=output_model,
            refine_prompt_string = RefinePrompt,
            map_prompt_string = MapPromptForSBOMFile,
            combine_prompt_string = CombinePrompt,
            summary_starting_string="Dependency Vulnerabilities Identified in the codebase are as follows : \n\n",
        )
    
        
    def format_to_string(
        self, 
        input:type[FinalDependencyVulnerabilities] )->str:
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
                Dependencies: {vulnerability.dependencies} \n
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