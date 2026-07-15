from helpers.context import  BaseSummaryManager 
from helpers.context.schema import IACVulnerability
from helpers.context.output_model import OutputModelManager
from pydantic import BaseModel, Field
from rich.console import Console
from langchain.schema import Document
console = Console()

class IACArchitecture(BaseModel):
    architecture_description: str = Field(..., description="A detailed description of the IAC Dependency architecture , that will be used to generate a IAC Dependecy diagram later on. ")

RefinePrompt = """
## Your Task : \n
Refine the given IAC Dependency Architecture description to make it more coherent and detailed . 
\n\n
---------------------------------------------------------------------------------------------------------
### The existing IAC Dependency Architecture description that needs to be refined is  :\n
{summary} 
\n\n\n
----------------------------------------------------------------------------------------------------------- 
### Here is the new content that must be used to refine the existing IAC Dependency Architecture description :\n
{text}
\n
----------------------------------------------------------------------------------------------------------
"""

MapPrompt = """
## Your Task : \n
You are an IAC Dependency Architecture expert , analyze the given IAC Code snippets and extract the IAC Dependency Architecture from these code snippets which can help us create a IAC Dependency diagram later on.
Make sure each resource and its dependencies are captured in the description.
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## IAC Code Snippets :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------
"""

CombinePrompt = """
## Your Task : \n
Analyze the IAC Dependency Architecture provided below that have been extracted from the codebase and combine them into a single description of the IAC Dependency Architecture.
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## IAC Vulnerabilities  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


class IACDiagramSummaryManager(BaseSummaryManager,OutputModelManager):
    def __init__(self):
        
        super().__init__(
            summary_output_model=IACArchitecture,
            refine_prompt_string = RefinePrompt,
            map_prompt_string = MapPrompt,
            combine_prompt_string = CombinePrompt,
            summary_starting_string="IAC Dependency Architecture Identified in the codebase are as follows : \n\n",
        )

    
        
    def format_to_string(
        self, 
        input:type[IACArchitecture] )->str:
        """
        Responsible for formatting the summary output model to a string
        Returns:
            str
        """
        try:
            return input.architecture_description
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