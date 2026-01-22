from helpers.context import  BaseSummaryManager , LogicalComponents
from rich.console import Console
from langchain.schema import Document
console = Console()

RefinePrompt = """
## Your Task : \n
Refine the given Logical Components list to make it more coherent and detailed . Refine the Logical Components list to at Most 10 Logical Components . Do not exceed the limit of 10 Logical Components .
\n\n
---------------------------------------------------------------------------------------------------------
### The existing Logical Components list that needs to be refined is  :\n
{summary} 
\n\n\n
----------------------------------------------------------------------------------------------------------- 
### Here is the new content that must be used to refine the existing Logical Components list :\n
{text}
\n
----------------------------------------------------------------------------------------------------------
"""

MapPrompt = """
## Your Task : \n
**Analyze this code and extract the Logical Components from this code which can help a cybersecurity professional identify vulnerabilities later** . 
For example : A logical component could be "Authentication Workflow/System , CRUD Database workflow , Role based access system , ... or any other feature specific logical component . 
Note : This was only an example to help you understand the task better , remember to only extract the logical components mentioned in the code snippet provided . 
Important : Extract at most 2 logical components from these snippets but meake the description as detailed as possible for each logical component , capturing all the logic/workflows corresponding to each logical component .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## Code Snippets :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------
"""

CombinePrompt = """
## Your Task : \n
Analyze the logical components provided below that have been extracted from the codebase and combine them into a single list of logical components 
that would help a cybersecurity professional identify vulnerabilities in the code later . 
Important : Combine at most 3 logical components into a single logical component , making the description as detailed as possible for each logical component , capturing all the logic/workflows corresponding to each logical component .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## Logical Components  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


class SASTSummaryManager(BaseSummaryManager):
    def __init__(self):
        super().__init__(
            summary_output_model=LogicalComponents,
            refine_prompt_string = RefinePrompt,
            map_prompt_string = MapPrompt,
            combine_prompt_string = CombinePrompt,
            summary_starting_string="Logical Components Identified in the codebase are as follows : \n\n",
        )
    
        
    def format_to_string(
        self, 
        input:type[LogicalComponents] )->str:
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