from helpers.context.scan_context import clone_repo_from_context, validate_dict_with_context , ZipContext , get_directory_from_zip_context
from helpers.context import CodebaseContext , BaseSummaryManager , LogicalComponents
from pathlib import Path
import json
from rich.console import Console
from langchain.schema import Document
console = Console()


class SASTSummaryManager(BaseSummaryManager):
    def __init__(self):
        super().__init__(
            summary_output_model=LogicalComponents,
            refine_prompt_string = "Refine the given Logical Components list to make it more coherent and detailed:\n\nThe existing Logical Components list that needs to be refined is  :\n {summary} \n\n\nHere is the new content that must be used to refine the existing Logical Components list : {text}",
            map_prompt_string = "Summarize this code into Logical Components where potential Vulnerabilities usually exist:\n\n{text}",
            combine_prompt_string = "Create a coherent summary of the logical components of the codebase from the given Logical Components lists {text}",
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

if __name__ == "__main__":
    included_path_arrays = [[".tf"]]
    excluded_path_arrays = [ ["api_routes"],["normal_scan_utils"],["mcpscan_utils"],["llm_scan_utils"]]

    # testing repository integration with sast agent 
    # dict_context = {
    # "mode":"github",
    # "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot.git",
    # "PAT":"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",
    # }
    # context = validate_dict_with_context(dict_context)
    # directory = clone_repo_from_context(context)

    zip_context = ZipContext(
            bucket_name="devsecshield-storage",
            # object_name="RiskPilot-main (1).zip" # size : Total size: 0.0002691037952899933 GB ( 0.2755622863769531 MB ) ( 288948 bytes ) ( 36 files ) , cost : 0.08 $ ( ~ 7 INR )
            object_name="DevSecShield-main.zip" # size : Total size: 0.000959618017077446 GB ( 0.9826488494873047 MB ) ( 1030382 bytes ) ( 153 files ) , cost : 0.182 $ ( ~ 16.7 INR )
        )
    directory = get_directory_from_zip_context(zip_context)

    
    #testing codebase context
    # directory = Path("C:/Users/HP/Desktop/RiskPilot - Copy/backend")
    codebase_context = CodebaseContext(
        directory=directory, 
        include_files_extensions=[".tf"],
        # exclude_path_arrays=excluded_path_arrays,
        include_path_arrays=included_path_arrays,
    )


    result = codebase_context.prepare_context(load_documents_to_vector_store=False)
    
    console.print(f"Codebase context id: {result.context_id}",style="bold green")
    # console.print(f"Summary: {result.summary}",style="dim yellow")

    # with open("codebase_context_result.json", "w+") as f:
    #     json.dump({
    #         "metadata": codebase_context.metadata,
    #         "result":result.summary.model_dump()
    #         }, f, indent=4)

    # if codebase_context.delete_context():
    #     console.print("Context deleted successfully",style="dim green")
    # else:
    #     console.print("Failed to delete context",style="bold red")