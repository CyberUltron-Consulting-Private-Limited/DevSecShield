from helpers.context import CodebaseContext , BaseSummaryManager , LogicalComponents
from pathlib import Path
import json
from rich.console import Console
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



if __name__ == "__main__":
    #testing codebase context
    directory = Path("C:/Users/HP/Desktop/RiskPilot - Copy/backend")
    codebase_context = CodebaseContext(
        directory=directory, 
        include_files_extensions=[".py"],
        include_path_arrays=[["llm_scan_utils"]],
    )


    result = codebase_context.prepare_context(summary_manager=SASTSummaryManager())
    
    console.print(f"Codebase context id: {result.context_id}",style="bold green")
    console.print(f"Summary: {result.summary}",style="dim yellow")

    with open("sast_agent_context_result.json", "w+") as f:
        json.dump(result.summary.model_dump(), f, indent=4)

    if codebase_context.delete_context():
        console.print("Context deleted successfully",style="dim green")
    else:
        console.print("Failed to delete context",style="bold red")