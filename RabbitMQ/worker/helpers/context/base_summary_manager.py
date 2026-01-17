from pydantic import BaseModel

class BaseSummaryManager:
    def __init__(
        self,
        summary_output_model:type[BaseModel],
        refine_prompt_string:str | None = None,
        map_prompt_string:str | None = None,
        combine_prompt_string:str | None = None,
        summary_starting_string:str | None = None,
    ):
        self.summary_output_model = summary_output_model
        self.refine_prompt_string = refine_prompt_string
        self.map_prompt_string = map_prompt_string
        self.combine_prompt_string = combine_prompt_string
        self.summary_starting_string = summary_starting_string

    
    def format_to_string(
        self,
        input:type[BaseModel] | str,
        )->str:
        """
        Responsible for combining multiple summary output models into a string ( if there is an output model ) 
        If there is no output model , then this function will return the summary as is . 
        Args:
            summary_output_models: list[type[BaseModel]]
        Returns:
            str
        """
        raise NotImplementedError("Subclasses must implement this method")
