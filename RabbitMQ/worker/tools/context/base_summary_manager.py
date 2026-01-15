from pydantic import BaseModel

class BaseSummaryManager:
    def __init__(self,summary_output_model:type[BaseModel]):
        self.summary_output_model = summary_output_model

    def get_summary_output_model(self)->type[BaseModel]:
        """
        Responsible for getting the summary output model
        Returns:
            type[BaseModel]
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def combine_summary_output_models_to_string(self,summary_output_models:list[type[BaseModel]])->str:
        """
        Responsible for combining multiple summary output models into a string . 
        Args:
            summary_output_models: list[type[BaseModel]]
        Returns:
            str
        """
        raise NotImplementedError("Subclasses must implement this method")
