from helpers.context.output_model import OutputModelManager
from helpers.context.schema import CodebaseVulnerability
from pydantic import BaseModel
from enum import Enum
from rich.console import Console
console = Console()

class OutputModelTest(OutputModelManager):
    def __init__(self):
        console.print("OutputModelTest initialized",style="bold green")


if __name__ == "__main__":
    output_model_test = OutputModelTest()

    console.print(f"Getting Codebase Output Model the first time  ....",style="dim yellow")
    output_model = output_model_test.get_output_model(CodebaseVulnerability)
    for name,info in output_model.model_fields.items():
        console.print(f"Field name: {name}",style="bold green")
        console.print(f"Field info: {info}",style="bold green")
    console.print(f"Output model schema: {output_model.model_json_schema()}",style="bold green")



    console.print(f"Getting Codebase Output Model the second time  ....",style="dim yellow")
    output_model = output_model_test.get_output_model(CodebaseVulnerability)
    for name,info in output_model.model_fields.items():
        console.print(f"Field name: {name}",style="bold green")
        console.print(f"Field info: {info}",style="bold green")
    console.print(f"Output model schema: {output_model.model_json_schema()}",style="bold orange1")

    # class TestingEnum(Enum):
    #     TESTING = "testing"
    #     TESTING2 = "testing2"
    
    # class TestingModel(BaseModel):
    #     testing : TestingEnum
    #     string_field_name : str
    

    # for f_name, f_info in TestingModel.model_fields.items():
    #     f_dct = f_info.asdict()
    #     console.print(f"Field name: {f_name}",style="bold green")
    #     console.print(f"Field info: {f_info}",style="bold green")
    #     console.print(f"Field dictionary: {f_dct}",style="bold green")
