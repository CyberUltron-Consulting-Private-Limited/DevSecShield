from langchain.agents import create_agent
from langchain.agents.structured_output import ProviderStrategy, ToolStrategy
from langchain_aws import ChatBedrock
from langchain.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, Field
from typing import Literal
from rich.console import Console
from fastapi import HTTPException, status

console = Console()

def generate_llm_response ( 
    prompt : str,
    system_prompt : str | None = None ,
    output_model : BaseModel | None = None ,
     ):
    try :
        model = ChatBedrock(
            model="anthropic.claude-3-5-sonnet-20240620-v1:0",
            temperature=0,
            max_tokens=None,
            region_name='us-east-1',
            aws_access_key_id="AKIA5T2YUFAY5IVCRYEY",
            aws_secret_access_key="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")


        structured_llm = model.with_structured_output(output_model,include_raw=True)

        result = structured_llm.invoke([SystemMessage(content=system_prompt) , HumanMessage(content=prompt)])


        return result.get("parsed")

    except Exception as e:
        console.print(f"Error in generate_llm_response: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in generating LLM response , please try again later")

if __name__ == "__main__":
    class Test(BaseModel):
        name: str = Field(description="The name of the person")
        description: str = Field(description="The description of the person")
    result = generate_llm_response(prompt="Hello, how are you? im a test person", system_prompt="You are a helpful assistant.", output_model=Test)
    print(result)