from langchain.agents import create_agent
from langchain.agents.structured_output import ProviderStrategy, ToolStrategy
from langchain_aws import ChatBedrock
from langchain.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, Field
from typing import Literal
from rich.console import Console
from fastapi import HTTPException, status
import instructor
from dotenv import load_dotenv
from openai import OpenAI
import base64

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



def generate_structured_response_bedrock(input_prompt: str, system_prompt: str, output_model: BaseModel) -> BaseModel:
    """
    ### Returns :
    - The structured response from the LLM as BaseModel
    ### Description :
    This function is used to generate a structured response from an LLM.
    It takes in an input prompt, a system prompt, and an output model.
    It returns the structured response from the LLM.
    ### Args :
    - input_prompt : The input prompt to send to the LLM
    - system_prompt : The system prompt to send to the LLM
    - output_model : The output model to use for the structured response
    """
    try :
        load_dotenv()
        client = instructor.from_provider("bedrock/anthropic.claude-3-haiku-20240307-v1:0")
        response = client.create(
            modelId="anthropic.claude-3-haiku-20240307-v1:0",
            messages=[
                {"role": "user", "content": input_prompt},
            ],
            response_model=output_model,
        )

        return response
    except Exception as e:
        console.print(f"Error in generate_structured_response: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in generating structured response , please try again later")


def generate_structured_response(input_prompt:str,
                      model:str="gpt-5-nano",
                      output_model=None,
                      system_prompt:str=None,
                      image:bytes | None = None)-> BaseModel:
    """
    ### Generates a structued response for text or text + image input. 
    The returned value will be the output_model type model for structured outputs.
    Args :
    - promt : str => is the prompt for generating the response
    - system_prompt : str => system instructions for response generation
    - output_model => the structured output model that will be returned
    - image : bytes => the image bytes
    """
    
    load_dotenv()
    client = OpenAI()
    print("📝 Generating Structured response")

    if image:
        print("📷 Image input ")
        image_data = base64.b64encode(image).decode("ascii") #output is 'str'
        response = client.responses.parse(
            model=model,
            text_format=output_model,
            instructions= system_prompt,
            input=[
                {
                    "role": "user",
                    "content": [
                        { "type": "input_text", "text": input_prompt },
                        {
                            "type": "input_image",
                            "image_url": f"data:image/jpeg;base64,{image_data}",
                        },
                    ],
                }
            ],
            )
    
    else:
        print("⭐ Pure Text input ")
        response = client.responses.parse(
            model=model,
            text_format=output_model,
            instructions=system_prompt,
            input=input_prompt
        )
        print(response)
    
    model_response = response.output_parsed
    return model_response

if __name__ == "__main__":
    class Test(BaseModel):
        name: str = Field(description="The name of the person")
        description: str = Field(description="The description of the person")
    result = generate_structured_response(input_prompt="Hello, how are you? im a test person", system_prompt="You are a helpful assistant.", output_model=Test)
    print(result)