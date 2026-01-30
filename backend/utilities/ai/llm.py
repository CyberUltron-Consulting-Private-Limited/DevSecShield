from langchain.agents import create_agent
from langchain.agents.structured_output import ProviderStrategy, ToolStrategy
from langchain_aws import ChatBedrock
from langchain_openai import ChatOpenAI
import os
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


def get_llm(
    model: str = "gpt-5-nano",
    temperature: float = 0.0,
    max_tokens: int | None = None,
    output_model: type[BaseModel] = None,
    timeout: int = 60*10, # 10 minutes
    ):
    """
    Responsible for getting OpenAI LLM, based on the specified model, temperature, max_tokens
    """
    try:
        load_dotenv()
        OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
        if not OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY not found")
        else:
            pass
        
        if output_model:
            llm = ChatOpenAI(
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                api_key=OPENAI_API_KEY,
                timeout=timeout,
            ).with_structured_output(schema=output_model)
            console.print(f"Structured OpenAI LLM fetched successfully",style="dim green")
        else:
            llm = ChatOpenAI(
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                api_key=OPENAI_API_KEY,
                timeout=timeout,
            )
            console.print(f"Unstructured OpenAI LLM fetched successfully",style="dim green")
        
        return llm
    except Exception as e:
        raise ValueError(f"Error in getting LLM: {e}")

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