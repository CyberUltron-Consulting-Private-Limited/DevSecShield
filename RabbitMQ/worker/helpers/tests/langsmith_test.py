"""Manual smoke checks against a live LLM provider (network + credentials). Not part of the automated suite:
they skip unless RUN_LIVE_LLM_TESTS=1, and nothing runs at import."""
import pytest

from langsmith import traceable
from rich.console import Console
from dotenv import load_dotenv
import os
from langchain_aws import ChatBedrock
from langchain.prompts import PromptTemplate


console = Console()
load_dotenv()
pytestmark = pytest.mark.skipif(os.getenv("RUN_LIVE_LLM_TESTS") != "1", reason="live LLM call; set RUN_LIVE_LLM_TESTS=1")



def test_llm():
    llm = ChatBedrock(
        model="openai.gpt-oss-120b-1:0",
        region=os.getenv("AWS_DEFAULT_REGION", "ap-south-1"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        temperature=0,
        model_kwargs={"top_p": 1},
    )
    response = llm.invoke("Hello , how are you?")
    console.print(response.content, style="bold green")


@traceable
def test_llm_chain():
    llm = ChatBedrock(
        model="openai.gpt-oss-120b-1:0",
        region=os.getenv("AWS_DEFAULT_REGION", "ap-south-1"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        temperature=0,
        model_kwargs={"top_p": 1},
    )

    combine_prompt_template = "You are a helpful assistant that can answer questions and help with tasks. Here is the text: {text}"
    combine_prompt = PromptTemplate(input_variables=["text"],template=combine_prompt_template)
    combine_chain = combine_prompt | llm
    response = combine_chain.invoke({"text": "Hello, how are you?"})
    console.print(response.content,style="bold green")



# this function doesnt log the llm calls in langsmith dashboard because it doesnt use langchain wrappers for the llm 
@traceable
def test_llm_with_openai_sdk():
    llm = ChatBedrock(
        model="openai.gpt-oss-120b-1:0",
        region=os.getenv("AWS_DEFAULT_REGION", "ap-south-1"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        temperature=0,
        model_kwargs={"top_p": 1},
    )
    response = llm.invoke("Hello, how are you?")
    console.print(response.content, style="bold green")

# test_llm()
# test_llm_chain()
if __name__ == "__main__":
    test_llm_with_openai_sdk()
