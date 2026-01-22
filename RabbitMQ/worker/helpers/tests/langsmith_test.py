from openai import OpenAI
from langsmith.wrappers import wrap_openai
from langsmith import traceable
from rich.console import Console
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate


console = Console()
load_dotenv()



def test_llm():

    client_no_wrapper = OpenAI()

    client = wrap_openai(client_no_wrapper)

    prompt = "Hello , how are you?"

    response = client.chat.completions.create(
        model="gpt-5-nano",
        messages=[{"role": "user", "content": prompt}],
    )

    console.print(response.choices[0].message.content,style="bold green")


@traceable
def test_llm_chain():

    llm = ChatOpenAI(model="gpt-5-nano")

    combine_prompt_template = "You are a helpful assistant that can answer questions and help with tasks. Here is the text: {text}"
    combine_prompt = PromptTemplate(input_variables=["text"],template=combine_prompt_template)
    combine_chain = combine_prompt | llm
    response = combine_chain.invoke({"text": "Hello, how are you?"})
    console.print(response.content,style="bold green")



# this function doesnt log the llm calls in langsmith dashboard because it doesnt use langchain wrappers for the llm 
@traceable
def test_llm_with_openai_sdk():
    client = OpenAI()
    prompt = "Hello, how are you?"
    response = client.chat.completions.create(
        model="gpt-5-nano",
        messages=[{"role": "user", "content": prompt}],
    )
    console.print(response.choices[0].message.content,style="bold green")

# test_llm()
# test_llm_chain()
test_llm_with_openai_sdk()