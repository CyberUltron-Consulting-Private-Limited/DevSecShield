from pydantic import BaseModel
from langchain_core.documents import Document
from langchain_community.vectorstores import VectorStore
from rich.console import Console
from schema import BaseVulnerability
from output_model import OutputModelManager
from openai import OpenAI
import base64
from dotenv import load_dotenv
import os
from langchain_aws import ChatBedrock
from langchain_core.messages import HumanMessage , SystemMessage

console = Console()

class BaseAgent(OutputModelManager):

    def __init__(self):
        console.print(f"BaseAgent initialized without overriding the __init__ method",style="dim yellow")
    
    def run_agent(self):
        raise NotImplementedError("Subclasses must implement this method")

    def query_vector_store(
        self,
        vector_store: VectorStore,
        query: str,
        k: int = 20,
        metadata_filter: dict = None,
        score_threshold: float = 0.7,
    ) -> list[Document]:
        try:
            if not vector_store or not query or not k:
                raise Exception("Vector store, query or k are missing")
            
            # retriever = vector_store.as_retriever(search_kwargs={"k": k, "filter": metadata_filter , "score_threshold": score_threshold})
            # retriever_docs = retriever.invoke(query)
            
            docs = vector_store.similarity_search(
                query=query, 
                k=k, 
                filter=metadata_filter)
            
            return docs
        except Exception as e:
            console.print(f"Error while querying vector store: {e}",style="bold red")
            raise e
    

    def generate_structured_response(
        self, 
        prompt: str,
        system_prompt: str,
        output_model: type[BaseModel],
        image: bytes = None,
        llm_model: str = "gpt-5-nano",
    ) -> type[BaseModel] | str:
        try:
            output_model = self.get_output_model(output_model)
            
            load_dotenv()
            client = OpenAI()
            console.print("Generating Structured response .... ",style="bold bright_yellow")

            if image:
                console.print("Image input Detected",style="bright_cyan")
                image_data = base64.b64encode(image).decode("ascii") #output is 'str'
                response = client.responses.parse(
                    model=llm_model,
                    text_format=output_model,
                    instructions= system_prompt,
                    input=[
                        {
                            "role": "user",
                            "content": [
                                { "type": "input_text", "text": prompt },
                                {
                                    "type": "input_image",
                                    "image_url": f"data:image/jpeg;base64,{image_data}",
                                },
                            ],
                        }
                    ],
                    )
            
            else:
                console.print("Pure Text input Detected",style="bright_cyan")
                response = client.responses.parse(
                    model=llm_model,
                    text_format=output_model,
                    instructions=system_prompt,
                    input=prompt
                )
            
            model_response = response.output_parsed
            return model_response
        except Exception as e:
            console.print(f"Error: {e}",style="bold red")
            raise e
    
    def generate_unstructured_response(
        self,
        prompt: str,
        system_prompt: str,
        max_output_tokens: int = 10000,
    ) -> str:
        try:
            load_dotenv()
            AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
            AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
            AWS_REGION = os.getenv("AWS_DEFAULT_REGION")
            if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY or not AWS_REGION:
                raise Exception("AWS credentials not found")
            else:
                pass

            model = ChatBedrock(
                model="openai.gpt-oss-20b-1:0",
                region=AWS_REGION or "ap-south-1",
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                max_tokens=max_output_tokens,
            )

            result = model.invoke({"messages":[SystemMessage(system_prompt), HumanMessage(prompt)]})
            response = result["messages"][-1]
            response_string = response.content

            start = response_string.find("<reasoning>")
            end = response_string.find("</reasoning>")
            reasoning = response_string[start:end+len("</reasoning>")].replace("<reasoning>", "").replace("</reasoning>", "")
            content_without_reasoning = response_string[:start] + response_string[end+len("</reasoning>"):]
            return content_without_reasoning
        except Exception as e:
            console.print(f"Error: {e}",style="bold red")
            raise e
    



if __name__ == "__main__":
    agent = BaseAgent()
    model = agent.get_output_model(BaseVulnerability)
            