from pydantic import BaseModel
from langchain_core.documents import Document
from langchain_community.vectorstores import VectorStore
from rich.console import Console
from helpers.context.base_utilities import BaseUtilities
from helpers.context.schema import BaseVulnerability
from helpers.context.output_model import OutputModelManager
import base64
import json
import time
from dotenv import load_dotenv
import os
from langchain_aws import ChatBedrock
from langchain_core.messages import HumanMessage , SystemMessage
from qdrant_client import models
from helpers.parsers.base_vuln import parse_vuln

console = Console()

class BaseAgent(OutputModelManager,BaseUtilities):

    tracing : bool = True 

    def __init__(self):
        console.print(f"BaseAgent initialized without overriding the __init__ method",style="dim yellow")
    
    def run_agent(self):
        raise NotImplementedError("Subclasses must implement this method")
    

    def to_dict_list(self,output:list[type[BaseVulnerability]]) -> list[dict]:
        """
        Parse the list of vulnerabilities output of the agent into a list of dictionaries
        """
        try:
            # console.print(f"output to parse : {output}",style="bold yellow")
            parsed_output = []
            for item in output:
                parsed_output.append(parse_vuln(item))
            # Keep a stable order so repeated scans with same findings produce deterministic payload ordering.
            parsed_output.sort(key=lambda row: json.dumps(row, sort_keys=True, ensure_ascii=True))
            return parsed_output
        except Exception as e:
            console.print(f"Error while parsing output: {e}",style="bold red")
            raise e

    def query_vector_store(
        self,
        vector_store: VectorStore,
        query: str,
        k: int = 20,
        metadata_filter: dict = None,
        score_threshold: float = 0.5,
    ) -> list[Document]:
        try:
            if not vector_store or not query or not k:
                raise Exception("Vector store, query or k are missing")

            
            
            context_id = metadata_filter.get("context_id")
            if not context_id:
                raise Exception("Context id is missing")
            else:
                console.print(f"🔍Creating filter for qdrant Context id: {context_id}",style="bold yellow")
                filter = models.Filter(
                    should=[
                        models.FieldCondition(
                            key="metadata.context_id",
                            match=models.MatchValue(value=context_id)
                        )
                    ]
                )
                console.print(f"🔍Filter created: {filter}",style="dim orange1")
            

            # this approach sometimes yields 0 hits , but the similarity search approach works fine for this use case
            # retriever = vector_store.as_retriever(search_kwargs={"k": k, "filter": filter , "score_threshold": score_threshold})
            # docs = retriever.invoke(query)
            # console.print(f"🔍 RAG Results length: {len(docs)}",style="bold yellow")


                
            docs = vector_store.similarity_search(
                query=query, 
                k=k, 
                filter=filter,
                search_params=models.SearchParams(exact=True),
                )
            # Sort results by source metadata for deterministic ordering across runs
            docs.sort(key=lambda d: d.metadata.get("source", ""))
            console.print(f"🔍 RAG Results length: {len(docs)}",style="bold yellow")
            
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
        llm_model: str = os.getenv("LLM_MODEL", "openai.gpt-oss-120b-1:0"),
        max_retries: int = 3,
    ) -> type[BaseModel] | str:
        try:
            load_dotenv()
            llm = self.get_llm(model=llm_model, temperature=0.0, output_model=output_model)

            console.print("Generating Structured response .... ", style="bold bright_yellow")

            if image:
                console.print("Image input Detected", style="bright_cyan")
                image_data = base64.b64encode(image).decode("ascii")
                user_prompt = (
                    f"{prompt}\n\n"
                    "Use the following base64 image payload as supporting evidence while answering:\n"
                    f"{image_data}"
                )
            else:
                console.print("Pure Text input Detected", style="bright_cyan")
                user_prompt = prompt

            messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
            last_error = None
            for attempt in range(1, max_retries + 1):
                try:
                    console.print(f"Using Bedrock Invoke API to generate response", style="dim cyan")
                    response = llm.invoke(messages)
                    return response
                except Exception as invoke_err:
                    last_error = invoke_err
                    err_str = str(invoke_err)
                    # Retry on transient Bedrock errors (Unknown role, throttling, 5xx)
                    is_transient = any(s in err_str for s in [
                        "Unknown role", "ThrottlingException", "ServiceUnavailableException",
                        "ModelTimeoutException", "InternalServerException", "Too many requests",
                    ])
                    if is_transient and attempt < max_retries:
                        wait_secs = 2 ** attempt
                        console.print(f"⚠️ Transient Bedrock error (attempt {attempt}/{max_retries}), retrying in {wait_secs}s: {err_str[:120]}", style="bold yellow")
                        time.sleep(wait_secs)
                    else:
                        raise
            raise last_error  # should not reach here
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
                model=os.getenv("LLM_MODEL", "openai.gpt-oss-120b-1:0"),
                region=AWS_REGION or "ap-south-1",
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                max_tokens=max_output_tokens,
                temperature=0,
                model_kwargs={"top_p": 1, "top_k": 1},
            )

            result = model.invoke([SystemMessage(content=system_prompt), HumanMessage(content=prompt)])
            response_string = result.content if hasattr(result, "content") else str(result)

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
            