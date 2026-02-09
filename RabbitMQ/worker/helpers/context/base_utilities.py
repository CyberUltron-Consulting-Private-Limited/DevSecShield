
import os
from dotenv import load_dotenv
from langchain_community.vectorstores import VectorStore
from rich.console import Console
from pydantic import BaseModel
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_aws import ChatBedrock
from qdrant_client import QdrantClient
from langchain_qdrant import QdrantVectorStore
from langsmith.wrappers import wrap_openai
console = Console()


class BaseUtilities:
    """
    ### Contains utilities like 
    - get_vector_store
    - get_llm
    - get_embedding_model
    """
    tracing : bool = True 
    llm_timeout: int = 60*10 # 10 minutes

    def __init__(self):
        raise NotImplementedError("Subclass must implement this method")
    

    def get_embedding_model(
        self,
        model: str = "text-embedding-3-small",
    ):
        """
        Responsible for getting OpenAI Embedding model, based on the specified model
        """
        try:
            load_dotenv()
            OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
            if not OPENAI_API_KEY:
                raise ValueError("OPENAI_API_KEY not found")
            else:
                pass
            openai_embedding = OpenAIEmbeddings(
                model=model,
                api_key=OPENAI_API_KEY,
            )
            console.print(f"OpenAI embedding model fetched successfully",style="dim green")
            return openai_embedding
        except Exception as e:
            raise ValueError(f"Error in getting embedding model: {e}")
    
    
    def get_aws_bedrock_llm(
        self,
    ):
        """
        Responsible for getting an unstructured LLM that uses AWS Bedrock
        """
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
            )
            console.print(f"Unstructured LLM fetched successfully",style="dim green")
            return model
        except Exception as e:
            raise ValueError(f"Error in getting unstructured LLM: {e}")
    
    
    def get_llm(
        self,
        model: str = "gpt-5-nano",
        temperature: float = 0.0,
        max_tokens: int | None = None,
        output_model: type[BaseModel] = None,
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
                    timeout=self.llm_timeout,
                ).with_structured_output(schema=output_model)
                console.print(f"Structured OpenAI LLM fetched successfully",style="dim green")
            else:
                llm = ChatOpenAI(
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    api_key=OPENAI_API_KEY,
                    timeout=self.llm_timeout,
                )
                console.print(f"Unstructured OpenAI LLM fetched successfully",style="dim green")
            
            return llm
        except Exception as e:
            raise ValueError(f"Error in getting LLM: {e}")
    
    
    
    def get_vector_store(self, collection_name: str)->VectorStore:
        """
        Responsible for getting the qdrant vector store for the specified collection
        """
        try:
            # getting qdrant client from url and api key 
            load_dotenv()
            is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
            if is_docker_container and is_docker_container == "True":
                qdrant_host = "13.203.233.15"
                qdrant_port = "7333"
                qdrant_url = f"http://{qdrant_host}:{qdrant_port}"
            else:
                qdrant_url = "http://localhost:7333"

            # getting api key from environment variable
            QDRANT_API_KEY = os.getenv("QDRANT_API_KEY")
            if not QDRANT_API_KEY:
                raise ValueError("QDRANT_API_KEY not found")
            else:
                console.print(f"QDRANT_API_KEY is set to {QDRANT_API_KEY[:10]}...",style="dim green")

            qdrant_client = QdrantClient(url=qdrant_url, api_key=QDRANT_API_KEY, check_compatibility=False)

            
            # getting vector store from collection name , embedding model and qdrant client
            vectorstore = QdrantVectorStore(
                collection_name=collection_name,
                embedding=self.get_embedding_model(),
                client=qdrant_client,
            )

            # returning the vector store
            return vectorstore
        except Exception as e:
            raise ValueError(f"Error in getting vector store: {e}")
    
    
    
    
    
