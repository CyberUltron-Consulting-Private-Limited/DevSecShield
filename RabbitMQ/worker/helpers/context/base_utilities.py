from dataclasses import dataclass
import os
from botocore.utils import tempfile
from dotenv import load_dotenv
from langchain_community.vectorstores import VectorStore
from langchain_core.documents import Document
from pymongo import MongoClient
from rich.console import Console
from langchain.prompts import PromptTemplate
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_aws import ChatBedrock
from langchain_mongodb import MongoDBAtlasVectorSearch
from helpers.context.schema import LogicalComponents,IndividualLogicalComponent
from helpers.context.base_summary_manager import BaseSummaryManager
import json
from langchain_chroma import Chroma
console = Console()


class BaseUtilities:
    """
    ### Contains utilities like 
    - get_mongo_client_db
    - get_vector_store
    - get_llm_
    - get_embedding_model
    """
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
                ).with_structured_output(schema=output_model)
                console.print(f"Structured OpenAI LLM fetched successfully",style="dim green")
            else:
                llm = ChatOpenAI(
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    api_key=OPENAI_API_KEY,
                )
                console.print(f"Unstructured OpenAI LLM fetched successfully",style="dim green")
            return llm
        except Exception as e:
            raise ValueError(f"Error in getting LLM: {e}")
    
    def get_mongo_client_db(self, dev_environment: bool = True):
        """
        Responsible for getting the mongo client for Database ( collection not specified here yet )
        """
        try:
            load_dotenv()
            is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
            
            if is_docker_container and is_docker_container == "True":
                mongo_username = os.environ['MONGO_INITDB_ROOT_USERNAME']
                mongo_password = os.environ['MONGO_INITDB_ROOT_PASSWORD']
                mongo_host = "13.203.233.15"
                mongo_port = "27017"    
                mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"
            elif dev_environment:
                mongo_url = "mongodb://localhost:27017/"
            else:
                mongo_username = os.environ['MONGO_INITDB_ROOT_USERNAME']
                mongo_password = os.environ['MONGO_INITDB_ROOT_PASSWORD']
                mongo_host = "13.203.233.15"
                mongo_port = "27017"
                mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"
            
            mongo_client = MongoClient(mongo_url)
            mongo_db = mongo_client['devsecshield_backend_server_db']
            console.print(f"Mongo client fetched successfully",style="dim green")
            return mongo_db
            
        except Exception as e:
            raise ValueError(f"Error in getting mongo client: {e}")
    
    def get_vector_store(self, collection_name: str)->VectorStore:
        """
        Responsible for getting the vector store for the specified collection
        """
        try:
            mongo_db = self.get_mongo_client_db()
            collection = mongo_db[collection_name]
            embedding_model = self.get_embedding_model()
            vectorstore = MongoDBAtlasVectorSearch(collection=collection, embedding=embedding_model)
            console.print(f"Vector store fetched successfully",style="dim green")
            return vectorstore
        except Exception as e:
            raise ValueError(f"Error in getting vector store: {e}")
    
    
    
    def get_chroma_client(self, dev_environment: bool = True):
        """
        Responsible for getting the chroma client
        """
        try:
            load_dotenv()
            is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
            
            if is_docker_container and is_docker_container == "True":
                chroma_host = "13.203.233.15"
                chroma_port = "9090"
                chroma_url = f"http://{chroma_host}:{chroma_port}"
            elif dev_environment:
                chroma_url = "http://localhost:9090"
            else:
                chroma_host = "13.203.233.15"
                chroma_port = "9090"
                chroma_url = f"http://{chroma_host}:{chroma_port}"

            chroma_client = Chroma(host=chroma_host, port=chroma_port)
            console.print(f"Chroma client fetched successfully",style="dim green")
            return chroma_client

        except Exception as e:
            raise ValueError(f"Error in getting chroma client: {e}")
    
    def get_chroma_vector_store(self, collection_name: str)->VectorStore:
        """
        Responsible for getting the vector store for the specified collection
        """
        try:
            vector_store = Chroma(
                collection_name=collection_name,
                embedding_function=self.get_embedding_model(),
                host="localhost",
                port=9090,
                # headers={"X_CHROMA_TOKEN" : "new-token"}
            )
            console.print(f"Chroma Vector store object instantiated !",style="dim green")
            return vector_store
        except Exception as e:
            raise ValueError(f"Error in getting chroma vector store: {e}")
    
