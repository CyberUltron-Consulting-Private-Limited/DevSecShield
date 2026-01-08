from dataclasses import dataclass
import os
from dotenv import load_dotenv
from langchain_community.vectorstores import VectorStore
from pymongo import MongoClient
from rich.console import Console
from langchain.prompts import PromptTemplate
from langchain.chains.summarize import load_summarize_chain
from pydantic import BaseModel

console = Console()

@dataclass
class BaseContext:
    vector_store: VectorStore = None
    summary: str = None

    error_message: str = None

class BaseContextManager:

    def __init__(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    def prepare_context(self)->BaseContext:
        raise NotImplementedError("Subclasses must implement this method")
    
    def __get_embedding_model(self):
        """
        Responsible for getting the embedding model
        """
        try:
            # TODO : Finish this function
            pass
        except Exception as e:
            raise ValueError(f"Error in getting embedding model: {e}")
    
    def __get_llm(self,output_model: BaseModel = None):
        """
        Responsible for getting the LLM
        """
        try:
            # TODO : Finish this function
            pass
        except Exception as e:
            raise ValueError(f"Error in getting LLM: {e}")
    
    def __get_mongo_client_db(self, dev_environment: bool = False):
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
            return mongo_db
            
        except Exception as e:
            raise ValueError(f"Error in getting mongo client: {e}")
    
    def generate_map_reduce_summary(
        self, 
        combine_prompt_string: str = "Combine these summaries into a coherent summary:", 
        map_prompt_string: str = "Summarize this content:",
    
    ):
        """
        Responsible for generating a map reduce summary of documents, based on the specified prompt
        """
        try:
            if self.split_documents:

                console.print(f"Generating map reduce summary of codebase",style="bold blue1")


                console.print(f"Setting up map and combine prompts",style="dim blue1")
                
                map_prompt_template = map_prompt_string + "\n{text}"
                map_prompt = PromptTemplate(
                    input_variables=["text"],
                    template=map_prompt_template
                )

                combine_prompt_template = combine_prompt_string + "\n{text}"
                combine_prompt = PromptTemplate(
                    input_variables=["text"],
                    template=combine_prompt_template
                )

                # Create and run the chain
                console.print(f"Creating and running the chain",style="dim blue1")
                chain = load_summarize_chain(
                    self.__get_llm(),
                    chain_type="map_reduce",
                    map_prompt=map_prompt,
                    combine_prompt=combine_prompt,
                    verbose=True
                )

                summary = chain.run(self.split_documents)
                console.print(f"Map reduce summary generated successfully",style="bold blue1")
                return summary
            else:
                raise ValueError(f"No split documents found")
            
        except Exception as e:
            raise ValueError(f"Error in generating map reduce summary of codebase: {e}")
