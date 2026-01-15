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
from schema import LogicalComponents,IndividualLogicalComponent


console = Console()

@dataclass
class BaseContext:
    context_id: str = None
    summary: str | type[BaseModel] = None
    error_message: str = None

def remove_reasoning_from_response(response: str)->str:
    """
    Responsible for removing the reasoning from the response
    """
    try:
        end = response.find("</reasoning>")
        if end == -1:
            return response
        content_without_reasoning = response[end+len("</reasoning>"):]
        return content_without_reasoning
    except Exception as e:
        console.print(f"Error in removing reasoning from response: {e}",style="dim red")
        return response

def format_logical_components_for_summary(logical_components: list[IndividualLogicalComponent] , summary_starting_string: str)->str:
    """
    Responsible for formatting the logical components for the summary
    """
    try:
        summary = summary_starting_string
        for item in logical_components:
            temp = f"""
            \n\n\n
            ----------------------------------------------------------------------------------------------
            Logical Component : {item.title} \n
            Description : {item.description} \n
            Dependencies : {item.dependencies} \n
            Business Logic : {item.business_logic} \n
            ----------------------------------------------------------------------------------------------
            \n\n\n
            """
            summary += temp
        return summary
    except Exception as e:
        raise ValueError(f"Error in formatting logical components for summary: {e}")

class BaseContextManager:

    def __init__(self):
        self.doc_ids = []
        self.context_id = None
    
    def prepare_context(self)->BaseContext:
        raise NotImplementedError("Subclasses must implement this method")
    
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
    
    
    def get_unstructured_llm(
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
    
    def add_documents_to_vector_store(
        self, 
        documents: list[Document] = None, 
        vector_store: VectorStore = None, 
        ):
        try:
            if not documents or not vector_store:
                raise Exception("Documents or vector store are missing")
            
            console.print(f"Adding documents to vector store ...",style="dim bright_cyan")
            added_ids = vector_store.add_documents(documents=documents)
            self.doc_ids.extend(added_ids) # adding the added ids to the doc_ids attr , to use later for deleting the documents
            console.print(f"Documents added to vector store , access doc ids using the doc_ids attribute of the class",style="bold bright_cyan")
            return True

        except Exception as e:
            console.print(f"Error while adding documents to vector store: {e}",style="bold red")
            return False
    
    def add_context_id_to_documents(self, documents: list[Document] , context_id: str):
        """
        Responsible for adding the context id to the documents
        """
        try:
            for document in documents:
                document.metadata["context_id"] = context_id
            return documents
        except Exception as e:
            raise ValueError(f"Error in adding context id to documents: {e}")
    
    def generate_map_reduce_summary(
        self,
        refine_prompt_string: str | None = None, 
        map_prompt_string: str | None = None,
        combine_prompt_string: str | None = None,
    )->list[IndividualLogicalComponent]:
        """
        Responsible for generating a map reduce summary of documents, based on the specified prompt
        """
        try:
            if self.documents:

                console.print(f"Generating map reduce summary of codebase",style="bold bright_cyan")

                if not refine_prompt_string or not map_prompt_string:
                    console.print(f"Combine prompt string or map prompt string is not set. Therfore using fallback prompts",style="dim yellow")
                    refine_prompt_string = "Refine the given summary to make it more coherent and detailed:\n\nThe existing summary that needs to be refined is  :\n {summary} \n\n\nHere is the new content that must be used to refine the existing summary : {text}"
                    map_prompt_string = "Summarize this content:\n\n{text}"
                    combine_prompt_string = "Create a coherent summary of the logical components of the codebase from the given summaries {text}"
                
                
                console.print(f"Setting up map and combine prompts",style="dim bright_cyan")

                
                
                map_prompt_template = map_prompt_string 
                map_prompt = PromptTemplate(
                    input_variables=["text"],
                    template=map_prompt_template
                )
                map_chain = map_prompt | self.get_llm()

                refine_prompt_template = refine_prompt_string 
                refine_prompt = PromptTemplate(
                    input_variables=["text","summary"],
                    template=refine_prompt_template
                )
                refine_chain = refine_prompt | self.get_llm(output_model=LogicalComponents)

                combine_prompt_template = combine_prompt_string
                combine_prompt = PromptTemplate(
                    input_variables=["text"],
                    template=combine_prompt_template
                )
                combine_chain = combine_prompt | self.get_llm(output_model=LogicalComponents)

  
                
                # ----------------------------------------> Mapping ( each document is mapped to a summary )
                map_results = []
                console.print(f"Mapping length of documents {len(self.documents)}",style="dim bright_cyan")
                for document in self.documents:
                    map_chain_response = map_chain.invoke({"text": f"Document Name : {document.metadata['source']}\n\nDocument Content : {document.page_content}"})
                    content_without_reasoning = remove_reasoning_from_response(map_chain_response.content)
                    console.print(f"Map result For Document {document.metadata['source']}: content length {len(content_without_reasoning)}",style="dim bright_cyan")
                    map_results.append(content_without_reasoning)

                # ---------------------> Reducing ( the summaries are reduced to a single summary 10 at a time )  
                console.print(f"Creating initial summary using combine chain",style="dim yellow")
                combine_chain_response : type[LogicalComponents] = combine_chain.invoke({"text": "\n\n".join(map_results[:10])})
                

                summary_to_be_refined = format_logical_components_for_summary(
                    combine_chain_response.logical_components, 
                    summary_starting_string="Logical Components Identified in the codebase are as follows : \n\n")

                if len(map_results) > 10:
                    console.print(f"Refining summaries using refine chain",style="dim yellow")

                    for i in range(10, len(map_results), 10):
                        
                        summaries_concatenated = "\n\n".join(map_results[i:i+10])

                        refine_response : type[LogicalComponents] = refine_chain.invoke({"text": summaries_concatenated, "summary": summary_to_be_refined})
                        
                        summary_to_be_refined = format_logical_components_for_summary(
                            refine_response.logical_components, 
                            summary_starting_string= "Logical Components Identified in the codebase are as follows : \n\n")

                        console.print(f"Refine result content length {len(summary_to_be_refined)}",style="dim bright_cyan")

                    return refine_response
                
                else:
                    return combine_chain_response
            else:
                raise ValueError(f"No split documents found")
            
        except Exception as e:
            
            raise ValueError(f"Error in generating map reduce summary of codebase: {e}")
    

    def delete_context(self):
        """
        Responsible for closing the context
        """
        try:
            if self.context_id:
                vector_store = self.get_vector_store(collection_name=self.collection_name)
                success = vector_store.delete(ids=self.doc_ids)
                if success:
                    console.print(f"Context closed successfully",style="bold bright_cyan")
                    return True
                else:
                    console.print(f"Failed to delete documents from vector store",style="bold red")
                    return False
            else:
                console.print(f"Context id is not set",style="bold red")
                return False
        except Exception as e:
            console.print(f"Error in closing context: {e}",style="bold red")
            return False

if __name__ == "__main__":
    # testing llm chain with openai llm ( structured and unstructured )
    base_context = BaseContextManager()
    llm = base_context.get_llm()
    prompt = "Here are some details about the codebase , tell me if it is a web application or a mobile application: {codebase_details}"
    prompt_template = PromptTemplate(
        input_variables=["codebase_details"],
        template=prompt
    )
    chain = prompt_template | llm
    print(chain.invoke({"codebase_details": "The codebase is a web application built with Flask and MongoDB."}).content)
    print(chain.invoke({"codebase_details": "The codebase is a mobile application built with React Native and MongoDB."}).content)