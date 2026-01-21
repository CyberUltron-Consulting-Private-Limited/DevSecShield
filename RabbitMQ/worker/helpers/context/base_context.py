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
from helpers.context.base_utilities import BaseUtilities
from helpers.context.schema import LogicalComponents,IndividualLogicalComponent
from helpers.context.base_summary_manager import BaseSummaryManager
import json

console = Console()

@dataclass
class BaseResult:
    context_id: str = None
    summary: str | type[BaseModel] = None
    error_message: str = None


class BaseContextManager(BaseUtilities):

    def __init__(self):
        self.doc_ids = []
        self.context_id = None
    
    def prepare_context(self)->BaseResult:
        raise NotImplementedError("Subclasses must implement this method")
    
    
    def add_documents_to_vector_store(
        self, 
        documents: list[Document] = None, 
        vector_store: VectorStore = None, 
        ):
        """
        Responsible for adding documents to the vector store
        Attributes Set :
        - self.doc_ids : list[str] ( the ids of the documents added to the vector store )
        """
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
        summary_manager: BaseSummaryManager,
    )->type[BaseModel] | str:
        """
        Responsible for generating a map reduce summary of documents, based on the specified prompt
        Requires : self.documents to be set
        """
        try:

            # STEP [ 1 ] ----------------> Extract required utils from summary manager class and validation --------------------------
            
            refine_prompt_string = summary_manager.refine_prompt_string
            map_prompt_string = summary_manager.map_prompt_string
            combine_prompt_string = summary_manager.combine_prompt_string
            summary_output_model : type[BaseModel] = summary_manager.summary_output_model
            summary_starting_string = summary_manager.summary_starting_string



            

            # STEP [ 2 ] ----------------> Validation and fallback prompts--------------------------------- --------------------------
            
            if not self.documents:
                raise ValueError("Documents are not set")
            if not refine_prompt_string or not map_prompt_string or not combine_prompt_string:
                console.print(f"Combine prompt string or map prompt string is not set. Therfore using fallback prompts",style="dim yellow")
                refine_prompt_string = "Refine the given summary to make it more coherent and detailed:\n\nThe existing summary that needs to be refined is  :\n {summary} \n\n\nHere is the new content that must be used to refine the existing summary : {text}"
                map_prompt_string = "Summarize this content:\n\n{text}"
                combine_prompt_string = "Create a coherent summary of the logical components of the codebase from the given summaries {text}"
            if not summary_starting_string:
                console.print(f"Summary starting string is not set. Therefore using fallback starting string",style="dim yellow")
                summary_starting_string = "Logical Components Identified in the codebase are as follows : \n\n"




            # STEP [ 3 ] ----------------> Setting up map , combine and refine chains--------------------------------- --------------------------
            
            map_prompt_template = map_prompt_string 
            map_prompt = PromptTemplate( input_variables=["text"], template=map_prompt_template )
            map_chain = map_prompt | self.get_llm( output_model=summary_output_model )

            refine_prompt_template = refine_prompt_string 
            refine_prompt = PromptTemplate(input_variables=["text","summary"],template=refine_prompt_template)
            refine_chain = refine_prompt | self.get_llm(output_model=summary_output_model)

            combine_prompt_template = combine_prompt_string
            combine_prompt = PromptTemplate(input_variables=["text"],template=combine_prompt_template)
            combine_chain = combine_prompt | self.get_llm(output_model=summary_output_model)






            # STEP [ 4 ] ----------------> Mapping ( each document is mapped to a summary )--------------------------------- --------------------------
            
            map_results = []
            console.print(f"Mapping length of documents {len(self.documents)}",style="dim yellow")
            for i in range(0, len(self.documents), 10): # summarizing 10 documents at a time
                documents_batch = self.documents[i:i+10]
                documents_data = summary_manager.format_documents_to_string( documents=documents_batch )

                # for testing 
                # documents_for_ingestion = { "documents_data": documents_data }
                # with open(f"logging_stuff_ingestion_{i}.json", "w+") as f:
                #     json.dump(documents_for_ingestion, f, indent=4)

                console.print(f"Documents data length before summarizing {len(documents_data)}",style="dim bright_cyan")
                map_chain_response = map_chain.invoke({"text": documents_data})
                documents_summary = summary_manager.format_to_string( input=map_chain_response )

                console.print(f"Map Summary for Documents {i} to {i+10} .  Content length of map summary: {len(documents_summary)}",style="dim bright_cyan")

                # for testing 
                # logging_stuff = { "documents_summary": documents_summary }
                # with open(f"logging_stuff_map_{i}.json", "w+") as f:
                #     json.dump(logging_stuff, f, indent=4)

                map_results.append(documents_summary)       





            # STEP [ 5 ] ----------------> Reducing ( the summaries are reduced to a single summary 10 at a time )-------------------------------------------------------------
            
            
            # =========================== if the map results has only 1 item , then skip summarization and return that one map result =========================================
            if len(map_results)==1 : 
                console.print("Skipping Combine and Refine steps as there is only 1 Map summary result .", style="dim yellow")
                return map_chain_response
            
            
            # =================================== Creating initial summary that will be refined ===================================
            console.print(f"Map results length : {len(map_results)}",style="dim yellow")
            console.print(f"Initial Summary : Combining first batch (upto 10 ) map results",style="dim yellow")
            combine_chain_response = combine_chain.invoke({"text": "\n\n".join(map_results[:10])})
            summary_to_be_refined = summary_manager.format_to_string( input=combine_chain_response )

            
            # ========================================= Refining the initial summary by 10 summaries at a time ===================================
            if len(map_results) > 10:
                for i in range(10, len(map_results), 10):
                    summaries_concatenated = "\n\n".join(map_results[i:i+10])

                    # for testing 
                    # logging_stuff = { "summaries_concatenated": summaries_concatenated, "summary_to_be_refined": summary_to_be_refined }
                    # with open(f"logging_stuff_refine_{i}.json", "w+") as f:
                    #     json.dump(logging_stuff, f, indent=4)
                    

                    refine_chain_response = refine_chain.invoke({"text": summaries_concatenated, "summary": summary_to_be_refined})
                    summary_to_be_refined = summary_manager.format_to_string( input=refine_chain_response ) 
                    console.print(f"Refine result for batch {i} to {i+10} .  Content length of refine result: {len(summary_to_be_refined)}",style="dim bright_cyan")
                
                return refine_chain_response
            else:
                # for testing 
                # logging_stuff = { "summary_to_be_refined": summary_to_be_refined }
                # with open("logging_stuff_final.json", "w+") as f:
                #     json.dump(logging_stuff, f, indent=4)

                return combine_chain_response
            
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
                    self.doc_ids=[]
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