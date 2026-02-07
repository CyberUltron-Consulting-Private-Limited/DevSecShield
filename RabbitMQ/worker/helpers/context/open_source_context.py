from typing import Callable
from rich.console import Console
from langchain_community.vectorstores import MongoDBAtlasVectorSearch, VectorStore
from helpers.context.scan_context import validate_dict_with_context
from helpers.context.base_context import BaseResult, BaseContextManager
from langchain_text_splitters.character import RecursiveCharacterTextSplitter
from langchain_text_splitters.json import RecursiveJsonSplitter
import uuid
from datetime import datetime
from helpers.context.base_summary_manager import BaseSummaryManager
from dataclasses import dataclass
import json
console = Console()

@dataclass
class OpenSourceResult(BaseResult):
    results: str | dict | None = None

class OpenSourceContext(BaseContextManager):
    """
    This class is responsible for running the open source tool and loading the context into its vector store
    """
    
    def __init__(self,open_source_tool: Callable | None = None, **kwargs):
        """
        Args:
            open_source_tool: The open source tool function to run that returns a dict of results
            kwargs: The keyword arguments to pass to the open source tool function
        ### Example Usage :
        ```python
        from tools.context.open_source_context import OpenSourceContext
        from tools.sast_utils.sast_runner import run_sast_scan

        open_source_tool = run_sast_scan
        context = validate_dict_with_context(dict_context) # GithubContext | GitlabContext | BitbucketContext
        app_lang = "python"
        open_source_context = OpenSourceContext(open_source_tool=open_source_tool, context=context, app_lang=app_lang)

        open_source_context.prepare_context(combine_prompt_string="combine_prompt_string", map_prompt_string="map_prompt_string")

        vector_store = open_source_context.vector_store
        if open_source_context.error_message:
            print(open_source_context.error_message)
        else:
            print("Open source tool ran successfully")
        """
        try:
            super().__init__()
            if open_source_tool and isinstance(open_source_tool, Callable):
                self.open_source_tool = open_source_tool
            else:
                raise ValueError(f"Open source tool must be a callable")
            if kwargs:
                self.kwargs = kwargs
            else:
                raise ValueError(f"kwargs must be a dictionary")
            self.collection_name = "open_source_context"
            self.results:dict | None = None
        except Exception as e:
            raise ValueError(f"Error in initializing OpenSourceContext: {e}")

    def run_open_source_tool(self)->None:
        """
        Responsible for running the open source tool and returning the context
        """
        try:
            console.print(f"Running open source tool: {self.open_source_tool.__name__}",style="bold yellow")
            results = self.open_source_tool(**self.kwargs)
            if results:
                console.print(f"Results found !",style="bold green")
                self.results = results # SET results ⭐

                # for testing ⚠️⚠️
                # with open("results.json", "w") as f:
                #     json.dump(results, f, indent=2)


            else:
                console.print(f"No results found !",style="bold red")
                raise ValueError(f"No results found")
        except Exception as e:
            raise ValueError(f"Error in running open source tool: {e}")
    
    def split_and_set_result_documents(
        self,
        max_chunk_size: int = 10000
        )->bool:
        """
        Responsible for splitting the results into documents and setting the documents
        """
        try:
            splitter = RecursiveCharacterTextSplitter(chunk_size=max_chunk_size)
            if not self.results:
                raise ValueError(f"No results found")
            split_json_documents = splitter.create_documents(texts=[str(self.results)])
            if not split_json_documents:
                raise ValueError(f"No split json documents found")
            self.documents = split_json_documents # SET documents ⭐
            return True
        except Exception as e:
            return False
    
    def save_results_into_vector_store_and_return_context_id(
        self,
        max_chunk_size: int = 10000
        )->str:
        """
        Main function responsible for loading the results into a vector store and returning the context id
        """
        try:
            splitter = RecursiveCharacterTextSplitter(chunk_size=max_chunk_size)
            if not self.results:
                raise ValueError(f"No results found")
            split_json_documents = splitter.create_documents(texts=[str(self.results)])

            # for testing 
            for json_document in split_json_documents:
                console.print(f"JSON Document length: {len(json_document.page_content)}",style="dim yellow")


            if not split_json_documents:
                raise ValueError(f"No split json documents found")

            
            # adding context_id to the documents metadata for filtering
            generated_id = str(uuid.uuid4()) + datetime.now().strftime("%Y%m%d%H%M%S")
            console.print(f"Adding {len(split_json_documents)} opensource context documents to vector store with context id : {generated_id}",style="bold green")
            split_json_documents_with_context_id = self.add_context_id_to_documents(documents=split_json_documents, context_id=generated_id)
            

            #adding documents to vector store
            vector_store = self.get_vector_store(collection_name=self.collection_name)
            adding_success = self.add_documents_to_vector_store(documents=split_json_documents_with_context_id, vector_store=vector_store) # SETS doc_ids ⭐
            if not adding_success:
                raise ValueError(f"Failed to add documents to vector store")
            
            self.context_id = generated_id # SET context_id ⭐
            self.documents = split_json_documents # SET documents ⭐

            return generated_id
        except Exception as e:
            raise ValueError(f"Error in loading results into vector store: {e}")

    def prepare_context(
        self,
        load_results_into_vector_store: bool = True,
        summary_manager: BaseSummaryManager | None = None,
        )->OpenSourceResult:
        """
        Responsible for running the open source tool and returning the vector store
        
        Returns :
        - BaseContext object with vector store and summary if successful ( if unsuccessful , error message field is populated )

        Args:
            load_results_into_vector_store: bool = True,
            summary_manager: BaseSummaryManager | None = None
        """
        try:
            self.run_open_source_tool()


            # if load_results_into_vector_store is True, then save the results into the vector store and return the context id
            if load_results_into_vector_store:
                context_id = self.save_results_into_vector_store_and_return_context_id() #sets self.documents for map reduce summary
            else:
                context_id = None
                self.split_and_set_result_documents() #sets self.documents for map reduce summary
                     
            # if summary_manager is provided, then generate the summary using the summary manager
            if summary_manager:
                summary = self.generate_map_reduce_summary(summary_manager=summary_manager)
            else:
                summary = None
            
            # if results are not found, raise an error
            if not self.results:
                raise ValueError(f"No results found")
            
            return OpenSourceResult(context_id=context_id, summary=summary , results=self.results)
        except Exception as e:
            # return OpenSourceResult(error_message=f"Error in running open source tool and returning context: {e}")
            raise e

