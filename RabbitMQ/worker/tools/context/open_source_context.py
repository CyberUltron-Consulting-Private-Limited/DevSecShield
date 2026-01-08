from typing import Callable
from rich.console import Console
from langchain_community.vectorstores import MongoDBAtlasVectorSearch, VectorStore
from tools.context.base_context import BaseContext, BaseContextManager
from langchain_text_splitters import RecursiveJsonSplitter

console = Console()


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
            if open_source_tool and isinstance(open_source_tool, Callable):
                self.open_source_tool = open_source_tool
            else:
                raise ValueError(f"Open source tool must be a callable")
            if kwargs:
                self.kwargs = kwargs
            else:
                raise ValueError(f"kwargs must be a dictionary")
            self.collection_name = "open_source_context"
        except Exception as e:
            raise ValueError(f"Error in initializing OpenSourceContext: {e}")

    def _run_open_source_tool(self)->dict:
        """
        Responsible for running the open source tool and returning the context
        """
        try:
            console.print(f"Running open source tool: {self.open_source_tool.__name__}",style="bold yellow")
            results = self.open_source_tool(**self.kwargs)
            if results:
                console.print(f"Results found !",style="bold green")
                self.results = results
            else:
                console.print(f"No results found !",style="bold red")
                raise ValueError(f"No results found")
        except Exception as e:
            raise ValueError(f"Error in running open source tool: {e}")
    
    def _load_results_into_vector_store(self)->VectorStore:
        """
        loads the results into a vector store
        """
        try:
            splitter = RecursiveJsonSplitter(max_chunk_size=500)
            if not self.results:
                raise ValueError(f"No results found")
            json_documents = splitter.create_documents(texts=[self.results])
            if json_documents:
                console.print(f"Loading {len(json_documents)} json documents into vector store",style="dim blue1")
                mongo_db = self.__get_mongo_client_db()
                collection = mongo_db[self.collection_name]
                vector_store = MongoDBAtlasVectorSearch(collection, self.__get_embedding_model())
                vector_store.add_documents(json_documents)
                console.print(f"Json chunks loaded into vector store successfully",style="bold blue1")
                return vector_store
            else:
                raise ValueError(f"No json chunks found")
        except Exception as e:
            raise ValueError(f"Error in loading results into vector store: {e}")

    def prepare_context(self,
        combine_prompt_string: str | None = None,
        map_prompt_string: str | None = None,
    )->BaseContext:
        """
        Responsible for running the open source tool and returning the vector store
        
        Returns :
        - BaseContext object with vector store and summary if successful ( if unsuccessful , error message field is populated )

        ### Example Usage : 
        ```python

        from tools.context.open_source_context import OpenSourceContext

        open_source_context = OpenSourceContext(open_source_tool=open_source_tool, **kwargs)

        open_source_context.prepare_context(combine_prompt_string="combine_prompt_string", map_prompt_string="map_prompt_string")
        
        vector_store = open_source_context.vector_store
        
        if open_source_context.error_message:
            print(open_source_context.error_message)
        else:
            print("Open source tool ran successfully")
        """
        try:
            self._run_open_source_tool()
            vector_store = self._load_results_into_vector_store()
            if combine_prompt_string and map_prompt_string:
                summary = self.generate_map_reduce_summary(
                    combine_prompt_string=combine_prompt_string, 
                    map_prompt_string=map_prompt_string,
                )
            else:
                summary = None
            return BaseContext(vector_store=vector_store, summary=summary)
        except Exception as e:
            return BaseContext(error_message=f"Error in running open source tool and returning vector store: {e}")