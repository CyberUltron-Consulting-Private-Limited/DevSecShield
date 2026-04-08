from dataclasses import dataclass
import os
import time
import hashlib
import json as _json
import logging
from botocore.utils import tempfile
from dotenv import load_dotenv
from langchain_community.vectorstores import VectorStore
from langchain_core.documents import Document
from pymongo import MongoClient
from rich.console import Console
from langchain.prompts import PromptTemplate
from pydantic import BaseModel, Field
from langchain_aws import ChatBedrock
from langchain_mongodb import MongoDBAtlasVectorSearch
from helpers.context.base_utilities import BaseUtilities
from helpers.context.schema import LogicalComponents
from helpers.context.base_summary_manager import BaseSummaryManager
import json
from langsmith import traceable

console = Console()
_logger = logging.getLogger(__name__)

load_dotenv()

_TRANSIENT_BEDROCK_ERRORS = [
    "Unknown role", "ThrottlingException", "ServiceUnavailableException",
    "ModelTimeoutException", "InternalServerException", "Too many requests",
]

def _invoke_with_retry(chain, payload: dict, max_retries: int = 3):
    """Invoke a LangChain chain with automatic retry on transient Bedrock errors."""
    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            return chain.invoke(payload)
        except Exception as e:
            last_error = e
            err_str = str(e)
            is_transient = any(s in err_str for s in _TRANSIENT_BEDROCK_ERRORS)
            if is_transient and attempt < max_retries:
                wait_secs = 2 ** attempt
                console.print(f"⚠️ Transient Bedrock error (attempt {attempt}/{max_retries}), retrying in {wait_secs}s: {err_str[:120]}", style="bold yellow")
                time.sleep(wait_secs)
            else:
                raise
    raise last_error


def _get_mongo_client():
    """Get a MongoDB client using environment variables."""
    is_docker = os.getenv("IS_DOCKER_CONTAINER", "False") == "True"
    host = os.getenv("MONGO_HOST", "13.203.233.15" if is_docker else "localhost")
    port = os.getenv("MONGO_PORT", "27017")
    username = os.getenv("MONGO_INITDB_ROOT_USERNAME")
    password = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
    if username and password:
        url = f"mongodb://{username}:{password}@{host}:{port}/"
    else:
        url = f"mongodb://{host}:{port}/"
    return MongoClient(url)


def _hash_documents(documents: list[Document]) -> str:
    """Compute a deterministic SHA256 hash over sorted document content."""
    sorted_content = sorted(doc.page_content for doc in documents)
    fingerprint = "\n".join(sorted_content)
    return hashlib.sha256(fingerprint.encode()).hexdigest()


_CACHE_DB = "new_devsecshield_backend_server_db"
_CACHE_COLLECTION = "map_reduce_cache"
_BATCH_MAP_CACHE_COLLECTION = "map_reduce_batch_cache"

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
    
    
    @traceable
    def generate_map_reduce_summary(
        self,
        summary_manager: BaseSummaryManager,
    )->type[BaseModel] | str:
        """
        Responsible for generating a map reduce summary of documents, based on the specified prompt
        Requires : self.documents to be set
        """
        try:

            # STEP [ 0 ] ----------------> Check MongoDB cache for previously computed summary --------------------------
            
            if self.documents:
                _doc_hash = _hash_documents(self.documents)
                try:
                    _mongo = _get_mongo_client()
                    try:
                        _col = _mongo[_CACHE_DB][_CACHE_COLLECTION]
                        cached = _col.find_one({"_id": _doc_hash})
                        if cached:
                            console.print(f"✅ Map-reduce cache HIT for hash {_doc_hash[:16]}...", style="bold green")
                            # Reconstruct Pydantic model from cached JSON if output model is set
                            summary_output_model = summary_manager.summary_output_model
                            if summary_output_model and cached.get("model_data"):
                                return summary_output_model.model_validate(cached["model_data"])
                            return cached.get("raw_text", "")
                        else:
                            console.print(f"🔍 Map-reduce cache MISS for hash {_doc_hash[:16]}...", style="dim yellow")
                    finally:
                        _mongo.close()
                except Exception as cache_err:
                    console.print(f"⚠️ Map-reduce cache lookup failed (non-fatal): {cache_err}", style="dim yellow")

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






            # STEP [ 4 ] ----------------> Incremental Mapping with per-batch caching --------------------------
            # Each batch of 10 documents is cached individually by content hash.
            # When a small change occurs, only the affected batch is re-mapped;
            # all other batches serve from cache, saving LLM calls.
            
            map_results = []
            _batch_cache_hits = 0
            _batch_cache_misses = 0
            _last_map_response = None  # track final response object for single-batch case
            console.print(f"Mapping length of documents {len(self.documents)}",style="dim yellow")
            for i in range(0, len(self.documents), 10): # summarizing 10 documents at a time
                documents_batch = self.documents[i:i+10]

                # Compute per-batch content hash for incremental caching
                _batch_hash = _hash_documents(documents_batch)

                # Check per-batch cache in MongoDB
                _batch_cached_text = None
                try:
                    _mongo = _get_mongo_client()
                    try:
                        _bcol = _mongo[_CACHE_DB][_BATCH_MAP_CACHE_COLLECTION]
                        _bcached = _bcol.find_one({"_id": _batch_hash})
                        if _bcached:
                            _batch_cached_text = _bcached.get("map_text", None)
                    finally:
                        _mongo.close()
                except Exception:
                    pass  # non-fatal, will just re-compute

                if _batch_cached_text:
                    _batch_cache_hits += 1
                    console.print(f"♻️ Batch {i//10} map cache HIT (hash {_batch_hash[:12]}...)", style="dim green")
                    _logger.warning("♻️ Batch %d map cache HIT (hash %s...)", i//10, _batch_hash[:12])
                    map_results.append(_batch_cached_text)
                else:
                    _batch_cache_misses += 1
                    _logger.warning("🔍 Batch %d map cache MISS (hash %s...)", i//10, _batch_hash[:12])
                    documents_data = summary_manager.format_documents_to_string( documents=documents_batch )

                    console.print(f"Documents data length before summarizing {len(documents_data)}",style="dim bright_cyan")
                    map_chain_response = _invoke_with_retry(map_chain, {"text": documents_data})
                    _last_map_response = map_chain_response
                    documents_summary = summary_manager.format_to_string( input=map_chain_response )

                    console.print(f"Map Summary for Documents {i} to {i+10} .  Content length of map summary: {len(documents_summary)}",style="dim bright_cyan")

                    # Store per-batch map result for future incremental reuse
                    try:
                        _mongo = _get_mongo_client()
                        try:
                            _bcol = _mongo[_CACHE_DB][_BATCH_MAP_CACHE_COLLECTION]
                            _bcol.replace_one(
                                {"_id": _batch_hash},
                                {"_id": _batch_hash, "map_text": documents_summary},
                                upsert=True,
                            )
                        finally:
                            _mongo.close()
                    except Exception:
                        pass  # non-fatal

                    map_results.append(documents_summary)

            console.print(f"📊 Batch map summary: {_batch_cache_hits} cache hits, {_batch_cache_misses} misses out of {_batch_cache_hits + _batch_cache_misses} batches", style="bold bright_cyan")
            _logger.warning("📊 Batch map summary: %d cache hits, %d misses out of %d batches", _batch_cache_hits, _batch_cache_misses, _batch_cache_hits + _batch_cache_misses)       





            # STEP [ 5 ] ----------------> Reducing ( the summaries are reduced to a single summary 10 at a time )-------------------------------------------------------------
            
            
            # =========================== if the map results has only 1 item , then skip summarization and return that one map result =========================================
            if len(map_results)==1 : 
                console.print("Skipping Combine and Refine steps as there is only 1 Map summary result .", style="dim yellow")
                if _last_map_response is not None:
                    # Fresh LLM response — cache the full result
                    self._store_map_reduce_cache(_doc_hash, _last_map_response)
                    return _last_map_response
                else:
                    # All batches served from cache — reconstruct from cached summary output model
                    if summary_output_model:
                        try:
                            _mongo = _get_mongo_client()
                            try:
                                _col = _mongo[_CACHE_DB][_CACHE_COLLECTION]
                                cached = _col.find_one({"_id": _doc_hash})
                                if cached and cached.get("model_data"):
                                    return summary_output_model.model_validate(cached["model_data"])
                            finally:
                                _mongo.close()
                        except Exception:
                            pass
                    # Fallback: re-run combine on the single cached map text
                    combine_chain_response = _invoke_with_retry(combine_chain, {"text": map_results[0]})
                    self._store_map_reduce_cache(_doc_hash, combine_chain_response)
                    return combine_chain_response
            
            
            # =================================== Creating initial summary that will be refined ===================================
            console.print(f"Map results length : {len(map_results)}",style="dim yellow")
            console.print(f"Initial Summary : Combining first batch (upto 10 ) map results",style="dim yellow")
            combine_chain_response = _invoke_with_retry(combine_chain, {"text": "\n\n".join(map_results[:10])})
            summary_to_be_refined = summary_manager.format_to_string( input=combine_chain_response )

            
            # ========================================= Refining the initial summary by 10 summaries at a time ===================================
            if len(map_results) > 10:
                for i in range(10, len(map_results), 10):
                    summaries_concatenated = "\n\n".join(map_results[i:i+10])

                    # for testing 
                    # logging_stuff = { "summaries_concatenated": summaries_concatenated, "summary_to_be_refined": summary_to_be_refined }
                    # with open(f"logging_stuff_refine_{i}.json", "w+") as f:
                    #     json.dump(logging_stuff, f, indent=4)
                    

                    refine_chain_response = _invoke_with_retry(refine_chain, {"text": summaries_concatenated, "summary": summary_to_be_refined})
                    summary_to_be_refined = summary_manager.format_to_string( input=refine_chain_response ) 
                    console.print(f"Refine result for batch {i} to {i+10} .  Content length of refine result: {len(summary_to_be_refined)}",style="dim bright_cyan")
                
                self._store_map_reduce_cache(_doc_hash, refine_chain_response)
                return refine_chain_response
            else:
                # for testing 
                # logging_stuff = { "summary_to_be_refined": summary_to_be_refined }
                # with open("logging_stuff_final.json", "w+") as f:
                #     json.dump(logging_stuff, f, indent=4)

                self._store_map_reduce_cache(_doc_hash, combine_chain_response)
                return combine_chain_response
            
        except Exception as e:
            raise ValueError(f"Error in generating map reduce summary of codebase: {e}")
    
    
    def _store_map_reduce_cache(self, doc_hash: str, result):
        """Store map-reduce result in MongoDB cache, keyed by document content hash."""
        try:
            _mongo = _get_mongo_client()
            _col = _mongo[_CACHE_DB][_CACHE_COLLECTION]
            cache_doc = {"_id": doc_hash}
            if isinstance(result, BaseModel):
                cache_doc["model_data"] = result.model_dump()
                cache_doc["model_class"] = result.__class__.__name__
            else:
                cache_doc["raw_text"] = str(result)
            _col.replace_one({"_id": doc_hash}, cache_doc, upsert=True)
            console.print(f"✅ Map-reduce result cached with hash {doc_hash[:16]}...", style="bold green")
            _mongo.close()
        except Exception as cache_err:
            console.print(f"⚠️ Map-reduce cache store failed (non-fatal): {cache_err}", style="dim yellow")

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