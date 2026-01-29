import json
import os
from typing import Iterable, Literal
import uuid
from datetime import datetime
from bson.regex import Regex
from langchain_community.document_loaders.generic import GenericLoader
from helpers.context.custom_language_parser import LanguageParser
from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from rich.console import Console
from helpers.context.base_context import BaseResult, BaseContextManager
from pathlib import Path
from helpers.context.base_summary_manager import BaseSummaryManager
from helpers.context.measure_size import get_size_of_documents
import re
console = Console()

def get_documents_after_exclusion(
    document_iterator: Iterable[Document], 
    exclude_path_arrays: list[list[str]],
    verbose: bool = False,
    metadata: dict | None = None)->Iterable[Document]:
    """
    Responsible for getting the documents with exclusion
    """
    try:
        
        console.print("Getting documents with exclusion .... ✔️",style="bold yellow ")
        for document in document_iterator:
            matches_count = 0

            if "parsing_error" in document.metadata:
                if verbose:
                    console.print(f"Skipping document with parsing error",style="dim red")
                continue # skip the document if it has a parsing error
            
            for exclude_path_array in exclude_path_arrays:
                if file_path_matches_pattern(document.metadata['source'] , exclude_path_array ):
                    if verbose:
                        console.print(f"Skipping document with exclusion: {document.metadata['source']} due to match with exclusion path matching: {exclude_path_array}",style="dim red")
                    matches_count += 1

            if matches_count > 0:
                if metadata:
                    metadata["excluded_documents"].append(document.metadata["source"])
                continue # skip
            else:
                if metadata:
                    metadata["included_documents"].append(document.metadata["source"])
                yield document
    except Exception as e:
        raise ValueError(f"Error in getting documents with exclusion: {e}")

def get_documents_after_inclusion(
    document_iterator: Iterable[Document], 
    include_path_arrays: list[list[str]],
    verbose: bool = False,
    metadata: dict | None = None)->Iterable[Document]:
    """
    Responsible for getting the documents with inclusion
    """
    try:
        console.print("Getting documents with inclusion .... ✔️",style="bold yellow ")
        for document in document_iterator:
            matches_count = 0
            if "parsing_error" in document.metadata:
                if verbose:
                    console.print(f"Skipping document with parsing error",style="dim red")
                continue # skip the document if it has a parsing error
            
            for include_path_array in include_path_arrays:
                if file_path_matches_pattern(document.metadata['source'] , include_path_array ):
                    if verbose:
                        console.print(f"Accepting document with inclusion: {document.metadata['source']} with inclusion path matching: {include_path_array}",style="dim green")
                    matches_count += 1
            
            if matches_count > 0:
                if metadata:
                    metadata["included_documents"].append(document.metadata["source"])
                yield document
            else:
                if metadata:
                    metadata["excluded_documents"].append(document.metadata["source"])
                continue # skip
    except Exception as e:
        raise ValueError(f"Error in getting documents with inclusion: {e}")

def get_documents(
    document_iterator: Iterable[Document], 
    verbose: bool = False,
    metadata: dict | None = None)->Iterable[Document]:
    """
    Responsible for getting the documents with inclusion
    """
    try:
        console.print("Getting documents without exclusion or inclusion .... ✔️",style="bold yellow ")
        for document in document_iterator:
            if "parsing_error" in document.metadata:
                if verbose:
                    console.print(f"Skipping document with parsing error",style="dim red")
                continue # skip

            if metadata:
                metadata["included_documents"].append(document.metadata["source"])
            yield document # accept document 
        
                
    except Exception as e:
        raise ValueError(f"Error in getting documents with inclusion: {e}")


def file_path_matches_pattern(file_path:str, path_array: list[str])->bool:
        """
        Responsible for accepting or rejecting a file based on the file path
        """
        try:
            matches_count = 0

            # STEP [ 1 ] ------------------------------- Build Regex string ------------------------------------
            regex = path_array[0]
            if len(path_array) > 2:
                for i in range(1,len(path_array)-1):
                    child = path_array[i]
                    # new parent
                    regex= rf"{regex}" + r"[\\/]" + rf"{child}" 
            elif len(path_array) == 2:
                regex= rf"{path_array[0]}" + r"[\\/]" + rf"{path_array[1]}" 
            else:
                regex = r"[\\/]" + rf"{path_array[0]}" 
            

            # if path array is simply an extension , then use the extension as the regex
            if len(path_array) == 1 and path_array[0].startswith("."):
                regex = rf"{path_array[0]}"
                


            # STEP [ 2 ] ---------------------- Search for regex in file path ------------------------------------
            if re.search(regex, file_path):
                matches_count += 1       


            
            # STEP [ 3 ] ----------------------- Return True if regex is found in file path ------------------------------------
            if matches_count > 0:
                return True
            else:
                return False
            
        except Exception as e:
            raise ValueError(f"Error in file_path_matches_pattern: {e}")


class CodebaseContext(BaseContextManager):
    """
    This class is responsible for preparing the codebase for ingestion by the AI Agent 
    it will : 
    1. Load the codebase into vector store and return vector store instance for querying,deletion,updating,etc
    2. Generate a map reduce summary of the codebase, based on the specifications given
    """

    def __init__(
        self, 
        directory: str | Path , 
        include_files_extensions: list[str] = None,
        exclude_path_arrays: list[list[str]] = None, # Expectation ex : [ ["root", "frontend"], ["root", "backend"] , ["file_name.extension"] , [ "parent_directory", "file_name.extension"]]
        include_path_arrays: list[list[str]] = None, # Expectation ex : [ ["root", "frontend"], ["root", "backend"] , ["file_name.extension"] , [ "parent_directory", "file_name.extension"]]
        ):
        """
        Ingests Codebase and provides Summary of the codebase + context id of documents loaded to Vector Store
        Args:
            context: The context of the codebase to be prepared for ingestion
            include_files_extensions : list of file extensions to include
            include_path_arrays: list of path arrays to include  ex : [ ["root", "frontend"], ["root", "backend"] , ["file_name.extension"] , [ "parent_directory", "file_name.extension"]]
            exclude_path_arrays: list of path arrays to exclude ex : [ ["root", "frontend"], ["root", "backend"] , ["file_name.extension"] , [ "parent_directory", "file_name.extension"]]
        """
        try:
            super().__init__()

            if not directory or not isinstance(directory, (str, Path)):
                raise ValueError(f"Directory is required")
            self.directory = directory
            self.exclude_path_arrays= exclude_path_arrays if exclude_path_arrays else None
            self.include_path_arrays= include_path_arrays if include_path_arrays else None

            self.include_files_extensions = include_files_extensions if include_files_extensions else []
            self.collection_name = "codebase_context"

            self.metadata = { "excluded_documents": [] , "included_documents": []}

        except Exception as e:
            raise ValueError(f"Error in preparing codebase: {e}")

    

    def load_documents_of_extension(self,lang_ext: str)->Iterable[Document]:
        """
        loads documents of a specific language ( file extension )
        ### Requires the following attributes to be set :
        - self.directory
        - self.exclude_path_arrays
        - self.include_path_arrays
        - self.include_files_extensions
        """
        try:
            # --------------------------------------- Initialize the loader and other variables --------------------------------------------
            loader = GenericLoader.from_filesystem(
                self.directory,
                glob="**/*",
                suffixes=[lang_ext],
                parser=LanguageParser(),
                show_progress=True,
            )
            document_loader_object = loader.lazy_load()
            documents = []
            console.print(f"include path arrays : {self.include_path_arrays} \nexclude path arrays : {self.exclude_path_arrays}",style="dim yellow")
            

            # ----------------------- Only allow either file exclusion or inclusion ( inclusion takes precedence over exclusion ) --------------------------------------------
            if self.exclude_path_arrays and self.include_path_arrays :
                raise ValueError(f"Only one of exclude_path_arrays or include_path_arrays can be provided")
            

            # ---------------------------------- Setting up document iterator with exclusion or inclusion --------------------------------------------
            if not self.exclude_path_arrays and not self.include_path_arrays:
                iterator = get_documents(document_loader_object,metadata=self.metadata)
            elif self.exclude_path_arrays and not self.include_path_arrays:
                iterator = get_documents_after_exclusion(document_loader_object, self.exclude_path_arrays, metadata=self.metadata)
            elif self.include_path_arrays and not self.exclude_path_arrays:
                iterator = get_documents_after_inclusion(document_loader_object, self.include_path_arrays, metadata=self.metadata)
            else:
                raise ValueError(f"Only one of exclude_path_arrays or include_path_arrays can be provided")
            
            # --------------------------------------- Cycle through all the documents --------------------------------------------
            for document in iterator:
                documents.append(document)

            console.print(f"{len(documents)} Language: {lang_ext} Documents loaded successfully",style="dim green")
            included_set = set(self.metadata["included_documents"])
            excluded_set = set(self.metadata["excluded_documents"])
            console.print(f"Included documents count: {len(included_set)}",style="dim yellow")
            console.print(f"Excluded documents count: {len(excluded_set)}",style="dim yellow")

            

            return documents
        except Exception as e:
            raise ValueError(f"Error in loading documents of extension : {e}")
    
    def split_documents_of_language(
        self, 
        documents: Iterable[Document] , 
        language: Language,
        chunk_size: int = 5000,
        chunk_overlap: int = 200
        )->list[Document]:
        """
        splits the documents into smaller chunks
        """
        try:
            if len(documents) == 0 or not documents:
                raise ValueError(f"No documents found to split")
            
            codebase_splitter = RecursiveCharacterTextSplitter.from_language(
                language=language, chunk_size=chunk_size, chunk_overlap=chunk_overlap
            )
            split_documents = codebase_splitter.split_documents(documents)
            if split_documents:
                console.print(f"{len(split_documents)} Documents of language: {language} split successfully",style="dim yellow")
                return split_documents
            else:
                raise ValueError(f"No split documents found")
        except Exception as e:
            raise ValueError(f"Error in splitting documents of language: {e}")
    
    def split_documents_without_language(
        self, 
        documents: Iterable[Document],
        chunk_size: int = 5000,
        chunk_overlap: int = 200
        )->list[Document]:
        """
        splits the documents into smaller chunks without using the language
        """
        try:
            if len(documents) == 0 or not documents:
                raise ValueError(f"No documents found to split")
            
            document_splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
            split_documents = document_splitter.split_documents(documents)
            console.print(f"{len(split_documents)} Documents without language split successfully",style="dim yellow")
            return split_documents
        except Exception as e:
            raise ValueError(f"Error in splitting documents without language: {e}")

    
    def load_and_split_codebase_into_documents(self)->list[Document]:
        """
        Responsible for loading codebase as documents and splitting them based on their language inferred from the file extension
        Cyles through all the file extensions and load the documents accordingly

        Requires :
        - __init__ to have run 
        """
        try:
            split_documents_list = []
            for file_extension in self.include_files_extensions:
                language = self.get_language_from_file_extension(file_extension)
                if language!= None and isinstance(language, Language):
                    console.print(f"Loading documents of language: {language}",style="dim green")
                    documents = self.load_documents_of_extension(file_extension)
                    if len(documents) == 0 :
                        console.print(f"No language documents found of extension : {file_extension} , skipping .... ",style="dim red")
                        continue
                    split_documents = self.split_documents_of_language(documents, language)
        
                    split_documents_list.extend(split_documents)
                else:
                    console.print(f"Loading documents without language: {file_extension}",style="dim green")
                    documents = self.load_documents_of_extension(file_extension)
                    if len(documents) == 0 :
                        console.print(f"No non-language documents found of extension : {file_extension} , skipping .... ",style="dim red")
                        continue
                    split_documents = self.split_documents_without_language(documents)
                    split_documents_list.extend(split_documents)
            

            included_set = set(self.metadata["included_documents"])
            excluded_set = set(self.metadata["excluded_documents"])
            self.metadata["included_documents"] = included_set
            self.metadata["excluded_documents"] = excluded_set
            
            
            # for testing
            for included in self.metadata["excluded_documents"]:
                console.print(f" -{included}",style = "dim red")
            for included in self.metadata["included_documents"]:
                console.print(f" -{included}",style = "dim green")
            
            

            console.print(f"Total split documents: {len(split_documents_list)}",style="dim green")
            return split_documents_list

        except Exception as e:
            included_set = set(self.metadata["included_documents"])
            excluded_set = set(self.metadata["excluded_documents"])
            self.metadata["included_documents"] = included_set
            self.metadata["excluded_documents"] = excluded_set
            
            
            # for testing
            for included in self.metadata["excluded_documents"]:
                console.print(f" -{included}",style = "dim red")
            for included in self.metadata["included_documents"]:
                console.print(f" -{included}",style = "dim green")


            raise ValueError(f"Error in loading and splitting codebase into documents: {e}")
    
    def split_documents_and_set_documents(self)->bool:
        """
        Responsible for splitting the documents and setting the documents attribute
        Requires :
        - __init__ to have run 
        """
        try:
            split_documents = self.load_and_split_codebase_into_documents()
            if not split_documents:
                console.print(f"No split documents found",style="dim red")
                return False
            self.documents = split_documents
            return True # success
        except Exception as e:
            console.print(f"Error in splitting documents and setting documents attribute: {e}",style="dim red")
            return False
    

    def save_documents_to_vector_store_and_return_context_id(self)->str:
        """
        Main function responsible for loading the split documents into a vector store
        Attributes set :
        - self.context_id : str
        """
        try:
            vectorstore = self.get_vector_store(collection_name=self.collection_name) 
                 
            split_documents = self.load_and_split_codebase_into_documents()
            if not split_documents:
                raise ValueError(f"No split documents found")

            # Adding agent_job_id to the documents metadata for filtering
            generated_id = str(uuid.uuid4()) + datetime.now().strftime("%Y%m%d%H%M%S")
            split_documents_with_context_id = self.add_context_id_to_documents(documents=split_documents, context_id=generated_id)

            console.print(f"Adding {len(split_documents_with_context_id)} codebase documents to vector store with context id : {generated_id}",style="bold green")
            adding_success = self.add_documents_to_vector_store( documents=split_documents_with_context_id, vector_store=vectorstore, ) # SETS doc_ids ⭐
            if not adding_success:
                raise ValueError(f"Failed to add documents to vector store")
            
            self.context_id = generated_id # SET context_id ⭐
            self.documents = split_documents_with_context_id # SET documents ⭐

            return generated_id

        except Exception as e:
            raise ValueError(f"Error in saving documents to vector store and returning context id: {e}")



    def get_language_from_file_extension(self, file_extension: str)->Language:
        """
        Responsible for getting the language from the file extension
        Only supports languages that match app_lang options: python, javascript, java, php, c, ruby, rust, swift, csharp, kotlin
        """
        try:
            match file_extension:
                case ".py":
                    return Language.PYTHON
                case ".js":
                    return Language.JS
                case ".java":
                    return Language.JAVA
                case ".php":
                    return Language.PHP
                case ".c":
                    return Language.C
                case ".cs":
                    return Language.CSHARP
                case ".kt":
                    return Language.KOTLIN
                case ".rb":
                    return Language.RUBY
                case ".rs":
                    return Language.RUST
                case ".swift":
                    return Language.SWIFT
                # Unsupported extensions that don't match app_lang options
                # These will be handled without language-specific parsing
                case _:
                    return None # when None , the document will be split without language
        except Exception as e:
            raise ValueError(f"Error in getting language from file extension: {e}")
    

    def prepare_context(
        self,
        load_documents_to_vector_store: bool = True,
        summary_manager: BaseSummaryManager | None = None,
    )->BaseResult:
        """
        Responsible for preparing the codebase for ingestion
        Args:
            load_documents_to_vector_store: bool
            summary_manager: BaseSummaryManager
        Returns:
            BaseContext
        """
        try:
            # if load_documents_to_vector_store is True, then save the documents to the vector store and return the context id
            if load_documents_to_vector_store:
                context_id = self.save_documents_to_vector_store_and_return_context_id() #sets self.documents for map reduce summary
            else:
                context_id = None
                self.split_documents_and_set_documents() #sets self.documents for map reduce summary
            
            # if summary_manager is provided, then generate the summary using the summary manager
            if summary_manager:
                summary = self.generate_map_reduce_summary(
                    summary_manager=summary_manager, )
            else:
                summary = None


            return BaseResult(context_id=context_id, summary=summary)


        except Exception as e:
            # return BaseResult(error_message=f"Error in preparing codebase for ingestion: {e}")
            raise e

    

    def estimate_size_of_documents(self)->int:
        """
        Estimates the size of the documents
        Requires :
        - __init__ to have run 
        Returns:
            tuple[int, int, int] : (size_in_bytes, size_in_mb, size_in_gb)
        """
        try:
            self.split_documents_and_set_documents()

            documents = self.documents
            sizes = get_size_of_documents(documents)

            return sizes 
        except Exception as e:
            raise ValueError(f"Error in estimating size of documents: {e}")



        