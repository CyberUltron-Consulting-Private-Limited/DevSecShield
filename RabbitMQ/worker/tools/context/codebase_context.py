from typing import Iterable, Literal
import uuid
from datetime import datetime
from bson.regex import Regex
from langchain_community.document_loaders.generic import GenericLoader
from custom_language_parser import LanguageParser
from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from langchain_community.vectorstores import VectorStore
from rich.console import Console
from base_context import BaseContext, BaseContextManager
from pathlib import Path
import sys
import re


def accept_file(file_path:str, exclude_path_array: list[str])->bool:
        """
        Responsible for accepting or rejecting a file based on the file path
        """
        try:
            dont_allow_count = 0

            # STEP [ 1 ] ---------------- Build Regex string ------------------------------------
            
            regex = exclude_path_array[0]
            if len(exclude_path_array) > 2:
                for i in range(1,len(exclude_path_array)-1):
                    child = exclude_path_array[i]
                    # new parent
                    regex= rf"{regex}" + r"[\\/]" + rf"{child}"
            elif len(exclude_path_array) == 2:
                regex= rf"{exclude_path_array[0]}" + r"[\\/]" + rf"{exclude_path_array[1]}"
            else:
                regex = r"[\\/]" + rf"{exclude_path_array[0]}"

            # STEP [ 2 ] ---------------- Search for regex in file path ------------------------------------
           
            if re.search(regex, file_path):
                dont_allow_count += 1       

            
            # STEP [ 3 ] ---------------- Return False if regex is found in file path ------------------------------------

            if dont_allow_count > 0:
                return False
            else:
                return True
            
        except Exception as e:
            raise ValueError(f"Error in file_accept_or_reject: {e}")

console = Console()

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
        app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"],
        exclude_paths: list[list[str]] = None, # Expectation ex : [ ["root", "frontend"], ["root", "backend"] , ["file_name.extension"] , [ "parent_directory", "file_name.extension"]]
        ):
        """
        Ingests Codebase and provides Summary of the codebase + context id of documents loaded to Vector Store
        Args:
            context: The context of the codebase to be prepared for ingestion
            include_files: The list of file extensions to be included in the codebase
        ### Example Usage : 
        ```python
        from tools.context.codebase_context import CodebaseContext
        from utils.context_utils import validate_dict_with_context

        context = validate_dict_with_context(dict_context) # GithubContext | GitlabContext | BitbucketContext

        codebase_context = CodebaseContext(context=context, app_lang=app_lang)

        codebase_context.prepare_context(combine_prompt_string="combine_prompt_string", map_prompt_string="map_prompt_string")
        ```
        """
        try:
            super().__init__()

            if not directory or not isinstance(directory, (str, Path)):
                raise ValueError(f"Directory is required")
            self.directory = directory
            self.exclude_path_arrays= exclude_paths if exclude_paths else []

            include_files = None
            match app_lang:
                case "python":
                    include_files = [".py"]
                    self.default_exclude_paths = ["__pycache__", ".venv", "venv", "env", ".env", "dist", "build", ".egg-info"]
                case "javascript":
                    include_files = [".js"]
                    self.default_exclude_paths = ["node_modules", ".next", "dist", "build", ".cache", ".nuxt", ".output"]
                case "java":
                    include_files = [".java"]
                    self.default_exclude_paths = ["target", "build", ".gradle", ".m2", "out", ".idea"]
                case "php":
                    include_files = [".php"]
                    self.default_exclude_paths = ["vendor", "node_modules", ".composer"]
                case "c":
                    include_files = [".c"]
                    self.default_exclude_paths = ["build", "bin", "obj", "cmake-build-"]
                case "ruby":
                    include_files = [".rb"]
                    self.default_exclude_paths = ["vendor", "tmp", ".bundle", "node_modules"]
                case "rust":
                    include_files = [".rs"]
                    self.default_exclude_paths = ["target", ".cargo"]
                case "swift":
                    include_files = [".swift"]
                    self.default_exclude_paths = ["build", ".build", "DerivedData", "Pods"]
                case "csharp":
                    include_files = [".cs"]
                    self.default_exclude_paths = ["bin", "obj", "packages", ".vs", "node_modules"]
                case "kotlin":
                    include_files = [".kt"]
                    self.default_exclude_paths = ["build", ".gradle", ".idea", "out", "node_modules"]
                case _:
                    raise ValueError(f"Unsupported application language: {app_lang}")
            
            self.include_files = include_files if include_files else None
            self.collection_name = "codebase_context"

        except Exception as e:
            raise ValueError(f"Error in preparing codebase: {e}")

    

    def load_documents(self,lang_ext: str)->Iterable[Document]:
        """
        loads documents of a specific language ( file extension )
        """
        try:
            loader = GenericLoader.from_filesystem(
                self.directory,
                glob="**/*",
                suffixes=[lang_ext],
                parser=LanguageParser(),
                show_progress=True,
            )
            iterator = loader.lazy_load()


            documents = []
            default_excluded_count, parsing_error_count , excluded_count = 0,0,0
            for document in iterator:

                # ----------> Logic where we skip files ( Parsing error or in default exclude paths )
                if "parsing_error" in document.metadata:
                    parsing_error_count += 1
                    continue # skip the document if it has a parsing error
                if any(path in document.metadata['source'] for path in self.default_exclude_paths):
                    default_excluded_count += 1
                    continue # skip the document if it is in the default exclude paths
                
                # ----------> Logic where we skip files ( in exclude paths )
                dont_allow_count = 0
                for path_array in self.exclude_path_arrays:
                    if not accept_file(document.metadata['source'] , path_array ):
                        dont_allow_count += 1
                if dont_allow_count > 0:
                    excluded_count += 1
                    continue # skip the document if it is in the exclude paths

                # Accept Document 
                documents.append(document)

            console.print(f"{len(documents)} Language: {lang_ext} Documents loaded successfully",style="dim green")
            console.print(f"\n Parsing error Count: {parsing_error_count} , Excluded Count: {excluded_count} , default excluded count: {default_excluded_count}",style="dim yellow")

            return documents
        except Exception as e:
            raise ValueError(f"Error in loading documents of language: {e}")
    
    def split_documents_of_language(self, documents: Iterable[Document] , language: Language)->list[Document]:
        """
        splits the documents into smaller chunks
        """
        try:
            codebase_splitter = RecursiveCharacterTextSplitter.from_language(
                language=language, chunk_size=2000, chunk_overlap=200
            )
            split_documents = codebase_splitter.split_documents(documents)
            if split_documents:
                console.print(f"{len(split_documents)} Documents of language: {language} split successfully",style="dim green")
                return split_documents
            else:
                raise ValueError(f"No split documents found")
        except Exception as e:
            raise ValueError(f"Error in splitting documents of language: {e}")
    
    def split_documents_without_language(self, documents: Iterable[Document])->list[Document]:
        """
        splits the documents into smaller chunks without using the language
        """
        try:
            document_splitter = RecursiveCharacterTextSplitter(chunk_size=2000, chunk_overlap=200)
            split_documents = document_splitter.split_documents(documents)
            console.print(f"{len(split_documents)} Documents without language split successfully",style="dim green")
            return split_documents
        except Exception as e:
            raise ValueError(f"Error in splitting documents without language: {e}")

    
    def load_and_split_codebase_into_documents(self)->list[Document]:
        """
        Responsible for loading codebase as documents and splitting them based on their language inferred from the file extension
        Cyles through all the file extensions and load the documents accordingly
        """
        try:
            for file_extension in self.include_files:
                language = self.get_language_from_file_extension(file_extension)
                if language!= None and isinstance(language, Language):
                    console.print(f"Loading documents of language: {language}",style="dim green")
                    documents = self.load_documents(file_extension)
                    split_documents = self.split_documents_of_language(documents, language)
                    console.print(f"Split documents of language: {language} found and added {len(split_documents)} split documents",style="dim green")
        
                    return split_documents
                else:
                    console.print(f"Loading documents without language: {file_extension}",style="dim green")
                    documents = self.load_documents(file_extension)
                    split_documents = self.split_documents_without_language(documents)
                    console.print(f"Split documents of language: None found and added {len(split_documents)} split documents",style="dim green")
                    
                    return split_documents
        except Exception as e:
            raise ValueError(f"Error in loading and splitting codebase into documents: {e}")

    def load_documents_and_return_context_id(self)->str:
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

            adding_success = self.add_documents_to_vector_store( documents=split_documents_with_context_id, vector_store=vectorstore, )
            if not adding_success:
                raise ValueError(f"Failed to add documents to vector store")
            
            self.context_id = generated_id # SET context_id ⭐
            self.documents = split_documents_with_context_id # SET documents ⭐

            return generated_id

        except Exception as e:
            raise ValueError(f"Error in loading and returning context id: {e}")



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
        combine_prompt_string: str | None = None,
        map_prompt_string: str | None = None,
    )->BaseContext:
        """
        Responsible for preparing the codebase for ingestion

        Returns :
        - BaseContext object with vector store and summary if successful ( if unsuccessful , error message field is populated )

        ### Example Usage : 
        ```python

        from tools.context.codebase_context import PrepareCodebase

        codebase_context = PrepareCodebase(context=context, include_files=include_files)

        codebase_context.prepare_context(combine_prompt_string="combine_prompt_string", map_prompt_string="map_prompt_string")
        
        codebase_context_id = codebase_context.context_id
        summary = codebase_context.summary
        
        if codebase_context.error_message:
            print(codebase_context.error_message)
        else:
            print("Codebase prepared for ingestion successfully")
        ```
        """
        try:
            context_id = self.load_documents_and_return_context_id()
            if combine_prompt_string and map_prompt_string:
                summary = self.generate_map_reduce_summary(
                    combine_prompt_string=combine_prompt_string, 
                    map_prompt_string=map_prompt_string,
                )
            else:
                summary = None
            return BaseContext(context_id=context_id, summary=summary)
        except Exception as e:
            return BaseContext(error_message=f"Error in preparing codebase for ingestion: {e}")



if __name__ == "__main__":
    #testing codebase context
    directory = Path("C:/Users/HP/Desktop/RiskPilot")
    codebase_context = CodebaseContext(
        directory=directory, 
        app_lang="python",
        exclude_paths=[ ["RiskPilot" , "frontend" ] , [ ".venv" ] , [ "backend" , "__pycache__" ]  ]
    )
    result = codebase_context.prepare_context(combine_prompt_string="Create a coherent summary of the codebase", map_prompt_string="Create a detailed, descriptive and brief summary of this code:")
    print(result)


        