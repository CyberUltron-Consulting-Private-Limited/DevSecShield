from typing import Iterable, Literal
from langchain_community.vectorstores.mongodb_atlas import MongoDBAtlasVectorSearch
from tools.context.scan_context import GithubContext, GitlabContext, BitbucketContext, clone_repo
from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from langchain_community.vectorstores import VectorStore
from rich.console import Console
from tools.context.base import BaseContext, BaseContextManager

console = Console()

class CodebaseContext(BaseContextManager):
    """
    This class is responsible for preparing the codebase for ingestion by the AI Agent 
    it will : 
    1. Load the codebase into vector store and return vector store instance for querying,deletion,updating,etc
    2. Generate a map reduce summary of the codebase, based on the specifications given
    """

    def __init__(self, context: GithubContext | GitlabContext | BitbucketContext  , app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]):
        """
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
            directory = None
            if context and isinstance(context, GithubContext):
                directory = clone_repo(context.repo_url)
            elif context and isinstance(context, GitlabContext):
                directory = clone_repo(context.repo_url)
            elif context and isinstance(context, BitbucketContext):
                directory = clone_repo(context.repo_url)
            else : 
                raise ValueError(f"Unsupported context: {context}")

            include_files = None
            match app_lang:
                case "python":
                    include_files = [".py"]
                case "javascript":
                    include_files = [".js"]
                case "java":
                    include_files = [".java"]
                case "php":
                    include_files = [".php"]
                case "c":
                    include_files = [".c"]
                case "ruby":
                    include_files = [".rb"]
                case "rust":
                    include_files = [".rs"]
                case "swift":
                    include_files = [".swift"]
                case "csharp":
                    include_files = [".cs"]
                case "kotlin":
                    include_files = [".kt"]
                case _:
                    raise ValueError(f"Unsupported application language: {app_lang}")
            
            self.include_files = include_files if include_files else None
            self.collection_name = "codebase_context"
            self.split_documents: list[Document] = []

        except Exception as e:
            raise ValueError(f"Error in preparing codebase: {e}")
        finally:
            if directory:
                self.directory = directory
    

    def __load_documents_of_language(self,lang_ext: str)->Iterable[Document]:
        """
        loads documents of a specific language ( file extension )
        """
        try:
            loader = GenericLoader.from_filesystem(
                self.directory,
                glob="**/*",
                suffixes=[lang_ext],
                parser=LanguageParser()
            )
            documents = loader.load()
            return documents
        except Exception as e:
            raise ValueError(f"Error in loading documents of language: {e}")
    
    def __split_documents_of_language(self, documents: Iterable[Document] , language: Language)->list[Document]:
        """
        splits the documents into smaller chunks
        """
        try:
            codebase_splitter = RecursiveCharacterTextSplitter.from_language(
                language=language, chunk_size=2000, chunk_overlap=200
            )
            split_documents = codebase_splitter.split_documents(documents)
            if split_documents:
                return split_documents
            else:
                raise ValueError(f"No split documents found")
        except Exception as e:
            raise ValueError(f"Error in splitting documents of language: {e}")
    
    def __split_documents_without_language(self, documents: Iterable[Document])->list[Document]:
        """
        splits the documents into smaller chunks without using the language
        """
        try:
            document_splitter = RecursiveCharacterTextSplitter(chunk_size=2000, chunk_overlap=200)
            split_documents = document_splitter.split_documents(documents)
            return split_documents
        except Exception as e:
            raise ValueError(f"Error in splitting documents without language: {e}")
    
    def __load_documents_without_language(self,file_extension: str)->Iterable[Document]:
        """
        loads documents without using the language
        """
        try:
            loader = GenericLoader.from_filesystem(
                self.directory,
                suffixes=[file_extension],
            )
            documents = loader.load()
            return documents
        except Exception as e:
            raise ValueError(f"Error in loading documents without language: {e}")
    
    def __load_and_split_codebase_into_documents(self)->list[Document]:
        """
        Responsible for loading codebase as documents and splitting them based on their language inferred from the file extension
        Cyles through all the file extensions and load the documents accordingly
        """
        try:
            for file_extension in self.include_files:
                language = self.__get_language_from_file_extension(file_extension)
                if language!= None and isinstance(language, Language):
                    documents = self.__load_documents_of_language(file_extension)
                    split_documents = self.__split_documents_of_language(documents, language)
                    console.print(f"Split documents of language: {language} found and added {len(split_documents)} split documents",style="dim green")
                    self.split_documents.extend(split_documents)
                else:
                    documents = self.__load_documents_without_language(file_extension)
                    split_documents = self.__split_documents_without_language(documents)
                    console.print(f"Split documents of language: None found and added {len(split_documents)} split documents",style="dim green")
                    self.split_documents.extend(split_documents)
        except Exception as e:
            raise ValueError(f"Error in loading and splitting codebase into documents: {e}")

    def load_and_return_vector_store(self)->VectorStore:
        """
        Responsible for loading the split documents into a vector store
        """
        try:
            # TODO : Finish this function
            mongo_db = self.__get_mongo_client_db()
            collection = mongo_db[self.collection_name]
            embeddings = self.__get_embedding_model()
            vectorstore = MongoDBAtlasVectorSearch(collection, embeddings)

            # Load Codebase --> Split --> Add to Vector Store --> Return Vector Store 
            self.__load_and_split_codebase_into_documents()
            if self.split_documents:
                console.print(f"Adding split documents to vector store",style="dim blue1")
                vectorstore.add_documents(self.split_documents)
                console.print(f"Split documents added to vector store successfully",style="bold blue1")
                return vectorstore
            else:
                raise ValueError(f"No split documents found")
        except Exception as e:
            raise ValueError(f"Error in loading and returning vector store: {e}")



    def __get_language_from_file_extension(self, file_extension: str)->Language:
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
                    return None
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
        
        vector_store = codebase_context.vector_store
        summary = codebase_context.summary
        
        if codebase_context.error_message:
            print(codebase_context.error_message)
        else:
            print("Codebase prepared for ingestion successfully")
        ```
        """
        try:
            vector_store = self.load_and_return_vector_store()
            if combine_prompt_string and map_prompt_string:
                summary = self.generate_map_reduce_summary(
                    combine_prompt_string=combine_prompt_string, 
                    map_prompt_string=map_prompt_string,
                )
            else:
                summary = None
            return BaseContext(vector_store=vector_store, summary=summary)
        except Exception as e:
            return BaseContext(error_message=f"Error in preparing codebase for ingestion: {e}")


        