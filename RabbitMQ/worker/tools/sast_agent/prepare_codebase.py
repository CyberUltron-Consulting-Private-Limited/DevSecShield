from typing import Literal
from tools.context.scan_context import GithubContext, GitlabContext, BitbucketContext, clone_repo
from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
from langchain_core.documents import Document

class PrepareCodebase:

    def __init__(self, context: GithubContext | GitlabContext | BitbucketContext  , app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] = "python"):
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

            match app_lang:
                case "python":
                    self.include_files = [".py"]
                    self.parser = LanguageParser(language=Language.PYTHON, parser_threshold=50)
                    self.language = Language.PYTHON
                case "javascript":
                    self.include_files = [".js"]
                    self.parser = LanguageParser(language=Language.JAVASCRIPT, parser_threshold=50)
                    self.language = Language.JAVASCRIPT
                case "java":
                    self.include_files = [".java"]
                    self.parser = LanguageParser(language=Language.JAVA, parser_threshold=50)
                    self.language = Language.JAVA
                case "php":
                    self.include_files = [".php"]
                    self.parser = LanguageParser(language=Language.PHP, parser_threshold=50)
                    self.language = Language.PHP
                case "c":
                    self.include_files = [".c"]
                    self.parser = LanguageParser(language=Language.C, parser_threshold=50)
                    self.language = Language.C
                case "ruby":
                    self.include_files = [".rb"]
                    self.parser = LanguageParser(language=Language.RUBY, parser_threshold=50)
                    self.language = Language.RUBY
                case "rust":
                    self.include_files = [".rs"]
                    self.parser = LanguageParser(language=Language.RUST, parser_threshold=50)
                    self.language = Language.RUST
                case "swift":
                    self.include_files = [".swift"]
                    self.parser = LanguageParser(language=Language.SWIFT, parser_threshold=50)
                    self.language = Language.SWIFT
                case "csharp":
                    self.include_files = [".cs"]
                    self.parser = LanguageParser(language=Language.CSHARP, parser_threshold=50)
                    self.language = Language.CSHARP
                case "kotlin":
                    self.include_files = [".kt"]
                    self.parser = LanguageParser(language=Language.KOTLIN, parser_threshold=50)
                    self.language = Language.KOTLIN
                case _:
                    raise ValueError(f"Unsupported language: {app_lang}")
        except Exception as e:
            raise ValueError(f"Error in preparing codebase: {e}")
        finally:
            if directory:
                self.directory = directory
    

    def __load_and_split_codebase_into_documents(self):
        try:
            # STEP [ 1 ] : ------------------ Load the Codebase as Documents for further splitting --------------------------------------------
            loader = GenericLoader.from_filesystem(
                self.directory,
                glob="**/*",
                suffixes=self.include_files, # Specify relevant file types
                parser=self.parser
                )
            documents = loader.load()


            # STEP [ 2 ] : ------------------ Based on the lang , Split the Codebase into smaller chunks --------------------------------------------
            codebase_splitter = RecursiveCharacterTextSplitter.from_language(
            language=self.language, chunk_size=2000, chunk_overlap=200
            )
            split_documents = codebase_splitter.split_documents(documents)
            if split_documents:
                self.split_documents: list[Document] = split_documents # ( list of Document objects , each document is a chunk of the codebase )
            else:
                raise ValueError(f"No split documents found")

            
        except Exception as e:
            raise ValueError(f"Error in loading and splitting codebase: {e}")

    def __load_documents_into_vector_store(self):
        """
        Responsible for loading the split documents into a vector store
        """
        pass

    def __generate_map_reduce_summary_of_codebase(self):
        """
        Responsible for generating a map reduce summary of the codebase, based on the specified prompt
        """
        pass
    
    def __analyze_and_generate_vulnerabilities_for_component(self):
        pass


        