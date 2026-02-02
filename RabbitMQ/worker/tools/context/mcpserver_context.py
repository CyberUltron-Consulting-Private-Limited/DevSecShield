from typing import Iterable, Literal

from langchain_community.vectorstores.mongodb_atlas import MongoDBAtlasVectorSearch
from pymongo import MongoClient
from tools.context.scan_context import GithubContext, GitlabContext, BitbucketContext, clone_repo
from langchain_community.document_loaders.generic import GenericLoader
from langchain.prompts import PromptTemplate
from langchain.chains.summarize import load_summarize_chain
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from langchain_community.vectorstores import VectorStore
from rich.console import Console
from tools.context.base import BaseContext, BaseContextManager

class McpServerContext(BaseContextManager):
    """
    This class is responsible for preparing context for remote hosted MCP servers 
    """
    def __init__(self, context: GithubContext | GitlabContext | BitbucketContext  , app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]):
        """
        """