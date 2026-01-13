import warnings

warnings.filterwarnings("ignore")
from pprint import pprint
from rich.console import Console
from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_text_splitters import Language


console = Console()

loader = GenericLoader.from_filesystem(
    "C:/Users/HP/Desktop/RiskPilot",
    glob="**/*",
    suffixes=[".py"],
    show_progress=True,
    parser=LanguageParser(),

)
iterator = loader.lazy_load()
docs = []
for doc in iterator:
    docs.append(doc)
console.print(f"Number of documents: {len(docs)}",style="bold green")
