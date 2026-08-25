from langchain_community.document_loaders import DirectoryLoader
from langchain_community.document_loaders import TextLoader
from langchain_community.docstore.document import Document
from rich.console import Console

console = Console(markup=False) 


def load_dir_to_documents(dir_path: str) -> list[Document]:
    loader = DirectoryLoader(f"{dir_path}/", glob="**/*.md", loader_cls=TextLoader, show_progress=True)
    documents = loader.load()

    console.print(f"Number of Documents: {len(documents)}", style="bold green")

    return documents


if __name__ == "__main__":
    load_dir_to_documents("markdown_output")