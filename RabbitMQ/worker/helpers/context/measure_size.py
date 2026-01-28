import os
from rich.console import Console
from langchain_core.documents import Document
console = Console()

def get_size_of_documents(documents:list[Document]) -> tuple[int, int, int]:
    """
    Gets the size of the documents
    """
    try:
        set_of_sources = set([ document.metadata['source'] for document in documents ])

        total_size = 0
        for source in set_of_sources:
            if os.path.islink(source):
                continue # skip if it is a symbolic link
            size = os.path.getsize(source)
            total_size += size

        size_in_bytes = total_size
        size_in_mb = size_in_bytes / 1024 / 1024
        size_in_gb = size_in_mb / 1024
        return (size_in_bytes, size_in_mb, size_in_gb)
    except Exception as e:
        raise ValueError(f"Error in getting size of documents: {e}")