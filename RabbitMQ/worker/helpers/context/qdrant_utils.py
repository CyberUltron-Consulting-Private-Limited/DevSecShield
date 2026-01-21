import os
import time
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams
from rich.console import Console
console = Console()

def create_collection(collection_name: str , url: str, api_key: str)->None:
    try:
        qdrant_client = QdrantClient(url=url,api_key=api_key,check_compatibility=False)
        if not qdrant_client.collection_exists(collection_name):
            qdrant_client.create_collection(collection_name=collection_name,
                                     vectors_config=VectorParams(size=1536, distance=Distance.COSINE))
    except Exception as e:
        raise ValueError(f"Error in creating collection: {e}")


def check_if_collection_exists(collection_name: str, url: str, api_key: str)->bool:
    try:
        qdrant_client = QdrantClient(url=url,api_key=api_key,check_compatibility=False)
        return qdrant_client.collection_exists(collection_name)
    except Exception as e:
        raise ValueError(f"Error in checking if collection exists: {e}")


def run_initialization_checks(
    url: str, 
    api_key: str,
    collections: list[str] = [ "codebase_context" , "open_source_context" ], 
    )->None:
    try:
        for collection in collections:
            console.print(f"Checking if collection {collection} exists",style="dim yellow")
            if not check_if_collection_exists(collection, url, api_key):
                console.print(f"Collection {collection} does not exist, creating it",style="dim yellow")
                create_collection(collection, url, api_key)
                console.print(f"Collection {collection} created successfully",style="dim green")   
            else:
                console.print(f"Collection {collection} already exists, using it",style="dim green")
    except Exception as e:
        raise ValueError(f"Error in running initialization checks: {e}")

def delete_all_documents_from_collection(collection_name: str, url: str, api_key: str)->None:
    try:
        qdrant_client = QdrantClient(url=url,api_key=api_key,check_compatibility=False)
        if qdrant_client.delete_collection(collection_name=collection_name):
            console.print(f"All documents deleted from collection {collection_name}",style="dim green")
        else:
            console.print(f"Failed to delete collection {collection_name}",style="dim red")
            raise ValueError(f"Failed to delete collection {collection_name}")
        
        # sleep for 1 second
        time.sleep(1)
        # recreate the collection
        create_collection(collection_name, url, api_key)
        console.print(f"Collection {collection_name} recreated successfully",style="dim green")
    except Exception as e:
        raise ValueError(f"Error in deleting collection and all documents from collection: {e}")

def clear_all_collections_and_recreate(url: str, api_key: str)->None:
    try:
        collections = [ "codebase_context" , "open_source_context" ]
        for collection in collections:
            delete_all_documents_from_collection(collection, url, api_key)
    except Exception as e:
        raise ValueError(f"Error in clearing all collections and recreating: {e}")

if __name__ == "__main__":
    try:
        console.print("Running initialization checks",style="dim yellow")

        # getting api key from environment variable
        QDRANT_API_KEY = os.getenv("QDRANT_API_KEY")
        if not QDRANT_API_KEY:
            raise ValueError("QDRANT_API_KEY is not set")
        else:
            console.print(f"QDRANT_API_KEY is set to {QDRANT_API_KEY[:10]}...",style="dim green")

        # getting url based on IS_DOCKER_CONTAINER environment variable
        IS_DOCKER_CONTAINER = os.getenv("IS_DOCKER_CONTAINER")
        if IS_DOCKER_CONTAINER == "True":
            url = "http://13.203.233.15:6333"
        else:
            url = "http://localhost:6333"
        console.print(f"Using url: {url}",style="dim yellow")

        # running initialization checks
        # run_initialization_checks(url=url, api_key=QDRANT_API_KEY)
        # console.print("Initialization checks completed successfully",style="dim green")

        # clearing all collections and recreating
        clear_all_collections_and_recreate(url=url, api_key=QDRANT_API_KEY)
        console.print("All collections cleared and recreated successfully",style="dim green")
    
    except Exception as e:
        console.print(f"Error in running initialization checks: {e}",style="bold red")
        raise ValueError(f"Error in running initialization checks: {e}")